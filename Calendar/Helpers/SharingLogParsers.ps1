# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Calendar sharing invitation, acceptance, and InternetCalendar log parsing.

function Get-SharingInviteLogScopeNote {
    $note = "CalendarSharingInvite invitation entries are mailbox-wide and do not identify the shared folder. These entries cannot distinguish sharing of the main Calendar from a sub-calendar."
    if ($script:OwnerCalendarSubfolderSelected) {
        $note += " They cannot confirm that the selected calendar [$script:NormalizedOwnerCalendarFolderPath] was shared."
    }
    return $note
}

function Get-DatedSharingLogEntries {
    param(
        [AllowNull()]
        [object[]]$Entry,

        [DateTime]$ReferenceTimeUtc = [DateTime]::UtcNow
    )

    $entries = @($Entry | Where-Object { $null -ne $_ })
    $timestamps = Get-CalendarDiagnosticLogLineTimestamp -Line @($entries | ForEach-Object {
            "$($_.Timestamp),"
        }) -ReferenceTimeUtc $ReferenceTimeUtc
    $datedEntries = @(
        for ($index = 0; $index -lt $entries.Count; $index++) {
            $date = $timestamps[$index]
            if ($null -eq $date) {
                $parsedDate = ConvertTo-CalendarDiagnosticLogDateTime -Text $entries[$index].Timestamp
                if ($null -ne $parsedDate) {
                    $candidateDate = if ($parsedDate.Kind -eq [DateTimeKind]::Unspecified) {
                        [DateTime]::SpecifyKind($parsedDate, [DateTimeKind]::Utc)
                    } else {
                        $parsedDate.ToUniversalTime()
                    }
                    if ($candidateDate -le $ReferenceTimeUtc.AddHours(1)) {
                        $date = $candidateDate
                    }
                }
            }
            [PSCustomObject]@{
                Entry = $entries[$index]
                Date  = $date
            }
        }
    )
    return $datedEntries | Sort-Object -Property Date -Descending
}

function Get-ReceiverSharingSyncRequestEntries {
    param(
        [AllowNull()]
        [string[]]$Line,

        [AllowNull()]
        [object]$OwnerMailbox,

        [AllowNull()]
        [string]$CalendarName
    )

    $ownerGuid = [Guid]::Empty
    if ((-not [Guid]::TryParse([string]$OwnerMailbox.ExchangeGuid, [ref]$ownerGuid)) -or
        ($ownerGuid -eq [Guid]::Empty)) {
        Write-Verbose "The owner's ExchangeGuid is unavailable, so receiver synchronization requests cannot be correlated."
        return
    }
    foreach ($logLine in $Line) {
        if ($logLine -notmatch "^\s*(?<Timestamp>[^,]+),.*?\bEntry RequestId:\s*'(?<RequestId>[^']+)',\s*Sync Details for folder (?<FolderName>.+?) are\s") {
            continue
        }
        $timestamp = $Matches.Timestamp
        $requestId = $Matches.RequestId
        $folderName = $Matches.FolderName
        if ((-not [string]::IsNullOrWhiteSpace($CalendarName)) -and
            (-not [string]::Equals($folderName, $CalendarName, [System.StringComparison]::OrdinalIgnoreCase))) {
            continue
        }
        if ($logLine -notmatch '\[RMGUID,\s*(?<OwnerGuid>[0-9a-f-]{36})\]') {
            continue
        }
        $requestOwnerGuid = [Guid]::Empty
        if ((-not [Guid]::TryParse($Matches.OwnerGuid, [ref]$requestOwnerGuid)) -or
            ($requestOwnerGuid -ne $ownerGuid)) {
            continue
        }
        [PSCustomObject]@{
            Timestamp  = $timestamp
            RequestId  = $requestId
            FolderName = $folderName
        }
    }
}

<#
.SYNOPSIS
    Formats the CalendarSharingInvite logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing invite logs for a given identity and outputs the most recent update for each recipient.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing invite logs.
#>
function ProcessCalendarSharingInviteLogs {
    param (
        [string]$Identity
    )

    $script:OwnerInviteCheckAvailable = $false
    $script:OwnerInviteData = @()

    try {
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName CalendarSharingInvite -ErrorAction SilentlyContinue

        $logOutput = Invoke-SharingCollector -Name "OwnerInviteLog" -Action {
            Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName CalendarSharingInvite
        }
    } catch {
        Write-Warning "Failed to retrieve CalendarSharingInvite logs for [$Identity]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "CalendarSharingInvite" -Issue "The owner invite-log check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Collect CalendarSharingInvite logs with sufficient access and inspect the invite for the expected receiver." -Incomplete
        return
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        $script:CollectorStatuses["OwnerInviteLog"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host "No data found for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "CalendarSharingInvite" -Issue "The owner invite-log check had no data." -Evidence "CalendarSharingInvite returned no MailboxLog data for [$Identity]." -RecommendedNextStep "Collect CalendarSharingInvite logs and verify whether an invite was generated for [$Receiver]." -Incomplete
        return
    }

    # Split the output into an array of lines
    $script:OwnerInviteLogRaw = [string]$logOutput.MailboxLog
    $logLines = $logOutput.MailboxLog -split "\r?\n"

    $inviteEntries = Invoke-SharingEvaluation -Name "Owner invite-log parsing" -RuleIds @("SHR300", "SHR301") -Action {
        # These logs use labeled fields, not CSV quoting; mailbox names can contain commas and apostrophes.
        $entryPattern = '^\s*(?<Timestamp>[^,]+),\s*Mailbox:\s*(?<Mailbox>.*?),\s*Entry MailboxOwner:\s*(?<MailboxOwner>[^,]+),\s*Recipient:\s*(?<Recipient>[^,]+),\s*RecipientType:\s*(?<RecipientType>[^,]+),\s*Handler=(?:ms-exchange-)?(?<SharingType>[^,]+),\s*DetailLevel=(?<DetailLevel>.*)$'
        $entries = @(
            for ($index = 0; $index -lt $logLines.Count; $index++) {
                $line = $logLines[$index]
                if ($line -notlike "*RecipientType*") {
                    continue
                }
                if ($line -notmatch $entryPattern) {
                    throw "CalendarSharingInvite entry on line [$($index + 1)] did not match the expected labeled fields."
                }
                $mailbox = $Matches.Mailbox.Trim()
                if (($mailbox.Length -ge 2) -and $mailbox.StartsWith("'") -and $mailbox.EndsWith("'")) {
                    $mailbox = $mailbox.Substring(1, $mailbox.Length - 2)
                }
                [PSCustomObject]@{
                    Timestamp     = $Matches.Timestamp.Trim()
                    Mailbox       = $mailbox
                    MailboxOwner  = $Matches.MailboxOwner.Trim()
                    Recipient     = $Matches.Recipient.Trim()
                    RecipientType = $Matches.RecipientType.Trim()
                    SharingType   = $Matches.SharingType.Trim()
                    DetailLevel   = $Matches.DetailLevel.Trim()
                }
            }
        )
        return $entries
    }
    if ($null -eq $inviteEntries) {
        Add-SharingFinding -Severity Warning -Area "CalendarSharingInvite" -Issue "The owner invite-log check was unavailable." -Evidence "CalendarSharingInvite data could not be parsed." -RecommendedNextStep "Inspect the raw CalendarSharingInvite logs." -Incomplete
        return
    }
    $script:OwnerInviteCheckAvailable = $true
    $script:OwnerInviteData = @($inviteEntries)

    # Access the values as properties of the object
    foreach ($row in $inviteEntries) {
        Write-Debug "$($row.Recipient) - $($row.SharingType) - $($row.detailLevel)"
    }

    $datedInvites = @(Get-DatedSharingLogEntries -Entry @($inviteEntries) -ReferenceTimeUtc $script:RunStartedAt.ToUniversalTime())
    if (@($datedInvites | Where-Object { $null -eq $_.Date }).Count -gt 0) {
        Write-Warning "Some invitation timestamps could not be parsed; undated entries are displayed alongside the latest dated invitations per recipient."
    }
    $mostRecentRecipients = $datedInvites | Group-Object -Property { $_.Entry.Recipient } | ForEach-Object {
        $latestDate = $_.Group[0].Date
        $_.Group | Where-Object { ($null -eq $_.Date) -or ($_.Date -eq $latestDate) }
    } | Sort-Object -Property Date -Descending | ForEach-Object { $_.Entry }

    # Output the results to the console
    Write-Host -Object "User [$Identity] has calendar-sharing invitation entries for the following recipients:"
    Write-Host -ForegroundColor Yellow -Object (Get-SharingInviteLogScopeNote)
    $mostRecentRecipients | Format-Table -a Timestamp, Recipient, SharingType, DetailLevel

    $receiverInvites = @($inviteEntries | Where-Object -FilterScript {
            Test-SharingReceiverAddress -Address $_.Recipient
        })
    if ($receiverInvites.Count -eq 0) {
        Add-SharingFinding -Severity Error -Area "CalendarSharingInvite" -Issue "No pair-specific sharing invite was found for the expected receiver." -Evidence "Parsed owner CalendarSharingInvite data did not contain receiver [$Receiver]." -RecommendedNextStep "Inspect CalendarSharingInvite and AcceptCalendarSharingInvite logs for this owner/receiver pair."
    } else {
        $latestInvite = $datedInvites | Where-Object {
            Test-SharingReceiverAddress -Address $_.Entry.Recipient
        } | Select-Object -First 1
        Add-SharingFinding -RuleId "SHR301" -Status NotDetected -Evidence @{
            matchedInviteCount       = $receiverInvites.Count
            latestEntryUtc           = $(if ($null -ne $latestInvite.Date) { $latestInvite.Date.ToString("o") } else { $null })
            mailboxScoped            = $true
            calendarFolderIdentified = $false
            reason                   = "A mailbox-level invitation to the receiver was found; it does not identify which calendar folder was shared."
        }
    }
}

<#
.SYNOPSIS
    Formats the AcceptCalendarSharingInvite logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing invite logs.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing accept logs.
#>
function ProcessCalendarSharingAcceptLogs {
    param (
        [string]$Identity
    )

    # Define the header row
    $header4Line = "Timestamp", "Mailbox", "SharedCalendarOwner", "FolderName"
    $header5Line = "Timestamp", "MailboxLast", "MailboxFirst", "SharedCalendarOwner", "FolderName"

    try {
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite -ErrorAction SilentlyContinue
        Write-Host "Collecting AcceptCalendarSharingInvite logs for [$Identity] ..."
        $logOutput = Invoke-SharingCollector -Name "ReceiverAcceptLog" -Action {
            Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName AcceptCalendarSharingInvite
        }
    } catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "(?i)not\s+found|no\s+logs") {
            Write-Warning "No AcceptCalendarSharingInvite logs found for [$Identity]. Details: $errorMessage"
            Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept-log check was unavailable." -Evidence $errorMessage -RecommendedNextStep "Collect AcceptCalendarSharingInvite logs and verify acceptance for the expected owner." -Incomplete
            return
        }

        Write-Warning "Failed to collect AcceptCalendarSharingInvite logs for [$Identity]: $errorMessage"
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept-log check failed." -Evidence $errorMessage -RecommendedNextStep "Collect AcceptCalendarSharingInvite logs and verify acceptance for the expected owner." -Incomplete
        return
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        $script:CollectorStatuses["ReceiverAcceptLog"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host "No AcceptCalendarSharingInvite Logs found for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept-log check had no data." -Evidence "AcceptCalendarSharingInvite returned no MailboxLog data for [$Identity]." -RecommendedNextStep "Collect AcceptCalendarSharingInvite logs and verify acceptance for owner [$Owner]." -Incomplete
        return
    }

    # Split the output into an array of lines
    $script:ReceiverAcceptLogRaw = [string]$logOutput.MailboxLog
    $logLines = $logOutput.MailboxLog -split "`r`n"

    $acceptLogEntryPattern = '^\s*\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s+[AP]M)?,'
    $filteredLogLines = @()
    foreach ($line in $logLines) {
        if (($line -match $acceptLogEntryPattern) -and
            ($line -like "*Entry CreateInternalSharedCalendarGroupEntry*")) {
            $filteredLogLines += $line + "`n"
        }
    }
    if ($filteredLogLines.Count -eq 0) {
        $script:CollectorStatuses["ReceiverAcceptLog"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host "No CreateInternalSharedCalendarGroupEntry entries found for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "No relevant receiver accept-log entries were available." -Evidence "No CreateInternalSharedCalendarGroupEntry entries were returned for [$Identity]." -RecommendedNextStep "Inspect AcceptCalendarSharingInvite logs for acceptance of the calendar from [$Owner]." -Incomplete
        return
    }
    $ElementCount = ($filteredLogLines[0] -split ',').Count

    if ($ElementCount -eq 4) {
        $header = $header4Line
    } elseif ($ElementCount -eq 5) {
        $header = $header5Line
    } else {
        $parseError = ConvertTo-SharingErrorInfo -ErrorRecord "Unexpected receiver accept-log format."
        $script:CollectorStatuses["ReceiverAcceptLog"] = [PSCustomObject]@{ status = "Failed"; error = $parseError }
        $script:CollectionErrors.Add([PSCustomObject]@{
                collector = "ReceiverAcceptLog"
                error     = $parseError
            })
        Write-Host "Unexpected number of elements [$ElementCount] in the log lines for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept logs could not be parsed." -Evidence "The relevant log entry contained [$ElementCount] comma-delimited elements." -RecommendedNextStep "Inspect the raw AcceptCalendarSharingInvite logs for the owner/receiver pair." -Incomplete
        return
    }

    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    foreach ($line in $filteredLogLines) {
        $csvString += $line + "`n"
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("'", "")
    $csvString = $csvString.Replace("Entry MailboxOwner:", "")
    $csvString = $csvString.Replace("Entry CreateInternalSharedCalendarGroupEntry: ", "")
    $csvString = $csvString.Replace("Creating a shared calendar for ", "")
    $csvString = $csvString.Replace("calendar name ", "")

    # Convert the CSV string to an object
    $csvObject = Invoke-SharingEvaluation -Name "Receiver accept-log parsing" -RuleIds @("SHR220") -Action {
        $csvString | ConvertFrom-Csv
    }
    if ($null -eq $csvObject) {
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "The receiver accept logs could not be parsed." -Evidence "AcceptCalendarSharingInvite data could not be parsed." -RecommendedNextStep "Inspect the raw AcceptCalendarSharingInvite logs." -Incomplete
        return
    }
    $script:ReceiverAcceptLogEntries = @($csvObject)
    $displayCsvObject = if ($script:OwnerCalendarSubfolderSelected) {
        @($csvObject | Where-Object -FilterScript {
                (Test-SmtpAddressEqual -First $_.SharedCalendarOwner -Second $Owner) -and
                [string]::Equals(
                    $_.FolderName,
                    $script:RequestedOwnerCalendarLeafName,
                    [System.StringComparison]::OrdinalIgnoreCase)
            })
    } else {
        @($csvObject)
    }
    $script:ReceiverSelectedAcceptLogEntries = @($displayCsvObject)

    # Access the values as properties of the object
    foreach ($row in $csvObject) {
        Write-Debug "$($row.Timestamp) - $($row.SharedCalendarOwner) - $($row.FolderName) "
    }

    if ($script:OwnerCalendarSubfolderSelected) {
        Write-Host "Receiver [$Identity] accept-log entries for selected owner calendar [$($script:RequestedOwnerCalendarLeafName)] in the last 180 days:"
    } else {
        Write-Host "Receiver [$Identity] has accepted copies of the shared calendar from the following recipients in the last 180 days:"
    }
    # Determine the date layout by examining timestamps (a first value above 12 means day-first, for example 15/10/2026 13:44:31).
    $preferDayFirst = $false
    foreach ($entry in $csvObject) {
        $timestamp = $entry.Timestamp
        if ([string]::IsNullOrEmpty($timestamp)) { continue }

        $monthOrDay = $timestamp.Split(" ")[0]
        if ([string]::IsNullOrEmpty($monthOrDay)) { continue }

        $firstValue = $monthOrDay.Split("/")[0]
        if ([string]::IsNullOrEmpty($firstValue)) { continue }

        $valueToTest = 0
        if ([int]::TryParse($firstValue, [ref]$valueToTest)) {
            if ($valueToTest -gt 12) {
                Write-Verbose "Looks like European DateTime Format - dd/MM/yyyy HH:mm:ss"
                $preferDayFirst = $true
                break
            }
        }
    }

    $unparsedTimestamps = [System.Collections.Generic.List[string]]::new()
    $cutoffDate = (Get-Date).AddDays(-180)
    $entriesToDisplay = @($displayCsvObject | Where-Object {
            $entryTimestamp = ConvertTo-CalendarDiagnosticLogDateTime -Text $_.Timestamp -PreferDayFirst:$preferDayFirst
            if ($null -eq $entryTimestamp) {
                # Keep entries that cannot be dated so evidence is not hidden.
                $unparsedTimestamps.Add([string]$_.Timestamp)
                return $true
            }
            return ($entryTimestamp -gt $cutoffDate)
        })
    if ($unparsedTimestamps.Count -gt 0) {
        Write-Warning "$($unparsedTimestamps.Count) accept-log timestamp(s) could not be parsed. Those entries are shown without date filtering."
        Add-SharingFinding -Severity Warning -Area "AcceptCalendarSharingInvite" -Issue "Accept-log timestamps could not be parsed." -Evidence "Unparsed timestamps: [$(($unparsedTimestamps | Select-Object -Unique -First 5) -join '; ')]." -RecommendedNextStep "Inspect the raw AcceptCalendarSharingInvite logs and their timestamp culture." -Incomplete
    }
    $entriesToDisplay | Format-Table -a Timestamp, SharedCalendarOwner, FolderName
}

<#
.SYNOPSIS
    Formats the InternetCalendar logs from Export-MailboxDiagnosticLogs for a given identity.
.DESCRIPTION
    This function processes calendar sharing invite logs.
.PARAMETER Identity
    The SMTP Address for which to process calendar sharing accept logs.
#>
function ProcessInternetCalendarLogs {
    param (
        [string]$Identity
    )

    $script:ReceiverInternetCalendarEntries = @()

    # Define the header row
    $header = "Timestamp", "Mailbox", "SyncDetails", "PublishingUrl", "RemoteFolderName", "LocalFolderId", "Folder"

    $csvString = @()
    $csvString = $header -join ","
    $csvString += "`n"

    $logOutput = $null
    try {
        # Call the Export-MailboxDiagnosticLogs cmdlet and store the output in a variable
        # -ErrorAction is not supported on Export-MailboxDiagnosticLogs
        # $logOutput = Export-MailboxDiagnosticLogs $Identity -ComponentName AcceptCalendarSharingInvite -ErrorAction SilentlyContinue
        $logOutput = Invoke-SharingCollector -Name "InternetCalendar" -Action {
            Export-MailboxDiagnosticLogs -Identity $Identity -ComponentName InternetCalendar
        }
    } catch {
        Write-Warning "No InternetCalendar logs found for [$Identity]."
        Add-SharingFinding -Severity Warning -Area "InternetCalendar" -Issue "The published-calendar log check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Collect InternetCalendar logs if published-calendar behavior must be investigated." -Incomplete
        return
    }

    # check if the output is empty
    if ($null -eq $logOutput.MailboxLog) {
        $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host -ForegroundColor Green "No InternetCalendar Logs found for [$Identity]."
        Write-Host -ForegroundColor Green "User [$Identity] is not receiving any Published Calendars."
        return
    }

    # Split the output into an array of lines
    $logLines = $logOutput.MailboxLog -split "`r`n"

    # Loop through each line of the output
    foreach ($line in $logLines) {
        if ($line -like "*Entry Sync Details for InternetCalendar subscription DataType=calendar*") {
            $csvString += $line + "`n"
        }
    }
    if ($csvString -eq (($header -join ",") + "`n")) {
        $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "NoData"; error = $null }
        Write-Host -ForegroundColor Green "No InternetCalendar subscription entries found for [$Identity]."
        return
    }

    # Clean up output
    $csvString = $csvString.Replace("Mailbox: ", "")
    $csvString = $csvString.Replace("Entry Sync Details for InternetCalendar subscription DataType=calendar", "InternetCalendar")
    $csvString = $csvString.Replace("PublishingUrl=", "")
    $csvString = $csvString.Replace("RemoteFolderName=", "")
    $csvString = $csvString.Replace("LocalFolderId=", "")
    $csvString = $csvString.Replace("folder ", "")

    # Convert the CSV string to an object
    $csvObject = Invoke-SharingEvaluation -Name "InternetCalendar log parsing" -RuleIds @("SHR420") -Action {
        $csvString | ConvertFrom-Csv
    }
    if ($null -eq $csvObject) {
        Add-SharingFinding -Severity Warning -Area "InternetCalendar" -Issue "The published-calendar log check was unavailable." -Evidence "InternetCalendar data could not be parsed." -RecommendedNextStep "Inspect the raw InternetCalendar logs." -Incomplete
        return
    }

    # Clean up the Folder column
    foreach ($row in $csvObject) {
        $row.Folder = $row.Folder.Split("with")[0]
    }
    $script:ReceiverInternetCalendarEntries = @($csvObject)

    Write-Host -ForegroundColor Cyan "Receiver [$Identity] is/was receiving the following Published Calendars:"
    $csvObject | Sort-Object -Unique RemoteFolderName | Format-Table -a RemoteFolderName, Folder, PublishingUrl
}
