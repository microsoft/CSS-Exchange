# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing diagnostic output and reporting functions.
# cSpell:ignore Sharee Sharees

. $PSScriptRoot\..\Helpers\SharingIdentityUtilities.ps1

function Write-SharingFindingDetails {
    param(
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [hashtable]$SeverityOrder
    )

    $displayFindings = @($Findings |
            ForEach-Object {
                [PSCustomObject]@{
                    severity            = $_.severity
                    ruleId              = $_.ruleId
                    title               = $_.title
                    evidence            = $script:ConsoleFindingEvidence[$_.ruleId]
                    recommendedNextStep = $_.recommendedNextStep
                }
            } |
            Sort-Object -Property @{ Expression = { $SeverityOrder[$_.severity] } }, ruleId)

    $displayFindings |
        Format-Table -AutoSize -Wrap -Property @{
            Label      = "Severity"
            Expression = { $_.severity }
        }, @{
            Label      = "RuleId"
            Expression = { $_.ruleId }
        }, @{
            Label      = "Title"
            Expression = { $_.title }
        }, @{
            Label      = "Evidence"
            Expression = { $_.evidence }
        }
    Write-Host -ForegroundColor Blue "`rRecommended Next Steps:"
    foreach ($finding in $displayFindings) {
        Write-Host -ForegroundColor Yellow "[$($finding.ruleId)] $($finding.recommendedNextStep)"
    }
}

function Write-OwnerReceiverPermissionSummary {
    param(
        [Parameter(Mandatory)]
        [string]$Receiver
    )

    $receiverCalendarPermissions = Get-PermissionEntriesForIdentity `
        -PermissionEntries $script:OwnerCalendarPerms `
        -Identity $Receiver
    $receiverMailboxPermissions = Get-PermissionEntriesForIdentity `
        -PermissionEntries $script:OwnerMailboxPerms `
        -Identity $Receiver
    $allowedMailboxPermissions = @($receiverMailboxPermissions | Where-Object -FilterScript { -not $_.Deny })
    $deniedMailboxPermissions = @($receiverMailboxPermissions | Where-Object -FilterScript { $_.Deny })
    $calendarRights = if ($receiverCalendarPermissions.Count -gt 0) {
        Get-PermissionRightsText `
            -PermissionEntries $receiverCalendarPermissions `
            -IncludeSharingFlags
    } else {
        $null
    }
    $mailboxRights = if ($allowedMailboxPermissions.Count -gt 0) {
        Get-PermissionRightsText -PermissionEntries $allowedMailboxPermissions
    } else {
        $null
    }

    Write-Host -ForegroundColor DarkYellow "Owner-to-Receiver Permission Summary:"
    if ($deniedMailboxPermissions.Count -gt 0) {
        if ($null -ne $calendarRights) {
            Write-Host -ForegroundColor Green "Receiver [$Receiver] is using [$calendarRights] on the owner Calendar folder."
        }
        if ($null -ne $mailboxRights) {
            Write-Host -ForegroundColor Yellow "Receiver [$Receiver] has Allow entries for [$mailboxRights] on the owner Mailbox; Deny entries are also present, so these are not effective-access results."
        }
        $deniedRights = Get-PermissionRightsText -PermissionEntries $deniedMailboxPermissions
        Write-Host -ForegroundColor Yellow "Receiver [$Receiver] has Deny entries for [$deniedRights] on the owner Mailbox."
    } elseif (($null -ne $calendarRights) -and ($null -ne $mailboxRights)) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] has [$calendarRights] on the owner Calendar folder and [$mailboxRights] on the owner Mailbox."
    } elseif ($null -ne $calendarRights) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] is using [$calendarRights] on the owner Calendar folder."
    } elseif ($null -ne $mailboxRights) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] has [$mailboxRights] on the owner Mailbox."
    } elseif ($script:OwnerCalendarPermsAvailable -and $script:OwnerMailboxPermsAvailable) {
        Write-Host -ForegroundColor Yellow "Receiver [$Receiver] does not have an individual permission entry on the owner Calendar folder or Mailbox; access may come from Default or a group permission."
    } else {
        Write-Host -ForegroundColor Yellow "Receiver-specific permissions could not be fully evaluated because the owner Calendar folder or Mailbox permission query was unavailable."
    }
}

function ConvertTo-SharingRawValue {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [DateTime]) {
        return $Value.ToString("o")
    }
    if (($Value -is [string]) -or ($Value -is [bool]) -or ($Value.GetType().IsPrimitive)) {
        return $Value
    }
    if ($null -ne $Value.PSObject.Properties["IsPresent"]) {
        return [bool]$Value.IsPresent
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        # The leading comma keeps empty and single-item collections as JSON arrays.
        return , @($Value | ForEach-Object { ConvertTo-SharingRawValue -Value $_ })
    }

    return (ConvertTo-CalendarDiagnosticPlainString -Value $Value)
}

function ConvertTo-SharingRawObject {
    param(
        [AllowNull()]
        [object]$InputObject,

        [string[]]$Property
    )

    if ($null -eq $InputObject) {
        return $null
    }

    # Exchange returns flag enumerations as one comma-separated value such as "Editor, Delegate"; emit them as arrays.
    $flagPropertyNames = @("AccessRights", "SharingPermissionFlags", "ActiveShareeFlags", "ExtendedFolderFlags", "CalendarSharingFolderFlags")
    $rawObject = [ordered]@{}
    $propertyNames = if ($PSBoundParameters.ContainsKey("Property")) {
        $Property
    } else {
        @($InputObject.PSObject.Properties.Name)
    }
    foreach ($propertyName in $propertyNames) {
        $sourceProperty = $InputObject.PSObject.Properties[$propertyName]
        if ($null -eq $sourceProperty) {
            continue
        }

        $rawValue = ConvertTo-SharingRawValue -Value $sourceProperty.Value
        if (($propertyName -in $flagPropertyNames) -and ($null -ne $rawValue)) {
            $rawValue = @(@($rawValue) | ForEach-Object { ([string]$_) -split ',' } |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { -not [string]::IsNullOrEmpty($_) })
        } elseif (($propertyName -match '(Time|Date)$') -and ($rawValue -is [string])) {
            $rawValue = ConvertTo-SharingRawDateString -Text $rawValue
        }
        $rawObject[$propertyName] = $rawValue
    }

    return $rawObject
}

function ConvertTo-SharingRawDateString {
    param(
        [AllowNull()]
        [string]$Text
    )

    # Exchange formats these property values with the invariant culture (MM/dd/yyyy HH:mm:ss) in UTC.
    [string[]]$formats = @("MM/dd/yyyy HH:mm:ss", "M/d/yyyy H:mm:ss", "M/d/yyyy h:mm:ss tt")
    $parsedValue = [DateTime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTime]::TryParseExact($Text.Trim(), $formats, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsedValue)) {
        return $Text
    }
    if ($parsedValue.Year -le 1) {
        return "Uninitialized"
    }

    return $parsedValue.ToString("o")
}

function ConvertTo-SharingLogLines {
    param(
        [AllowNull()]
        [string]$Text,

        [DateTime]$ReferenceTimeUtc = [DateTime]::UtcNow
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return $null
    }

    # Exchange separates log entries with blank lines, which only add size to the JSON.
    $lines = @($Text -split "\r?\n" | Where-Object -FilterScript { -not [string]::IsNullOrWhiteSpace($_) })
    $recentLines = Select-CalendarDiagnosticLogLineWithinDays -Line $lines -ReferenceTimeUtc $ReferenceTimeUtc -MaximumAgeDays 365
    return [PSCustomObject]@{
        Line                    = @($recentLines.Line)
        OmittedOlderThanOneYear = $recentLines.OmittedEntries
    }
}

function Select-SharingEntriesWithinOneYear {
    param(
        [AllowNull()]
        [object[]]$Entry,

        [DateTime]$ReferenceTimeUtc = [DateTime]::UtcNow
    )

    $entries = @($Entry)
    $timestamps = Get-CalendarDiagnosticLogLineTimestamp -Line @($entries | ForEach-Object { "$($_.Timestamp)," }) -ReferenceTimeUtc $ReferenceTimeUtc
    $cutoff = $ReferenceTimeUtc.AddDays(-365)
    $keptEntries = [System.Collections.Generic.List[object]]::new()
    $omitted = 0
    for ($index = 0; $index -lt $entries.Count; $index++) {
        if (($null -ne $timestamps[$index]) -and ($timestamps[$index] -lt $cutoff)) {
            $omitted++
        } else {
            $keptEntries.Add($entries[$index])
        }
    }

    return [PSCustomObject]@{
        Entry                   = @($keptEntries)
        OmittedOlderThanOneYear = $omitted
    }
}

function Get-SharingJsonRawData {
    $mailboxProperties = @(
        "Identity", "DisplayName", "Alias", "PrimarySmtpAddress", "RecipientTypeDetails", "OrganizationalUnitRoot",
        "Database", "ExchangeGuid", "ExternalDirectoryObjectId", "WhenCreatedUTC", "WhenChangedUTC", "GrantSendOnBehalfTo"
    )
    $folderStatisticsProperties = @(
        "Name", "FolderPath", "FolderType", "ItemsInFolder", "VisibleItemsInFolder",
        "FolderSize", "FolderAndSubfolderSize", "CreationTime", "LastModifiedTime"
    )
    $calendarFolderProperties = @(
        "Identity", "CreationTime", "PublishEnabled", "PublishedCalendarUrl", "PublishedICalUrl", "ExtendedFolderFlags",
        "CalendarSharingFolderFlags", "CalendarSharingOwnerSmtpAddress", "CalendarSharingPermissionLevel",
        "SharingLevelOfDetails", "SharingPermissionFlags", "LastAttemptedSyncTime", "LastSuccessfulSyncTime",
        "SharedCalendarSyncStartDate"
    )
    $folderPermissionProperties = @("User", "AccessRights", "SharingPermissionFlags")
    $mailboxPermissionProperties = @("User", "AccessRights", "IsInherited", "Deny")
    $activeShareeProperties = @("EmailAddress", "SharingPermissionFlags", "ActiveShareeFlags", "LastSyncTime")
    $calendarEntryProperties = @("CalendarGroupName", "CalendarName", "OwnerEmailAddress", "SharingModelType", "IsOrphanedEntry")

    $permissionRows = {
        param($Entries, $Properties)
        @($Entries | ForEach-Object {
                $row = ConvertTo-SharingRawObject -InputObject $_ -Property $Properties
                $row["userIdentity"] = Get-CalendarDiagnosticPermissionIdentity -PermissionUser $_.User
                $row
            })
    }

    $counts = [ordered]@{
        owner_InviteLogEntries              = @($script:OwnerInviteData).Count
        receiver_AcceptLogEntries           = @($script:ReceiverAcceptLogEntries).Count
        receiver_SelectedAcceptLogEntries   = @($script:ReceiverSelectedAcceptLogEntries).Count
        receiver_InternetCalendarLogEntries = @($script:ReceiverInternetCalendarEntries).Count
        owner_CalendarFolderStatistics      = @($script:OwnerCalendarStats).Count
        owner_CalendarPermissions           = @($script:OwnerCalendarPerms).Count
        owner_MailboxPermissions            = @($script:OwnerMailboxPerms).Count
        owner_ActiveSharees                 = @($script:OwnerActiveSharees).Count
        receiver_FolderStatistics           = @($script:ReceiverFolderStatistics).Count
        receiver_CalendarEntries            = @($script:ReceiverCalendarEntries).Count
    }

    if (-not $IncludeSensitiveData) {
        return [ordered]@{
            included = $false
            note     = "Raw data is omitted in sanitized mode. Rerun with -IncludeSensitiveData to include it."
            counts   = $counts
        }
    }

    $newSection = {
        param($Source, $Data)
        [ordered]@{ source = $Source; data = $Data }
    }
    # Log entries older than one calendar year are omitted from the report.
    $referenceUtc = (Get-Date).ToUniversalTime()
    $newEntriesSection = {
        param($Source, $Entries)
        $recent = Select-SharingEntriesWithinOneYear -Entry $Entries -ReferenceTimeUtc $referenceUtc
        [ordered]@{
            source                  = $Source
            data                    = @($recent.Entry | ForEach-Object { ConvertTo-SharingRawObject -InputObject $_ })
            omittedOlderThanOneYear = $recent.OmittedOlderThanOneYear
        }
    }
    $newLogTextSection = {
        param($Source, $Text)
        $logLines = ConvertTo-SharingLogLines -Text $Text -ReferenceTimeUtc $referenceUtc
        [ordered]@{
            source                  = $Source
            data                    = $(if ($null -eq $logLines) { $null } else { $logLines.Line })
            omittedOlderThanOneYear = $(if ($null -eq $logLines) { 0 } else { $logLines.OmittedOlderThanOneYear })
        }
    }
    $ownerFolderIdentity = $script:OwnerCalendarFolderIdentity
    $receiverFolderIdentity = $script:ReceiverLocalCalendarFolderIdentity
    $ownerFolderStatisticsSource = "Get-MailboxFolderStatistics -Identity $Owner -FolderScope Calendar"
    $receiverFolderStatisticsSource = "Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar"
    $ownerCalendarFolderSource = "Get-MailboxCalendarFolder -Identity `"$ownerFolderIdentity`""

    $rawData = [ordered]@{
        included                       = $true
        counts                         = $counts
        owner_Mailbox                  = & $newSection "Get-Mailbox -Identity $Owner" (ConvertTo-SharingRawObject -InputObject $script:OwnerMB -Property $mailboxProperties)
        receiver_Mailbox               = & $newSection "Get-Mailbox -Identity $Receiver" (ConvertTo-SharingRawObject -InputObject $script:ReceiverMB -Property $mailboxProperties)
        owner_CalendarFolderStatistics = & $newSection $ownerFolderStatisticsSource @($script:OwnerCalendarStats | ForEach-Object { ConvertTo-SharingRawObject -InputObject $_ -Property $folderStatisticsProperties })
        owner_SelectedCalendar         = & $newSection "$ownerFolderStatisticsSource (selected entry)" (ConvertTo-SharingRawObject -InputObject $script:OwnerSelectedCalendar -Property $folderStatisticsProperties)
        owner_CalendarFolder           = & $newSection $ownerCalendarFolderSource (ConvertTo-SharingRawObject -InputObject $script:OwnerCalendarFolder -Property $calendarFolderProperties)
        owner_CalendarPermissions      = & $newSection "Get-MailboxFolderPermission -Identity `"$ownerFolderIdentity`"" (@(& $permissionRows $script:OwnerCalendarPerms $folderPermissionProperties))
        owner_MailboxPermissions       = & $newSection "Get-MailboxPermission -Identity $Owner" (@(& $permissionRows $script:OwnerMailboxPerms $mailboxPermissionProperties))
        owner_ActiveSharees            = & $newSection "Get-CalendarActiveSharingInformation -Identity `"$ownerFolderIdentity`"" @($script:OwnerActiveSharees | ForEach-Object { ConvertTo-SharingRawObject -InputObject $_ -Property $activeShareeProperties })
        owner_InviteLog                = & $newEntriesSection "Export-MailboxDiagnosticLogs -Identity $Owner -ComponentName CalendarSharingInvite (parsed entries)" $script:OwnerInviteData
        receiver_FolderStatistics      = & $newSection $receiverFolderStatisticsSource @($script:ReceiverFolderStatistics | ForEach-Object { ConvertTo-SharingRawObject -InputObject $_ -Property $folderStatisticsProperties })
        receiver_MatchedCalendar       = & $newSection "$receiverFolderStatisticsSource (matched entry)" (ConvertTo-SharingRawObject -InputObject $script:ReceiverMatchedCalendar -Property $folderStatisticsProperties)
        receiver_LocalCalendarFolder   = & $newSection "Get-MailboxCalendarFolder -Identity `"$receiverFolderIdentity`"" (ConvertTo-SharingRawObject -InputObject $script:ReceiverLocalCalendarFolder -Property $calendarFolderProperties)
        receiver_CalendarEntries       = & $newSection "Get-CalendarEntries -Identity $Receiver" @($script:ReceiverCalendarEntries | ForEach-Object { ConvertTo-SharingRawObject -InputObject $_ -Property $calendarEntryProperties })
        receiver_AcceptLog             = & $newEntriesSection "Export-MailboxDiagnosticLogs -Identity $Receiver -ComponentName AcceptCalendarSharingInvite (parsed entries)" $script:ReceiverAcceptLogEntries
        receiver_SelectedAcceptLog     = $(if ($script:OwnerCalendarSubfolderSelected) {
                & $newEntriesSection "Export-MailboxDiagnosticLogs -Identity $Receiver -ComponentName AcceptCalendarSharingInvite (parsed entries for the selected calendar)" $script:ReceiverSelectedAcceptLogEntries
            } else {
                & $newSection "Not filtered: the default owner calendar is selected, so the selected entries are the same as receiver_AcceptLog." $null
            })
        receiver_InternetCalendarLog   = & $newEntriesSection "Export-MailboxDiagnosticLogs -Identity $Receiver -ComponentName InternetCalendar (parsed entries)" $script:ReceiverInternetCalendarEntries
        owner_PublishedICalUrl         = & $newSection "$ownerCalendarFolderSource (PublishedICalUrl)" $script:OwnerPublishedICalUrl
        owner_InviteLogFull            = & $newLogTextSection "Export-MailboxDiagnosticLogs -Identity $Owner -ComponentName CalendarSharingInvite (full log)" $script:OwnerInviteLogRaw
        receiver_AcceptLogFull         = & $newLogTextSection "Export-MailboxDiagnosticLogs -Identity $Receiver -ComponentName AcceptCalendarSharingInvite (full log)" $script:ReceiverAcceptLogRaw
    }

    # The receiver SharingSyncAssistant and Sharing logs were collected for the freshness and exception rules.
    foreach ($logKey in @($script:SharingDiagnosticLogs.Keys)) {
        $rawData[$logKey] = $script:SharingDiagnosticLogs[$logKey]
    }

    return $rawData
}

function Get-SharingJsonReportObject {
    $fatalFailure = if ($null -ne $script:FatalPrerequisiteFailure) {
        [PSCustomObject]@{
            ruleId = $script:FatalPrerequisiteFailure.ruleId
            reason = $script:FatalPrerequisiteFailure.reason
        }
    } else {
        $null
    }
    $collectionStatus = if ($null -ne $script:FatalPrerequisiteFailure) {
        "FatalPrerequisiteFailure"
    } elseif (($script:CollectionErrors.Count -gt 0) -or
        ($script:EvaluationErrors.Count -gt 0) -or
        (@($script:SharingFindings | Where-Object -Property status -EQ "NotEvaluated").Count -gt 0)) {
        "Partial"
    } else {
        "Complete"
    }

    $categoryNames = @{
        "1" = "Owner"
        "2" = "Receiver"
        "3" = "Pair relationship"
        "4" = "Synchronization and performance"
    }
    $jsonFindings = @($script:SharingFindings | ForEach-Object {
            $finding = $_
            $findingResult = Get-CalendarDiagnosticFindingResult -Status $finding.status -Severity $finding.severity
            # Rule titles describe the problem, so state the outcome explicitly when the problem was not confirmed.
            $findingSummary = switch ($findingResult) {
                "Pass" { "Not detected: $($finding.title)" }
                "Inconclusive" { "Could not be evaluated: $($finding.title)" }
                "Skipped" { "Not applicable: $($finding.title)" }
                default { $finding.title }
            }
            [PSCustomObject]@{
                ruleId              = $finding.ruleId
                category            = $categoryNames[$finding.ruleId.Substring(3, 1)]
                severity            = $finding.severity
                status              = $finding.status
                result              = $findingResult
                title               = $finding.title
                summary             = $findingSummary
                evidence            = $finding.evidence
                recommendedNextStep = $(if ($findingResult -in @("Fail", "Info", "Inconclusive")) { $finding.recommendedNextStep } else { $null })
                area                = $(if ([string]::IsNullOrWhiteSpace($finding.area)) { $null } else { $finding.area })
            }
        })
    $failedRules = @($jsonFindings | Where-Object -Property result -EQ "Fail" | ForEach-Object { $_.ruleId })
    $inconclusiveRules = @($jsonFindings | Where-Object -Property result -EQ "Inconclusive" | ForEach-Object { $_.ruleId })
    $overallResult = if ($failedRules.Count -gt 0) {
        "Fail"
    } elseif ($inconclusiveRules.Count -gt 0) {
        "Inconclusive"
    } else {
        "Pass"
    }
    $sharingModel = if ($script:ExternalSharing) {
        "ExternalSharing"
    } elseif ($script:ModernSharing) {
        "Modern"
    } elseif ($script:PublishedSharing) {
        "PublishedCalendar"
    } elseif ($script:LegacyMapiSharing) {
        "LegacyMapi"
    } else {
        "Undetermined"
    }

    return [ordered]@{
        metadata         = [ordered]@{
            schemaVersion           = "1.0-preview"
            scriptVersion           = $BuildVersion
            runStartedAtUtc         = $script:RunStartedAt.ToUniversalTime().ToString("o")
            collectedAtUtc          = (Get-Date).ToUniversalTime().ToString("o")
            owner                   = $Owner
            receiver                = $Receiver
            ownerCalendarFolderPath = $(if ($script:OwnerCalendarFolderPathSpecified) { $script:NormalizedOwnerCalendarFolderPath } else { "(main) calendar" })
            collectionStatus        = $collectionStatus
            privacyMode             = $(if ($IncludeSensitiveData) { "Full" } else { "Sanitized" })
        }
        summary          = [ordered]@{
            overallResult     = $overallResult
            failCount         = $failedRules.Count
            infoCount         = @($jsonFindings | Where-Object -Property result -EQ "Info").Count
            inconclusiveCount = $inconclusiveRules.Count
            passCount         = @($jsonFindings | Where-Object -Property result -EQ "Pass").Count
            skippedCount      = @($jsonFindings | Where-Object -Property result -EQ "Skipped").Count
            failedRules       = $failedRules
            inconclusiveRules = $inconclusiveRules
        }
        sharing          = [ordered]@{
            sharingModel             = $sharingModel
            relationshipKind         = Get-SharingRelationshipKind
            sharingType              = $script:SharingType
            modernSharing            = [bool]$script:ModernSharing
            legacyMapiSharing        = [bool]$script:LegacyMapiSharing
            publishedSharing         = [bool]$script:PublishedSharing
            externalSharing          = [bool]$script:ExternalSharing
            fatalPrerequisiteFailure = $fatalFailure
        }
        collectors       = $script:CollectorStatuses
        findings         = $jsonFindings
        collectionErrors = @($script:CollectionErrors)
        evaluationErrors = @($script:EvaluationErrors)
        rawData          = Get-SharingJsonRawData
    }
}

function Write-SharingJsonReport {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-CalendarDiagnosticJsonFile -InputObject (Get-SharingJsonReportObject) -Path $Path -Depth 8
}
