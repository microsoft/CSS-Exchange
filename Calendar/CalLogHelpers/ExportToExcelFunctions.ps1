# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Export to Excel
function Export-CalLogExcel {
    Write-Host -ForegroundColor Cyan "Exporting Enhanced CalLogs to Excel Tab [$ShortId]..."
    $script:lastRow = 1000 # Default last row, will be updated later
    $script:firstRow = 3 # Row 1 is the Title, Row 2 is the Header
    $script:lastColumn = "AN" # Column AN is the last column in the Excel sheet

    $ExcelParamsArray = GetExcelParams -path $FileName -tabName $ShortId

    # Suppress EPPlus warnings and errors that occur when writing to an existing file
    # (AutoNameRange validation, named range conflicts, title character warnings)
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $excel = $script:EnhancedCalLogs | Export-Excel @ExcelParamsArray -PassThru 3>$null
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }

    FormatHeader ($excel)
    CheckRows ($excel)

    # Set tab color to match the role (Organizer=Orange, Room=Green, Attendee=Blue)
    $excel.Workbook.Worksheets[$ShortId].TabColor = $script:TabColor

    Export-Excel -ExcelPackage $excel -WorksheetName $ShortId -MoveToStart

    # Log script info (will be positioned in the middle)
    LogScriptInfo

    # Export Raw Logs for Developer Analysis in collected order; do not apply the Enhanced tab sort here.
    Write-Host -ForegroundColor Cyan "Exporting Raw CalLogs to Excel Tab [$($ShortId + "_Raw")]..."
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $rawExcel = $script:GCDO | Export-Excel -Path $FileName -WorksheetName $($ShortId + "_Raw") -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -ClearSheet -PassThru 3>$null
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    $rawExcel.Workbook.Worksheets[$ShortId + "_Raw"].TabColor = $script:TabColor
    Export-Excel -ExcelPackage $rawExcel -WorksheetName $($ShortId + "_Raw")
}

function Format-ElapsedTime {
    param(
        [TimeSpan]$Elapsed
    )

    if ($Elapsed.TotalHours -ge 1) {
        return ('{0:00}:{1:00}:{2:00}' -f [int]$Elapsed.TotalHours, $Elapsed.Minutes, $Elapsed.Seconds)
    }

    return ('{0:00}:{1:00}' -f [int]$Elapsed.TotalMinutes, $Elapsed.Seconds)
}

function Get-ExceptionSummaryText {
    $exceptionLogs = @($script:GCDO | Where-Object {
            ($null -ne $_.OriginalStartDate -and $_.OriginalStartDate -ne 'NotFound' -and -not [string]::IsNullOrEmpty([string]$_.OriginalStartDate)) -or
            (IsExceptionItemType (GetItemType $_.ItemClass))
        })
    $exceptionCount = $exceptionLogs.Count

    switch ($script:ExceptionCollectionStatus) {
        'CollectedFast' {
            if ($AllExceptions.IsPresent) {
                return "Yes - $exceptionCount exception log(s) collected with default fast exception collection for all Exception dates."
            }
            return "Yes - $exceptionCount exception log(s) collected with default fast exception collection for the last 3 months."
        }
        'CollectedLegacyFallback' {
            if ($AllExceptions.IsPresent) {
                return "Yes - $exceptionCount exception log(s) collected after default fast exception collection fell back to the legacy collector for all Exception dates."
            }
            return "Yes - $exceptionCount exception log(s) collected after default fast exception collection fell back to the legacy collector for the last 3 months."
        }
        'Collected' {
            return "Yes - $exceptionCount exception log(s) collected."
        }
        'NoExceptionDates' {
            return "No - the AppointmentRecurrenceBlob did not expose matching Exception dates."
        }
        'NotRecurring' {
            return "No - the meeting is not recurring."
        }
        'SkippedBySwitch' {
            return "No - skipped because -NoExceptions was used."
        }
        'SkippedUntilMeetingIdChosen' {
            return "No - skipped because -ExceptionDate requires rerunning with -MeetingID."
        }
        'SkippedMultipleMeetingIds' {
            return "No - skipped because Subject search resolved to multiple MeetingIDs."
        }
        'NoMeetingId' {
            return "No - no MeetingID was resolved from the Subject search."
        }
        default {
            if (-not $Exceptions.IsPresent) {
                return "No - Exception collection was not requested."
            }
            if ($exceptionCount -gt 0) {
                return "Yes - $exceptionCount exception log(s) present in the collected output."
            }
            return "No - no exception logs were found in the collected output."
        }
    }
}

function Get-CollectionMethodDescription {
    if ($script:SubjectSearch) {
        if ($script:SubjectMeetingIdCount -eq 1) {
            if ($script:ExceptionCollectionStatus -eq 'CollectedFast') {
                if ($AllExceptions.IsPresent) {
                    return 'Subject search resolved to one MeetingID; Exception data collected with default fast exception collection for all Exception dates. Tracking Logs still require -MeetingID.'
                }
                return 'Subject search resolved to one MeetingID; Exception data collected with default fast exception collection for the last 3 months. Tracking Logs still require -MeetingID.'
            }
            if ($script:ExceptionCollectionStatus -eq 'CollectedLegacyFallback') {
                if ($AllExceptions.IsPresent) {
                    return 'Subject search resolved to one MeetingID; default fast exception collection failed and the script fell back to the legacy Exception collector for all Exception dates. Tracking Logs still require -MeetingID.'
                }
                return 'Subject search resolved to one MeetingID; default fast exception collection failed and the script fell back to the legacy Exception collector for the last 3 months. Tracking Logs still require -MeetingID.'
            }
            if ($script:ExceptionCollectionStatus -eq 'Collected') {
                if ($ClassicExceptions.IsPresent) {
                    return 'Subject search resolved to one MeetingID; Exception data collected with -ClassicExceptions (legacy path). Tracking Logs still require -MeetingID.'
                }
                return 'Subject search resolved to one MeetingID; Exception data collected. Tracking Logs still require -MeetingID.'
            }
            if ($script:ExceptionCollectionStatus -eq 'SkippedBySwitch') {
                return 'Subject search resolved to one MeetingID; Exception collection was skipped because -NoExceptions was used. Tracking Logs still require -MeetingID.'
            }
            if ($script:ExceptionCollectionStatus -eq 'SkippedUntilMeetingIdChosen') {
                return 'Subject search resolved to one MeetingID; targeted Exception collection was skipped because -ExceptionDate requires rerunning with -MeetingID. Tracking Logs still require -MeetingID.'
            }
            if ($script:ExceptionCollectionStatus -eq 'NoExceptionDates') {
                return 'Subject search resolved to one MeetingID; the AppointmentRecurrenceBlob did not expose any matching Exception dates to collect. Tracking Logs still require -MeetingID.'
            }
            if ($script:ExceptionCollectionStatus -eq 'NotRecurring') {
                return 'Subject search resolved to one MeetingID; Exception lookup ran, but the meeting is not recurring. Tracking Logs still require -MeetingID.'
            }
            return 'Subject search resolved to one MeetingID. Tracking Logs still require -MeetingID for full collection.'
        }
        if ($script:SubjectMeetingIdCount -gt 1) {
            return 'Subject search resolved to multiple MeetingIDs; Exception collection was skipped. Re-run with a specific -MeetingID to collect meeting exceptions.'
        }
        return 'Subject search did not resolve to a MeetingID.'
    }

    if (-not [string]::IsNullOrEmpty($ExceptionDate)) {
        return 'MeetingID search with targeted -ExceptionDate collection.'
    }
    if ($NoExceptions.IsPresent) {
        return 'MeetingID search with Exception collection disabled by -NoExceptions.'
    }
    if ($script:ExceptionCollectionStatus -eq 'CollectedFast') {
        if ($AllExceptions.IsPresent) {
            return 'MeetingID search with default fast exception collection for all Exception dates.'
        }
        return 'MeetingID search with default fast exception collection for the last 3 months.'
    }
    if ($script:ExceptionCollectionStatus -eq 'CollectedLegacyFallback') {
        if ($AllExceptions.IsPresent) {
            return 'MeetingID search where default fast exception collection failed and the script fell back to the legacy Exception collector for all Exception dates.'
        }
        return 'MeetingID search where default fast exception collection failed and the script fell back to the legacy Exception collector for the last 3 months.'
    }
    if ($script:ExceptionCollectionStatus -eq 'Collected') {
        if ($ClassicExceptions.IsPresent) {
            return 'MeetingID search with -ClassicExceptions legacy Exception collection.'
        }
        return 'MeetingID search with Exception collection.'
    }
    if ($script:ExceptionCollectionStatus -eq 'NoExceptionDates') {
        return 'MeetingID search where the AppointmentRecurrenceBlob did not expose any matching Exception dates to collect.'
    }
    if ($script:ExceptionCollectionStatus -eq 'NotRecurring') {
        return 'MeetingID search where the meeting is not recurring, so no Exception logs were collected.'
    }
    return 'MeetingID'
}

function LogScriptInfo {
    # Increment run number only once per script invocation (not per identity)
    if (-not $script:RunNumberSet) {
        # Read the existing run count from the Excel file so numbering is continuous across sessions
        if ($script:RunNumber -eq 0 -and (Test-Path $FileName)) {
            try {
                $pkg = Open-ExcelPackage -Path $FileName -ErrorAction SilentlyContinue
                if ($null -ne $pkg -and $null -ne $pkg.Workbook.Worksheets["Script Info"]) {
                    $existingInfo = Import-Excel -ExcelPackage $pkg -WorksheetName "Script Info" -ErrorAction SilentlyContinue
                    if ($null -ne $existingInfo) {
                        $lastRunKey = $existingInfo | Where-Object { $_.Key -like "--- Run #* ---" } | Select-Object -Last 1
                        if ($null -ne $lastRunKey -and $lastRunKey.Key -match '#(\d+)') {
                            $script:RunNumber = [int]$Matches[1]
                        }
                    }
                }
            } catch {
                Write-Verbose "Unable to read existing run count from Excel: $_"
            } finally {
                if ($null -ne $pkg) { $pkg.Dispose() }
            }
        }
        $script:RunNumber++
        $script:RunNumberSet = $true
        $script:RunHeaderWritten = $false
    }

    $RunInfo = [System.Collections.Generic.List[object]]::new()

    # Write run header and shared info only once per run (on the first identity)
    if (-not $script:RunHeaderWritten) {
        $RunInfo.Add([PSCustomObject]@{
                Key   = "--- Run #$($script:RunNumber) ---"
                Value = "---"
            })
        $RunInfo.Add([PSCustomObject]@{
                Key   = "RunTime"
                Value = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            })
        $RunInfo.Add([PSCustomObject]@{
                Key   = "Script Name"
                Value = $($script:command.MyCommand.Name)
            })
        $RunInfo.Add([PSCustomObject]@{
                Key   = "Command Line"
                Value = $($script:command.Line)
            })

        # Combine version and age into one line
        $versionText = if (-not [string]::IsNullOrEmpty($script:BuildVersion)) { $script:BuildVersion } else { "Unknown" }
        if (-not [string]::IsNullOrEmpty($script:BuildVersion)) {
            try {
                $parts = $script:BuildVersion.Split('.')
                $buildDate = [DateTime]::new(2000 + [int]$parts[0], [int]$parts[1], [int]$parts[2])
                $age = (Get-Date) - $buildDate
                $ageText = if ($age.Days -eq 0) { "today" }
                elseif ($age.Days -eq 1) { "1 day old" }
                elseif ($age.Days -lt 30) { "$($age.Days) days old" }
                elseif ($age.Days -lt 365) { "$([math]::Floor($age.Days / 30)) month(s) old" }
                else { "$([math]::Floor($age.Days / 365)) year(s), $([math]::Floor(($age.Days % 365) / 30)) month(s) old" }
                $versionText = "$versionText ($ageText, built $($buildDate.ToString('yyyy-MM-dd')))"
            } catch {
                Write-Verbose "Unable to parse BuildVersion '$($script:BuildVersion)' for age calculation: $_"
            }
        }
        $RunInfo.Add([PSCustomObject]@{
                Key   = "Script Version"
                Value = $versionText
            })

        $RunInfo.Add([PSCustomObject]@{
                Key   = "Identities"
                Value = ($ValidatedIdentities -join '; ')
            })

        $RunInfo.Add([PSCustomObject]@{
                Key   = "Collection Method"
                Value = (Get-CollectionMethodDescription)
            })

        # Only log environment info on the first run
        if ($script:RunNumber -eq 1) {
            $RunInfo.Add([PSCustomObject]@{
                    Key   = "User"
                    Value = whoami.exe
                })
            $RunInfo.Add([PSCustomObject]@{
                    Key   = "PowerShell Version"
                    Value = $PSVersionTable.PSVersion
                })
            $RunInfo.Add([PSCustomObject]@{
                    Key   = "OS Version"
                    Value = $(Get-CimInstance -ClassName Win32_OperatingSystem).Version
                })
            $RunInfo.Add([PSCustomObject]@{
                    Key   = "More Info"
                    Value = "https://learn.microsoft.com/en-us/exchange/troubleshoot/calendars/analyze-calendar-diagnostic-logs"
                })
        }

        $script:RunHeaderWritten = $true
    }

    # Per-identity line: show which identity was collected and log count
    $logCount = if ($null -ne $script:GCDO) { $script:GCDO.Count } else { 0 }
    $elapsedText = 'Unknown'
    if ($null -ne $script:CurrentIdentityRunStartTime) {
        $elapsedText = Format-ElapsedTime -Elapsed ((Get-Date) - $script:CurrentIdentityRunStartTime)
    }
    $RunInfo.Add([PSCustomObject]@{
            Key   = "  $($script:Identity)"
            Value = "$logCount logs collected in $elapsedText at $(Get-Date -Format 'HH:mm:ss')"
        })
    $RunInfo.Add([PSCustomObject]@{
            Key   = "    Duration"
            Value = $elapsedText
        })
    $RunInfo.Add([PSCustomObject]@{
            Key   = "    Exceptions"
            Value = (Get-ExceptionSummaryText)
        })

    # Capture errors that occurred during this identity (new errors since last snapshot)
    # Filter out EPPlus internal errors (IsValidAddress) and Import-Excel worksheet-not-found errors
    $newErrors = @()
    for ($i = 0; $i -lt ($Error.Count - $script:PreRunErrorCount); $i++) {
        $err = $Error[$i]
        $msg = if ($err -is [System.Management.Automation.ErrorRecord]) { $err.Exception.Message } else { $err.ToString() }
        if ($msg -notlike '*IsValidAddress*' -and $msg -notlike '*Worksheet*Script Info*not found*') {
            $newErrors += $err
        }
    }
    if ($newErrors.Count -gt 0) {
        for ($i = 0; $i -lt $newErrors.Count; $i++) {
            $err = $newErrors[$i]
            $errorMessage = if ($err -is [System.Management.Automation.ErrorRecord]) {
                "$($err.Exception.Message) [$($err.CategoryInfo.Category): $($err.FullyQualifiedErrorId)]"
            } else {
                $err.ToString()
            }
            $RunInfo.Add([PSCustomObject]@{
                    Key   = "    Error $($i + 1)"
                    Value = $errorMessage
                })
        }
    }
    # Update snapshot so next identity only captures new errors
    $script:PreRunErrorCount = $Error.Count

    # Write Script Info into the existing workbook (Enhanced tab was already saved)
    $savedEAP = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'

        # Open existing package and add/append the Script Info sheet
        try {
            $pkg = Open-ExcelPackage -Path $FileName -ErrorAction Stop
            $sheetExists = $null -ne $pkg.Workbook.Worksheets["Script Info"]

            if ($sheetExists) {
                # Append rows after existing data
                $ws = $pkg.Workbook.Worksheets["Script Info"]
                $startRow = $ws.Dimension.End.Row + 1
            } else {
                # Create a new sheet
                $ws = $pkg.Workbook.Worksheets.Add("Script Info")
                $startRow = 1
                # Add header row
                $ws.Cells[$startRow, 1].Value = "Key"
                $ws.Cells[$startRow, 2].Value = "Value"
                $startRow = 2
            }

            foreach ($item in $RunInfo) {
                $ws.Cells[$startRow, 1].Value = $item.Key
                $ws.Cells[$startRow, 2].Value = [string]$item.Value
                $startRow++
            }

            $ws.Column(1).Width = 25
            $ws.Column(2).Width = 80
            $ws.TabColor = [System.Drawing.Color]::Gray
            $pkg.Save()
            $pkg.Dispose()
        } catch {
            Write-Warning "Unable to write Script Info tab: $_"
            if ($null -ne $pkg) { $pkg.Dispose() }
        }
    } finally {
        $ErrorActionPreference = $savedEAP
    }
}

function Export-TimelineExcel {
    Write-Host -ForegroundColor Cyan "Exporting Timeline to Excel..."
    $savedEAP = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $tlExcel = $script:TimeLineOutput | Export-Excel -Path $FileName -WorksheetName $($ShortId + "_TimeLine") -Title "Timeline for $Identity" -AutoSize -FreezeTopRow -BoldTopRow -ClearSheet -PassThru 3>$null
    } finally {
        $ErrorActionPreference = $savedEAP
    }
    $tlExcel.Workbook.Worksheets[$ShortId + "_TimeLine"].TabColor = $script:TabColor
    Export-Excel -ExcelPackage $tlExcel -WorksheetName $($ShortId + "_TimeLine")
}

function GetExcelParams($path, $tabName) {
    if ($script:IsOrganizer) {
        $TableStyle = "Light10" # Orange for Organizer
        $TitleExtra = ", Organizer"
        $script:TabColor = [System.Drawing.Color]::FromArgb(237, 125, 49) # Orange
    } elseif ($script:IsRoomMB) {
        Write-Host -ForegroundColor green "Room Mailbox Detected"
        $TableStyle = "Light11" # Green for Room Mailbox
        $TitleExtra = ", Resource"
        $script:TabColor = [System.Drawing.Color]::FromArgb(112, 173, 71) # Green
    } elseif ($script:IsDelegateOfOrganizer) {
        Write-Host -ForegroundColor Magenta "Delegate of Organizer Detected"
        $TableStyle = "Light10" # Orange family for Organizer-side
        $TitleExtra = ", Delegate"
        $script:TabColor = [System.Drawing.Color]::FromArgb(204, 85, 0) # Dark Orange
    } elseif ($script:IsDelegateOfAttendee) {
        Write-Host -ForegroundColor Magenta "Delegate of Attendee Detected"
        $TableStyle = "Light14" # Purple family for Attendee-side Delegate
        $TitleExtra = ", Delegate"
        $script:TabColor = [System.Drawing.Color]::FromArgb(112, 48, 160) # Dark Purple
    } else {
        $TableStyle = "Light12" # Light Blue for normal Attendee
        $script:TabColor = [System.Drawing.Color]::FromArgb(91, 155, 213) # Blue
    }

    if ($script:CalLogsDisabled) {
        $TitleExtra += ", WARNING: CalLogs are Turned Off for $Identity! This will be a incomplete story"
        $script:TabColor = [System.Drawing.Color]::FromArgb(255, 0, 0) # Red for Disabled CalLogs
    }

    if ($script:SubjectSearch) {
        if ($script:SubjectMeetingIdCount -eq 1) {
            if ($script:ExceptionCollectionStatus -eq "CollectedFast") {
                $TitleExtra += ", Collected with Subject search and default fast exception collection"
            } elseif ($script:ExceptionCollectionStatus -eq "CollectedLegacyFallback") {
                $TitleExtra += ", Collected with Subject search (default fast exception collection fell back to legacy)"
            } elseif ($script:ExceptionCollectionStatus -eq "Collected") {
                if ($ClassicExceptions.IsPresent) {
                    $TitleExtra += ", Collected with Subject search and -ClassicExceptions (legacy Exception collection)"
                } else {
                    $TitleExtra += ", Collected with Subject search and Exception data"
                }
            } elseif ($script:ExceptionCollectionStatus -eq "SkippedBySwitch") {
                $TitleExtra += ", Collected with Subject search (-NoExceptions used)"
            } elseif ($script:ExceptionCollectionStatus -eq "SkippedUntilMeetingIdChosen") {
                $TitleExtra += ", Collected with Subject search (-ExceptionDate requires rerun with -MeetingID)"
            } elseif ($script:ExceptionCollectionStatus -eq "NoExceptionDates") {
                $TitleExtra += ", Collected with Subject search (no matching Exception dates in AppointmentRecurrenceBlob)"
            } elseif ($script:ExceptionCollectionStatus -eq "NotRecurring") {
                $TitleExtra += ", Collected with Subject search (no recurring Exception data)"
            } else {
                $TitleExtra += ", Collected with Subject search"
            }
        } elseif ($script:SubjectMeetingIdCount -gt 1) {
            $TitleExtra += ", Collected with Subject search (multiple MeetingIDs; rerun with -MeetingID for Exceptions)"
        } else {
            $TitleExtra += ", Collected with Subject search"
        }
    }

    $script:lastRow = $script:GCDO.Count + $firstRow - 1 # Last row is the number of items in the GCDO array + 2 for the header and title rows.
    Write-Host -ForegroundColor Gray "Last Row is $lastRow, First Row is $firstRow, Last Column is $lastColumn"

    return @{
        Path                    = $path
        FreezeTopRow            = $true
        #  BoldTopRow              = $true
        Verbose                 = $false
        TableStyle              = $TableStyle
        WorksheetName           = $tabName
        TableName               = $tabName
        FreezeTopRowFirstColumn = $true
        AutoFilter              = $true
        ClearSheet              = $true
        Title                   = "Enhanced Calendar Logs for $Identity" + $TitleExtra + " for MeetingID [$($script:GCDO[0].CleanGlobalObjectId)]."
        TitleSize               = 14
        ConditionalText         = (Get-ConditionalFormattingRules)
    }
}

$ColumnMap = @{
    LogTimestamp                   = "A"
    LogRowType                     = "B"
    SubjectProperty                = "C"
    Client                         = "D"
    LogClientInfoString            = "E"
    TriggerAction                  = "F"
    ItemClass                      = "G"
    SeqExpItemVersion              = "H"
    Organizer                      = "I"
    From                           = "J"
    FreeBusyStatus                 = "K"
    ResponsibleUser                = "L"
    Sender                         = "M"
    LogFolder                      = "N"
    OriginalLogFolder              = "O"
    SharedFolderName               = "P"
    ReceivedRepresenting           = "Q"
    MeetingRequestType             = "R"
    StartTime                      = "S"
    EndTime                        = "T"
    OriginalStartDate              = "U"
    Location                       = "V"
    CalendarItemType               = "W"
    RecurrencePattern              = "X"
    AppointmentAuxiliaryFlags      = "Y"
    DisplayAttendeesAll            = "Z"
    AttendeeCount                  = "AA"
    AppointmentState               = "AB"
    ResponseType                   = "AC"
    ClientIntent                   = "AD"
    AppointmentRecurring           = "AE"
    HasAttachment                  = "AF"
    IsCancelled                    = "AG"
    IsAllDayEvent                  = "AH"
    Sensitivity                    = "AI"
    IsSeriesCancelled              = "AJ"
    SendMeetingMessagesDiagnostics = "AK"
    AttendeeCollection             = "AL"
    CalendarLogRequestId           = "AM"
    CleanGlobalObjectId            = "AN"
}

function GetExcelColumnNumber {
    param([string]$ColumnLetter)
    $number = 0
    $letters = $ColumnLetter.ToUpper().ToCharArray()
    foreach ($char in $letters) {
        $number = $number * 26 + ([int][char]$char - [int][char]'A' + 1)
    }
    return $number
}

function Get-ConditionalFormattingRules {
    if (-not (Get-Command -Name New-ConditionalText -ErrorAction SilentlyContinue)) {
        Write-Verbose "New-ConditionalText is unavailable; skipping Excel conditional formatting rules."
        return @()
    }

    return @(
        # Client, ShortClientInfoString and LogClientInfoString
        New-ConditionalText "Outlook" -ConditionalTextColor Green -BackgroundColor $null
        New-ConditionalText "OWA" -ConditionalTextColor DarkGreen -BackgroundColor $null
        New-ConditionalText "Teams" -ConditionalTextColor DarkGreen -BackgroundColor $null
        New-ConditionalText "Transport" -ConditionalTextColor Blue -BackgroundColor $null
        New-ConditionalText "Repair" -ConditionalTextColor DarkRed -BackgroundColor LightPink
        New-ConditionalText "Other ?BA" -ConditionalTextColor Orange -BackgroundColor $null
        New-ConditionalText "TimeService" -ConditionalTextColor Orange -BackgroundColor $null
        New-ConditionalText "Other REST" -ConditionalTextColor DarkRed -BackgroundColor $null
        New-ConditionalText "Unknown" -ConditionalTextColor DarkRed -BackgroundColor $null
        New-ConditionalText "ResourceBookingAssistant" -ConditionalTextColor Blue -BackgroundColor $null
        New-ConditionalText "Calendar Replication" -ConditionalTextColor Blue -BackgroundColor $null

        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "Interesting" -ConditionalTextColor Green -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "SeriesException" -ConditionalTextColor Green -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "DeletedSeriesException" -ConditionalTextColor Orange -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "MeetingMessageChange" -ConditionalTextColor Orange -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "SyncOrReplication" -ConditionalTextColor Blue -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'LogRowType') -ConditionalType ContainsText -Text "OtherAssistant" -ConditionalTextColor Orange -BackgroundColor $null

        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'TriggerAction') -ConditionalType ContainsText -Text "Create" -ConditionalTextColor Green -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'TriggerAction') -ConditionalType ContainsText -Text "Delete" -ConditionalTextColor Red -BackgroundColor $null

        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text "IPM.Appointment" -ConditionalTextColor Blue -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text "Cancellation" -ConditionalTextColor Black -BackgroundColor Orange
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text ".Request" -ConditionalTextColor DarkGreen -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text ".Resp." -ConditionalTextColor Orange -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ItemClass') -ConditionalType ContainsText -Text "IPM.OLE.CLASS" -ConditionalTextColor Plum -BackgroundColor $null

        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'FreeBusyStatus') -ConditionalType ContainsText -Text "Free" -ConditionalTextColor Red -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'FreeBusyStatus') -ConditionalType ContainsText -Text "Tentative" -ConditionalTextColor Orange -BackgroundColor $null
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'FreeBusyStatus') -ConditionalType ContainsText -Text "Busy" -ConditionalTextColor Green -BackgroundColor $null

        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'MeetingRequestType') -ConditionalType ContainsText -Text "Outdated" -ConditionalTextColor DarkRed -BackgroundColor LightPink

        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'CalendarItemType') -ConditionalType ContainsText -Text "RecurringMaster" -ConditionalTextColor $null -BackgroundColor Plum

        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'AppointmentAuxiliaryFlags') -ConditionalType ContainsText -Text "Copied" -ConditionalTextColor DarkRed -BackgroundColor LightPink
        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'AppointmentAuxiliaryFlags') -ConditionalType ContainsText -Text "ForwardedAppointment" -ConditionalTextColor DarkRed -BackgroundColor $null

        New-ConditionalText -Range (Get-ColumnRange -PropertyName 'ResponseType') -ConditionalType ContainsText -Text "Organizer" -ConditionalTextColor Orange -BackgroundColor $null
    )
}

function Get-ColumnRange {
    param(
        [string]$PropertyName,
        [int]$StartRow = 3,
        [int]$EndRow = $script:lastRow
    )

    if ($EndRow -eq 0) {
        $EndRow = 2000
    }

    $col = $ColumnMap[$PropertyName]

    # if ($null -eq $col) { throw "Unknown property: $PropertyName" }
    if ($StartRow -and $EndRow) {
        #  Write-Host -ForegroundColor DarkGray "Getting column range for $PropertyName : $col, StartRow: $StartRow, EndRow: $EndRow"
        return $col + $StartRow + ":" + $col + $EndRow
    } else {
        return $col + ":" + $col
    }
}

function CheckRows {
    param(
        [object] $excel
    )
    $sheet = $excel.Workbook.Worksheets[$ShortId]

    # Pre-filter LogRowType to hide noisy rows (OtherAssistant, MeetingMessageChange, deleted exceptions)
    SetLogRowTypeFilter -excel $excel

    # Highlight the Resp in LightGoldenRodYellow
    CheckColumnForText -sheet $sheet -columnNumber $(GetExcelColumnNumber($ColumnMap.ItemClass)) -textToFind "Resp" -cellColor "LightGoldenRodYellow" -fontColor "Black"

    # Highlight the RUM in Red
    CheckColumnForText -sheet $sheet -columnNumber $(GetExcelColumnNumber($ColumnMap.AppointmentAuxiliaryFlags)) -textToFind "RepairUpdateMessage" -cellColor "White" -fontColor "DarkRed"

    #Highlight the Cancellation in Orange
    CheckColumnsForValues -sheet $sheet -columnNumber1  $(GetExcelColumnNumber($ColumnMap.ItemClass)) -value1 "Cancellation" -columnNumber2  $(GetExcelColumnNumber($ColumnMap.TriggerAction)) -value2 "Create" -cellColor "Khaki" -fontColor "Black"

    # Highlight the Create from Transport in light blue
    CheckColumnsForValues -sheet $sheet -columnNumber1  $(GetExcelColumnNumber($ColumnMap.LogClientInfoString)) -value1 "Transport" -columnNumber2  $(GetExcelColumnNumber($ColumnMap.TriggerAction)) -value2 "Create" -cellColor "LightBlue" -fontColor "Black"

    # Highlight SharedFolderName with unique colors per shared folder
    HighlightSharedFolderNames -sheet $sheet

    # Detect organizer anomalies (only on organizer's tab)
    if ($script:IsOrganizer) {
        CheckOrganizerErrors -sheet $sheet
    }

    $excel.Save()
}

<#
.SYNOPSIS
Pre-filters the LogRowType column in the Excel table to hide noisy row types.
Hides OtherAssistant, MeetingMessageChange, and DeletedSeriesException rows by default.
Users can clear the filter in Excel to see all rows.
#>
function SetLogRowTypeFilter {
    param(
        [object] $excel
    )

    $sheet = $excel.Workbook.Worksheets[$ShortId]
    $logRowCol = GetExcelColumnNumber($ColumnMap.LogRowType)

    # Values to hide by default
    $hideValues = @("OtherAssistant", "MeetingMessageChange", "DeletedSeriesException")

    # Collect all unique values in the LogRowType column
    $lastDataRow = $sheet.Dimension.End.Row
    $allValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    for ($row = $script:firstRow; $row -le $lastDataRow; $row++) {
        $val = $sheet.Cells[$row, $logRowCol].Text
        if (-not [string]::IsNullOrEmpty($val)) {
            [void]$allValues.Add($val)
        }
    }

    $showValues = @($allValues | Where-Object { $_ -notin $hideValues })
    if ($showValues.Count -eq $allValues.Count) {
        Write-Verbose "No LogRowType values to filter out."
        return
    }

    Write-Verbose "Pre-filtering LogRowType: hiding $($hideValues -join ', ')"

    # Get the table and its autoFilter XML node
    $tbl = $sheet.Tables[0]
    if ($null -eq $tbl) {
        Write-Verbose "No table found, skipping LogRowType filter."
        return
    }

    $ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    $nsm = [System.Xml.XmlNamespaceManager]::new($tbl.TableXml.NameTable)
    $nsm.AddNamespace("t", $ns)
    $autoFilter = $tbl.TableXml.SelectSingleNode("//t:autoFilter", $nsm)

    if ($null -eq $autoFilter) {
        Write-Verbose "No autoFilter found in table, skipping."
        return
    }

    # Build filterColumn with visible values (Excel filters list what to SHOW)
    # colId is 0-based relative to the table, LogRowType is the 2nd column (B) = colId 1
    $tableStartCol = $tbl.Address.Start.Column
    $filterColId = $logRowCol - $tableStartCol

    # Remove any existing filterColumn for this colId to avoid duplicates on reruns
    $existingFilterCol = $autoFilter.SelectSingleNode("t:filterColumn[@colId='$filterColId']", $nsm)
    if ($null -ne $existingFilterCol) {
        $null = $autoFilter.RemoveChild($existingFilterCol)
    }

    $filterCol = $tbl.TableXml.CreateElement("filterColumn", $ns)
    $filterCol.SetAttribute("colId", $filterColId.ToString())
    $filters = $tbl.TableXml.CreateElement("filters", $ns)

    foreach ($val in $showValues) {
        $f = $tbl.TableXml.CreateElement("filter", $ns)
        $f.SetAttribute("val", $val)
        $null = $filters.AppendChild($f)
    }
    $null = $filterCol.AppendChild($filters)
    $null = $autoFilter.AppendChild($filterCol)

    # Hide the actual rows so they appear filtered on open
    # Removed row-hiding logic to ensure no rows are hidden
    # for ($row = $script:firstRow; $row -le $lastDataRow; $row++) {
    #     $val = $sheet.Cells[$row, $logRowCol].Text
    #     if ($val -in $hideValues) {
    #         $sheet.Row($row).Hidden = $true
    #     }
    # }
}

<#
.SYNOPSIS
Detects organizer anomalies on the Organizer's tab:
1. ResponseType changes from "Organizer" to something else on IPM.Appointment/Exception rows (not shared).
2. The From (Organizer SMTP) changes between qualifying rows, indicating multiple organizers.
Highlights the row text in Red and the problematic cell in Yellow.
#>
function CheckOrganizerErrors {
    param(
        [object] $sheet
    )

    $itemClassCol = GetExcelColumnNumber($ColumnMap.ItemClass)
    $sharedFolderCol = GetExcelColumnNumber($ColumnMap.SharedFolderName)
    $responseTypeCol = GetExcelColumnNumber($ColumnMap.ResponseType)
    $fromCol = GetExcelColumnNumber($ColumnMap.From)
    $lastDataRow = $sheet.Dimension.End.Row
    $lastDataCol = $sheet.Dimension.End.Column

    $firstOrganizer = $null  # Track the first From value seen on a qualifying row

    for ($row = $script:firstRow; $row -le $lastDataRow; $row++) {
        $itemClass = $sheet.Cells[$row, $itemClassCol].Text
        $sharedFolder = $sheet.Cells[$row, $sharedFolderCol].Text

        # Only check IPM.Appointment and Exception rows that are not shared
        if (($itemClass -ne "Ipm.Appointment" -and $itemClass -notlike "Exception*") -or
            $sharedFolder -ne "Not Shared") {
            continue
        }

        $responseType = $sheet.Cells[$row, $responseTypeCol].Text
        $fromValue = $sheet.Cells[$row, $fromCol].Text

        # Check 1: ResponseType should be "Organizer" on the organizer's tab
        if ($responseType -ne "Organizer") {
            # Red text for the whole row
            $rowRange = $sheet.Cells[$row, 1, $row, $lastDataCol]
            $rowRange.Style.Font.Color.SetColor([System.Drawing.Color]::Red)
            # Yellow highlight on the ResponseType cell
            $cell = $sheet.Cells[$row, $responseTypeCol]
            $cell.Style.Fill.PatternType = 'Solid'
            $cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Yellow)
        }

        # Check 2: From (Organizer SMTP) should not change between qualifying rows
        if ([string]::IsNullOrEmpty($fromValue) -or $fromValue -eq "-") {
            continue
        }

        if ($null -eq $firstOrganizer) {
            $firstOrganizer = $fromValue
        } elseif (-not (IsSameOrganizerIdentity $fromValue $firstOrganizer)) {
            # Red text for the whole row
            $rowRange = $sheet.Cells[$row, 1, $row, $lastDataCol]
            $rowRange.Style.Font.Color.SetColor([System.Drawing.Color]::Red)
            # Yellow highlight on the From cell
            $cell = $sheet.Cells[$row, $fromCol]
            $cell.Style.Fill.PatternType = 'Solid'
            $cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Yellow)
        }
    }
}

<#
.SYNOPSIS
Highlights rows in the SharedFolderName column with a unique pale color per shared folder name.
Cycles through 7 pale colors if there are more than 7 unique shared folder names.
#>
function HighlightSharedFolderNames {
    param(
        [object] $sheet
    )

    $sharedFolderCol = GetExcelColumnNumber($ColumnMap.SharedFolderName)
    $lastDataRow = $sheet.Dimension.End.Row
    $lastDataCol = $sheet.Dimension.End.Column

    # Debug: verify column alignment
    $headerValue = $sheet.Cells[2, $sharedFolderCol].Text
    Write-Verbose "HighlightSharedFolderNames: Column $($ColumnMap.SharedFolderName) = col# $sharedFolderCol, header='$headerValue', rows=$($script:firstRow)..$lastDataRow"
    if ($headerValue -ne "SharedFolderName") {
        # Column map is misaligned — find the actual column by scanning the header row
        for ($c = 1; $c -le $lastDataCol; $c++) {
            if ($sheet.Cells[2, $c].Text -eq "SharedFolderName") {
                Write-Host -ForegroundColor Yellow "HighlightSharedFolderNames: SharedFolderName found at column $c (expected $sharedFolderCol)"
                $sharedFolderCol = $c
                break
            }
        }
    }

    # Pale colors that are readable with black text
    # cSpell:ignore FromArgb
    [System.Drawing.Color[]] $PaleColors = @(
        [System.Drawing.Color]::FromArgb(220, 245, 220)  # Pale Green
        [System.Drawing.Color]::FromArgb(180, 215, 255)  # Pale Blue
        [System.Drawing.Color]::FromArgb(255, 240, 220)  # Pale Peach
        [System.Drawing.Color]::FromArgb(245, 230, 255)  # Pale Lavender
        [System.Drawing.Color]::FromArgb(255, 255, 210)  # Pale Yellow
        [System.Drawing.Color]::FromArgb(255, 225, 230)  # Pale Pink
        [System.Drawing.Color]::FromArgb(220, 245, 245)  # Pale Cyan
    )

    # Collect unique SharedFolderName values and apply formatting in a single pass
    $folderNames = @{}
    $colorIndex = 0

    for ($row = $script:firstRow; $row -le $lastDataRow; $row++) {
        $cellValue = $sheet.Cells[$row, $sharedFolderCol].Text
        if ([string]::IsNullOrEmpty($cellValue) -or $cellValue -eq "Not Shared") {
            continue
        }
        if (-not $folderNames.ContainsKey($cellValue)) {
            $folderNames[$cellValue] = $PaleColors[$colorIndex % $PaleColors.Count]
            $colorIndex++
        }

        $color = $folderNames[$cellValue]
        # Italicize the entire row
        $rowRange = $sheet.Cells[$row, 1, $row, $lastDataCol]
        $rowRange.Style.Font.Italic = $true
        # Highlight only the SharedFolderName cell
        $cell = $sheet.Cells[$row, $sharedFolderCol]
        $cell.Style.Fill.PatternType = 'Solid'
        $cell.Style.Fill.BackgroundColor.SetColor($color)
    }

    if ($folderNames.Count -eq 0) {
        Write-Verbose "No shared folder names found to highlight."
    } else {
        Write-Verbose "Highlighted $($folderNames.Count) unique shared folder name(s)."
    }
}

function SortByLogTimestamp {
    param(
        [object] $excel
    )
    $sheet = $excel.Workbook.Worksheets[$ShortId]
    $dataStartRow = $script:firstRow # Row 3 (row 1 = title, row 2 = header)
    $dataEndRow = $sheet.Dimension.End.Row
    $dataEndCol = $sheet.Dimension.End.Column
    $sortCol = GetExcelColumnNumber($ColumnMap.LogTimestamp)

    # Sort the data range by LogTimestamp column ascending
    # EPPlus Sort() takes a 0-based column offset within the range
    $sortRange = $sheet.Cells[$dataStartRow, 1, $dataEndRow, $dataEndCol]
    $sortRange.Sort($sortCol - 1)
    $excel.Save()
}

# check if a column contains a specific text and highlight the row
# This function highlights a row in the Excel sheet based on the row number and specified colors.
# Parameters:
#   - $sheet: The Excel worksheet object.
function CheckColumnForText {
    param (
        [object] $sheet,
        [int] $columnNumber,
        [string] $textToFind,
        [string] $cellColor = "Yellow",
        [string] $fontColor = "DarkRed"
    )

    $lastDataRow = $sheet.Dimension.End.Row
    $lastDataCol = $sheet.Dimension.End.Column
    Write-Verbose "Checking column $columnNumber for text '$textToFind'..."
    for ($row = $script:firstRow; $row -le $lastDataRow; $row++) {
        $cellValue = $sheet.Cells[$row, $columnNumber].Text

        if ($cellValue -like "*$textToFind*") {
            HighlightRow -sheet $sheet -rowNumber $row -lastCol $lastDataCol -cellColor $cellColor -fontColor $fontColor
        }
    }
}

# Checks if two columns in the same row match specified values and highlights the row if both match.
function CheckColumnsForValues {
    param (
        [object] $sheet,
        [int] $columnNumber1,
        [string] $value1,
        [int] $columnNumber2,
        [string] $value2,
        [string] $cellColor = "LightPink",
        [string] $fontColor = "DarkRed"
    )

    $lastDataRow = $sheet.Dimension.End.Row
    $lastDataCol = $sheet.Dimension.End.Column
    Write-Verbose "Checking for rows where column $columnNumber1 = '$value1' AND column $columnNumber2 = '$value2'..."
    for ($row = $script:firstRow; $row -le $lastDataRow; $row++) {
        $cellValue1 = $sheet.Cells[$row, $columnNumber1].Text
        $cellValue2 = $sheet.Cells[$row, $columnNumber2].Text

        if ($cellValue1 -like "*$value1*" -and $cellValue2 -like "*$value2*") {
            HighlightRow -sheet $sheet -rowNumber $row -lastCol $lastDataCol -cellColor $cellColor -fontColor $fontColor
        }
    }
}

function HighlightRow {
    param(
        [object] $sheet,
        [int] $rowNumber,
        [int] $lastCol,
        [string] $cellColor = "Thistle",
        [string] $fontColor = "DarkRed"
    )

    $rowRange = $sheet.Cells[$rowNumber, 1, $rowNumber, $lastCol]
    Write-Verbose "Highlighting row $rowNumber with cell color [$cellColor] and font color [$fontColor]"
    $rowRange.Style.Fill.PatternType = 'Solid'
    $rowRange.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::$cellColor)
    $rowRange.Style.Font.Color.SetColor([System.Drawing.Color]::$fontColor)
}

function FormatHeader {
    param(
        [object] $excel
    )
    $sheet = $excel.Workbook.Worksheets[$ShortId]
    $HeaderRow = 2

    # Define header metadata: property name, width, alignment, number format, comment
    $headerMeta = @(
        @{ Name = "LogTimestamp"; Width = 20; Align = "Center"; NumberFormat = "m/d/yyyy h:mm:ss"; Comment = "LogTimestamp: Time when the change was recorded in the CalLogs. This and all Times are in UTC." }
        @{ Name = "LogRowType"; Width = 20; Align = "Left"; Comment = "LogRowType: Filtered by default! Interesting logs are what to focus on. OtherAssistant, MeetingMessageChange, and DeletedSeriesException are hidden. Clear the filter to see all rows." }
        @{ Name = "SubjectProperty"; Width = 20; Align = "Left"; Comment = "SubjectProperty: The Subject of the Meeting." }
        @{ Name = "Client"; Width = 20; Align = "Left"; Comment = "Client (ShortClientInfoString): The 'friendly' Client name of the client that made the change." }
        @{ Name = "LogClientInfoString"; Width = 5; Align = "Left"; Comment = "LogClientInfoString: Full Client Info String of client that made the change." }
        @{ Name = "TriggerAction"; Width = 12; Align = "Center"; Comment = "TriggerAction (CalendarLogTriggerAction): The type of action that caused the change." }
        @{ Name = "ItemClass"; Width = 18; Align = "Left"; Comment = "ItemClass: The Class of the Calendar Item" }
        @{ Name = "SeqExpItemVersion"; Width = 10; Align = "Center"; Comment = "Seq:Exp:ItemVersion (AppointmentLastSequenceNumber:AppointmentSequenceNumber:ItemVersion): The Sequence Version, the Exception Version, and the Item Version.  Each type of item has its own count." }
        @{ Name = "Organizer"; Width = 20; Align = "Left"; Comment = "Organizer (From.FriendlyDisplayName): The Organizer of the Calendar Item." }
        @{ Name = "From"; Width = 20; Align = "Left"; Comment = "From: The SMTP address of the Organizer of the Calendar Item." }
        @{ Name = "FreeBusyStatus"; Width = 12; Align = "Center"; Comment = "FreeBusy (FreeBusyStatus): The FreeBusy Status of the Calendar Item." }
        @{ Name = "ResponsibleUser"; Width = 20; Align = "Left"; Comment = "ResponsibleUser(ResponsibleUserName): The Responsible User of the change." }
        @{ Name = "Sender"; Width = 20; Align = "Left"; Comment = "Sender (SenderEmailAddress): The Sender of the change." }
        @{ Name = "LogFolder"; Width = 16; Align = "Left"; Comment = "LogFolder (ParentDisplayName): The Log Folder that the CalLog was in." }
        @{ Name = "OriginalLogFolder"; Width = 16; Align = "Left"; Comment = "OriginalLogFolder (OriginalParentDisplayName): The Original Log Folder that the item was in / delivered to." }
        @{ Name = "SharedFolderName"; Width = 15; Align = "Left"; Comment = "SharedFolderName: Was this from a Modern Sharing, and if so what Folder." }
        @{ Name = "ReceivedRepresenting"; Width = 10; Align = "Left"; Comment = "ReceivedRepresenting: Who the item was Received for, often the Delegate." }
        @{ Name = "MeetingRequestType"; Width = 10; Align = "Center"; Comment = "MeetingRequestType: The Meeting Request Type of the Meeting." }
        @{ Name = "StartTime"; Width = 23; Align = "Center"; NumberFormat = "m/d/yyyy h:mm:ss"; Comment = "StartTime: The Start Time of the Meeting. This and all Times are in UTC." }
        @{ Name = "EndTime"; Width = 23; Align = "Center"; NumberFormat = "m/d/yyyy h:mm:ss"; Comment = "EndTime: The End Time of the Meeting. This and all Times are in UTC." }
        @{ Name = "OriginalStartDate"; Width = 15; Align = "Left"; NumberFormat = "m/d/yy"; Comment = "OriginalStartDate: The Original Start Date of the Meeting." }
        @{ Name = "Location"; Width = 10; Align = "Left"; Comment = "Location: The Location of the Meeting." }
        @{ Name = "CalendarItemType"; Width = 15; Align = "Center"; Comment = "CalendarItemType: The Calendar Item Type of the Meeting." }
        @{ Name = "RecurrencePattern"; Width = 20; Align = "Left"; Comment = "RecurrencePattern: The Recurrence Pattern of the Meeting." }
        @{ Name = "AppointmentAuxiliaryFlags"; Width = 30; Align = "Center"; Comment = "AppointmentAuxiliaryFlags: The Appointment Auxiliary Flags of the Meeting." }
        @{ Name = "DisplayAttendeesAll"; Width = 30; Align = "Left"; Comment = "DisplayAttendeesAll: List of the Attendees of the Meeting." }
        @{ Name = "AttendeeCount"; Width = 10; Align = "Center"; Comment = "AttendeeCount: The Attendee Count." }
        @{ Name = "AppointmentState"; Width = 20; Align = "Left"; Comment = "AppointmentState: The Appointment State of the Meeting." }
        @{ Name = "ResponseType"; Width = 10; Align = "Center"; Comment = "ResponseType: The Response Type of the Meeting." }
        @{ Name = "ClientIntent"; Width = 20; Align = "Center"; Comment = "ClientIntent: The Client Intent of the Meeting." }
        @{ Name = "AppointmentRecurring"; Width = 10; Align = "Center"; Comment = "AppointmentRecurring: Is this a Recurring Meeting?" }
        @{ Name = "HasAttachment"; Width = 10; Align = "Center"; Comment = "HasAttachment: Does this Meeting have an Attachment?" }
        @{ Name = "IsCancelled"; Width = 10; Align = "Center"; Comment = "IsCancelled: Is this Meeting Cancelled?" }
        @{ Name = "IsAllDayEvent"; Width = 10; Align = "Center"; Comment = "IsAllDayEvent: Is this an All Day Event?" }
        @{ Name = "Sensitivity"; Width = 12; Align = "Center"; Comment = "Sensitivity: The Sensitivity of the Meeting (Normal, Personal, Private, Confidential)." }
        @{ Name = "IsSeriesCancelled"; Width = 10; Align = "Center"; Comment = "IsSeriesCancelled: Is this a Series Cancelled Meeting?" }
        @{ Name = "SendMeetingMessagesDiagnostics"; Width = 30; Align = "Left"; Comment = "SendMeetingMessagesDiagnostics: Compound Property to describe why meeting was or was not sent to everyone." }
        @{ Name = "AttendeeCollection"; Width = 50; Align = "Left"; Comment = "AttendeeCollection: The Attendee Collection of the Meeting, use -TrackingLogs to get values." }
        @{ Name = "CalendarLogRequestId"; Width = 40; Align = "Center"; Comment = "CalendarLogRequestId: The Calendar Log Request ID of the Meeting." }
        @{ Name = "CleanGlobalObjectId"; Width = 40; Align = "Left"; Comment = "CleanGlobalObjectId: The MeetingID / Clean Global Object ID of the Meeting." }
    )

    foreach ($meta in $headerMeta) {
        $colLetter = $ColumnMap[$meta.Name]
        if ($null -eq $colLetter) { continue }
        $colIdx = [int][char]$colLetter[0] - [int][char]'A' + 1
        # Handle double-letter columns (e.g., "AB", "AM", etc.)
        if ($colLetter.Length -gt 1) {
            $colIdx = 0
            foreach ($c in $colLetter.ToCharArray()) {
                $colIdx = $colIdx * 26 + ([int][char]$c - [int][char]'A' + 1)
            }
        }
        $col = $sheet.Column($colIdx)
        $params = @{ Width = $meta.Width; HorizontalAlignment = $meta.Align }
        if ($meta.ContainsKey("NumberFormat")) { $params.NumberFormat = $meta.NumberFormat }
        $col | Set-ExcelRange @params
        Set-CellComment -Text $meta.Comment -Row $HeaderRow -ColumnNumber $colIdx -Worksheet $sheet
    }

    # Title Row
    $sheet.Row(1) | Set-ExcelRange -HorizontalAlignment Left
    Set-CellComment -Text "For more information see: https://aka.ms/AnalyzeCalLogs"  -Row 1 -ColumnNumber 1  -Worksheet $sheet

    # Set the Header row to be bold and left aligned
    $sheet.Row($HeaderRow) | Set-ExcelRange -Bold -HorizontalAlignment Left
}

<#
.SYNOPSIS
Cross-user post-pass that recolors any Attendee whose mailbox is also represented by a
Delegate-of-Attendee in the same workbook. Called once after all per-user worksheets
have been written.

Light Purple is applied to the Attendee tabs/tables when a Delegate-of-Attendee was
identified among the analyzed identities and their DelegateForSmtp matches the
Attendee's Identity. Delegate-of-Organizer cases are NOT affected; the Organizer keeps
their orange coloring.
#>
function Update-AttendeeTabsForDelegates {
    if ($null -eq $script:UserRoles -or $script:UserRoles.Count -eq 0) {
        return
    }
    if ([string]::IsNullOrEmpty($script:FileName) -or -not (Test-Path -LiteralPath $script:FileName)) {
        return
    }

    # Build the set of attendee SMTPs that have a Delegate among the analyzed users.
    $attendeesWithDelegate = @{}
    foreach ($entry in $script:UserRoles.Values) {
        if ($entry.IsDelegateOfAttendee -and -not [string]::IsNullOrEmpty($entry.DelegateForSmtp)) {
            $key = $entry.DelegateForSmtp.Trim().ToLowerInvariant()
            $attendeesWithDelegate[$key] = $true
        }
    }

    if ($attendeesWithDelegate.Count -eq 0) {
        return
    }

    # Find the matching Attendee identities in $script:UserRoles (pure Attendees only).
    $targets = @()
    foreach ($entry in $script:UserRoles.Values) {
        if ($entry.IsOrganizer -or $entry.IsRoomMB -or
            $entry.IsDelegateOfOrganizer -or $entry.IsDelegateOfAttendee) {
            continue
        }
        $key = ([string]$entry.Identity).Trim().ToLowerInvariant()
        if ($attendeesWithDelegate.ContainsKey($key)) {
            $targets += $entry
        }
    }

    if ($targets.Count -eq 0) {
        Write-Verbose "Update-AttendeeTabsForDelegates: No Attendee tabs needed recoloring."
        return
    }

    $lightPurple = [System.Drawing.Color]::FromArgb(218, 191, 246)
    $savedEAP = $ErrorActionPreference
    $pkg = $null

    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $pkg = Open-ExcelPackage -Path $script:FileName -ErrorAction Stop

        foreach ($target in $targets) {
            $shortId = $target.ShortId
            if ([string]::IsNullOrEmpty($shortId)) { continue }

            # Worksheet names follow Get-FileName / Export-CalLog conventions.
            foreach ($sheetName in @($shortId, ($shortId + "_TimeLine"))) {
                $ws = $pkg.Workbook.Worksheets[$sheetName]
                if ($null -eq $ws) { continue }

                $ws.TabColor = $lightPurple

                # If the sheet has a single table (Enhanced CalLogs), switch its style to a
                # purple-family style so the table coloring matches the tab.
                try {
                    if ($null -ne $ws.Tables -and $ws.Tables.Count -gt 0) {
                        $ws.Tables[0].StyleName = "Light14"
                    }
                } catch {
                    Write-Verbose "Update-AttendeeTabsForDelegates: Unable to set table style on [$sheetName]: $_"
                }
            }

            Write-Host -ForegroundColor Magenta "Recolored Attendee tab for [$($target.Identity)] (Light Purple) because a Delegate was analyzed."
            $script:UserRoles[$target.Identity].HasDelegate = $true
        }

        $pkg.Save()
    } catch {
        Write-Warning "Update-AttendeeTabsForDelegates: Unable to recolor Attendee tabs: $_"
    } finally {
        if ($null -ne $pkg) { $pkg.Dispose() }
        $ErrorActionPreference = $savedEAP
    }
}
