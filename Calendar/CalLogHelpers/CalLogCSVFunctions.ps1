# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# Constants to support the script
# ===================================================================================================
# Non-US date formats for TryParseExact fallback (constant, created once)
[string[]]$script:DateFormats = @(
    "d/M/yyyy h:mm:ss tt",
    "d/M/yyyy H:mm:ss",
    "d/M/yyyy H:mm",
    "d/M/yyyy h:mm tt",
    "dd/MM/yyyy h:mm:ss tt",
    "dd/MM/yyyy H:mm:ss",
    "dd/MM/yyyy HH:mm:ss",
    "dd/MM/yyyy H:mm",
    "dd/MM/yyyy h:mm tt",
    "d/M/yyyy",
    "dd/MM/yyyy"
)

$script:CalendarItemTypes = @{
    'IPM.Schedule.Meeting.Request.AttendeeListReplication' = "AttendeeList"
    'IPM.Schedule.Meeting.Canceled'                        = "Cancellation"
    'IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}' = "Exception"
    'IPM.Schedule.Meeting.Notification.Forward'            = "Forward.Notification"
    'IPM.Appointment'                                      = "Ipm.Appointment"
    'IPM.Appointment.Occurrence'                           = "Exception.Occurrence"
    'IPM.Schedule.Meeting.Request'                         = "Meeting.Request"
    'IPM.CalendarSharing.EventUpdate'                      = "SharingCFM"
    'IPM.CalendarSharing.EventDelete'                      = "SharingDelete"
    'IPM.Schedule.Meeting.Resp'                            = "Resp.Any"
    'IPM.Schedule.Meeting.Resp.Neg'                        = "Resp.Neg"
    'IPM.Schedule.Meeting.Resp.Tent'                       = "Resp.Tent"
    'IPM.Schedule.Meeting.Resp.Pos'                        = "Resp.Pos"
    '(Occurrence Deleted)'                                 = "Exception.Deleted"
}

<#
.SYNOPSIS
Resolves the ItemClass to a friendly type name using the CalendarItemTypes table.
If no exact match is found, progressively strips the last dot-segment and retries.
e.g. IPM.Schedule.Meeting.Resp.Tent.Follow → IPM.Schedule.Meeting.Resp.Tent → "Resp.Tent"
#>
function GetItemType {
    param([string]$ItemClass)
    $lookup = $ItemClass
    while (-not [string]::IsNullOrEmpty($lookup)) {
        $type = $script:CalendarItemTypes[$lookup]
        if (-not [string]::IsNullOrEmpty($type)) {
            return $type
        }
        # Strip the last segment and try the parent
        $lastDot = $lookup.LastIndexOf('.')
        if ($lastDot -le 0) { break }
        $lookup = $lookup.Substring(0, $lastDot)
    }
    return $null
}

function IsExceptionItemType {
    param(
        [string]$ItemType
    )

    return (-not [string]::IsNullOrEmpty($ItemType)) -and ($ItemType -like 'Exception*')
}

function IsExceptionLog {
    param(
        $CalLog
    )

    if ($null -eq $CalLog) {
        return $false
    }

    if ($CalLog.IsException -eq $true) {
        return $true
    }

    if ($null -ne $CalLog.CalendarItemType -and ([string]$CalLog.CalendarItemType) -like 'Exception*') {
        return $true
    }

    return IsExceptionItemType (GetItemType $CalLog.ItemClass)
}

function Get-CalendarLogNumericSortValue {
    param(
        $Value
    )

    if ($null -eq $Value) {
        return -1
    }

    $textValue = [string]$Value
    if ([string]::IsNullOrEmpty($textValue) -or $textValue -eq 'NotFound' -or $textValue -eq '-') {
        return -1
    }

    $numericValue = 0
    if ([int]::TryParse($textValue, [ref]$numericValue)) {
        return $numericValue
    }

    return [int]::MaxValue
}

function Get-CalendarLogOriginalStartDateSortRank {
    param(
        $Value
    )

    if ($null -eq $Value) {
        return 0
    }

    $textValue = [string]$Value
    if ([string]::IsNullOrEmpty($textValue) -or $textValue -eq 'NotFound') {
        return 0
    }

    return 1
}

function Get-CalendarLogOriginalStartDateSortValue {
    param(
        $Value
    )

    if ((Get-CalendarLogOriginalStartDateSortRank $Value) -eq 0) {
        return [datetime]::MinValue
    }

    $parsedValue = ConvertDateTimeSilent $Value
    if ($parsedValue -is [datetime]) {
        return $parsedValue
    }

    return [datetime]::MinValue
}

function ConvertValueToString {
    param(
        $Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return [string]$Value
}

function ConvertDateTimeSilent {
    param(
        $Value
    )

    if ($Value -is [datetime]) {
        return $Value
    }

    $textValue = [string]$Value
    if ([string]::IsNullOrEmpty($textValue) -or $textValue -eq 'N/A' -or $textValue -eq 'NotFound') {
        return [datetime]::MinValue
    }

    $InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
    $DateStyles = [System.Globalization.DateTimeStyles]::None
    $Parsed = [DateTime]::MinValue

    if ([DateTime]::TryParse($textValue, $InvariantCulture, $DateStyles, [ref]$Parsed)) {
        return $Parsed
    }

    if ([DateTime]::TryParseExact($textValue, $script:DateFormats, $InvariantCulture, $DateStyles, [ref]$Parsed)) {
        return $Parsed
    }

    if ([DateTime]::TryParse($textValue, [ref]$Parsed)) {
        return $Parsed
    }

    return [datetime]::MinValue
}

function Get-CalendarLogTimestampSortValue {
    param(
        $Value
    )

    $parsedValue = ConvertDateTimeSilent $Value
    if ($parsedValue -is [datetime]) {
        return $parsedValue
    }

    return [datetime]::MinValue
}

function Get-CalendarLogDateBucketSortValue {
    param(
        $Value
    )

    $timestamp = Get-CalendarLogTimestampSortValue $Value
    if ($timestamp -eq [datetime]::MinValue) {
        return [datetime]::MinValue
    }

    return $timestamp.Date
}

function Get-CalendarLogTimestampGroupKey {
    param(
        $Value
    )

    $timestamp = Get-CalendarLogTimestampSortValue $Value
    if ($timestamp -eq [datetime]::MinValue) {
        return 'Unknown'
    }

    return $timestamp.ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-SortCheckFailureDetails {
    param(
        [datetime]$PreviousTimestamp,
        [datetime]$CurrentTimestamp,
        [int]$PreviousIndex,
        [int]$CurrentIndex,
        $PreviousEntry,
        $CurrentEntry,
        [string]$ValuePropertyName
    )

    $previousValue = if ($null -ne $PreviousEntry -and -not [string]::IsNullOrEmpty($ValuePropertyName)) { [string]$PreviousEntry.$ValuePropertyName } else { '' }
    $currentValue = if ($null -ne $CurrentEntry -and -not [string]::IsNullOrEmpty($ValuePropertyName)) { [string]$CurrentEntry.$ValuePropertyName } else { '' }
    return "previous[$PreviousIndex]=$PreviousTimestamp raw=[$previousValue]; current[$CurrentIndex]=$CurrentTimestamp raw=[$currentValue]"
}

function Test-LogTimestampOrder {
    param(
        [array]$Entries,
        [string]$Name,
        [string]$ValuePropertyName
    )

    $previousTimestamp = $null
    $previousEntry = $null
    $previousIndex = -1
    $parsedCount = 0
    $skippedCount = 0
    $totalCount = @($Entries).Count

    for ($index = 0; $index -lt @($Entries).Count; $index++) {
        $entry = $Entries[$index]
        if ($null -eq $entry) {
            $skippedCount++
            continue
        }

        $timestamp = Get-CalendarLogTimestampSortValue $entry.$ValuePropertyName
        if ($timestamp -eq [datetime]::MinValue) {
            $skippedCount++
            continue
        }

        $parsedCount++
        if ($null -ne $previousTimestamp -and $previousTimestamp -gt $timestamp) {
            $details = Get-SortCheckFailureDetails -PreviousTimestamp $previousTimestamp -CurrentTimestamp $timestamp -PreviousIndex $previousIndex -CurrentIndex $index -PreviousEntry $previousEntry -CurrentEntry $entry -ValuePropertyName $ValuePropertyName
            Write-Verbose "$Name is not sorted correctly. $details"
            return $false
        }

        $previousTimestamp = $timestamp
        $previousEntry = $entry
        $previousIndex = $index
    }

    $suffix = if ($skippedCount -gt 0) { " Skipped [$skippedCount] row(s) with blank or non-date timestamps." } else { '' }
    Write-Verbose "$Name looks to be sorted correctly. Total rows [$totalCount]. Checked [$parsedCount] timestamped row(s).$suffix"
    return $true
}

function Write-UnknownTimestampDiagnostics {
    param(
        [array]$Entries,
        [string]$Name,
        [string]$ValuePropertyName,
        [int]$MaxItems = 20
    )

    $unknownEntries = [System.Collections.Generic.List[object]]::new()

    for ($index = 0; $index -lt @($Entries).Count; $index++) {
        $entry = $Entries[$index]

        if ($null -eq $entry) {
            [void]$unknownEntries.Add([PSCustomObject]@{
                    Index                = $index
                    Reason               = 'Null entry'
                    RawValue             = ''
                    LogRowType           = ''
                    TriggerAction        = ''
                    ItemClass            = ''
                    CalendarLogRequestId = ''
                    OriginalStartDate    = ''
                })
            continue
        }

        $timestamp = Get-CalendarLogTimestampSortValue $entry.$ValuePropertyName
        if ($timestamp -eq [datetime]::MinValue) {
            [void]$unknownEntries.Add([PSCustomObject]@{
                    Index                = $index
                    Reason               = 'Timestamp resolved to DateTime.MinValue'
                    RawValue             = [string]$entry.$ValuePropertyName
                    LogRowType           = [string]$entry.LogRowType
                    TriggerAction        = [string]$entry.TriggerAction
                    ItemClass            = [string]$entry.ItemClass
                    CalendarLogRequestId = [string]$entry.CalendarLogRequestId
                    OriginalStartDate    = [string]$entry.OriginalStartDate
                })
        }
    }

    if ($unknownEntries.Count -eq 0) {
        Write-Verbose "$Name has no Unknown LogTimestamp rows."
        return
    }

    Write-Verbose "$Name has [$($unknownEntries.Count)] Unknown LogTimestamp row(s) out of [$(@($Entries).Count)] total row(s)."
    foreach ($unknownEntry in ($unknownEntries | Select-Object -First $MaxItems)) {
        Write-Verbose ("  Index [{0}] Reason [{1}] Raw [{2}] LogRowType [{3}] TriggerAction [{4}] ItemClass [{5}] OriginalStartDate [{6}] CalendarLogRequestId [{7}]" -f $unknownEntry.Index, $unknownEntry.Reason, $unknownEntry.RawValue, $unknownEntry.LogRowType, $unknownEntry.TriggerAction, $unknownEntry.ItemClass, $unknownEntry.OriginalStartDate, $unknownEntry.CalendarLogRequestId)
    }

    if ($unknownEntries.Count -gt $MaxItems) {
        Write-Verbose "  ... truncated after [$MaxItems] Unknown rows."
    }
}

function SortCalendarDiagnosticObjectsByTimestamp {
    param(
        [array]$CalLogs
    )

    if ($null -eq $CalLogs -or $CalLogs.Count -le 1) {
        return @($CalLogs)
    }

    return @($CalLogs | Sort-Object @{ Expression = { Get-CalendarLogTimestampSortValue $_.LogTimestamp } })
}

function SortEnhancedCalendarLogsByTimestamp {
    param(
        [array]$CalLogs
    )

    if ($null -eq $CalLogs -or $CalLogs.Count -le 1) {
        return @($CalLogs)
    }

    return @($CalLogs | Sort-Object @{ Expression = { Get-CalendarLogTimestampSortValue $_.LogTimestamp } })
}

function SortCalendarDiagnosticObjects {
    param(
        [array]$CalLogs
    )

    if ($null -eq $CalLogs -or $CalLogs.Count -le 1) {
        return @($CalLogs)
    }

    try {
        return @($CalLogs | Sort-Object
            @{ Expression = { Get-CalendarLogTimestampSortValue $_.LogTimestamp } },
            @{ Expression = { Get-CalendarLogOriginalStartDateSortRank $_.OriginalStartDate } },
            @{ Expression = { Get-CalendarLogOriginalStartDateSortValue $_.OriginalStartDate } })
    } catch {
        Write-Warning "Secondary raw log sort failed; falling back to LogTimestamp-only sorting. $_"
        return SortCalendarDiagnosticObjectsByTimestamp -CalLogs $CalLogs
    }
}

function SortEnhancedCalendarLogs {
    param(
        [array]$CalLogs
    )

    if ($null -eq $CalLogs -or $CalLogs.Count -le 1) {
        return @($CalLogs)
    }

    try {
        # The Enhanced tab is the only output that gets re-ordered.
        # Sort by LogTimestamp first, then use OriginalStartDate only as a tie-breaker for matching timestamps.
        # Rows with unknown LogTimestamp values are preserved and appended to the end.
        $workingLogs = @($CalLogs | Where-Object { $null -ne $_ })
        $removedNullCount = $CalLogs.Count - $workingLogs.Count
        if ($removedNullCount -gt 0) {
            Write-Verbose "Removed [$removedNullCount] null enhanced log row(s) before sorting."
        }

        Write-Verbose "Starting Sorting Date"
        Write-Verbose "Sorting Enhanced logs by LogTimestamp, then OriginalStartDate for matching timestamps."

        $sortIndex = 0
        $sortRows = foreach ($workingLog in $workingLogs) {
            $sortIndex++
            [PSCustomObject]@{
                SortIndex              = $sortIndex
                TimestampValue         = Get-CalendarLogTimestampSortValue $workingLog.LogTimestamp
                OriginalStartDateRank  = Get-CalendarLogOriginalStartDateSortRank $workingLog.OriginalStartDate
                OriginalStartDateValue = Get-CalendarLogOriginalStartDateSortValue $workingLog.OriginalStartDate
                Log                    = $workingLog
            }
        }

        $knownTimestampRows = @($sortRows | Where-Object { $_.TimestampValue -ne [datetime]::MinValue } | Sort-Object TimestampValue, OriginalStartDateRank, OriginalStartDateValue, SortIndex)
        $unknownTimestampRows = @($sortRows | Where-Object { $_.TimestampValue -eq [datetime]::MinValue } | Sort-Object SortIndex)

        if ($unknownTimestampRows.Count -gt 0) {
            Write-Verbose "Keeping [$($unknownTimestampRows.Count)] Unknown LogTimestamp row(s) at the end of the Enhanced output."
        }

        $sortedLogs = @($knownTimestampRows | ForEach-Object { $_.Log }) + @($unknownTimestampRows | ForEach-Object { $_.Log })

        Write-Verbose "Validating Enhanced list order before sub filtering..."
        [void](Test-LogTimestampOrder -Entries $sortedLogs -Name 'Enhanced Tab' -ValuePropertyName 'LogTimestamp')
        Write-UnknownTimestampDiagnostics -Entries $sortedLogs -Name 'Enhanced Tab' -ValuePropertyName 'LogTimestamp'

        return @($sortedLogs)
    } catch {
        Write-Warning "Secondary enhanced log sort failed; falling back to LogTimestamp-only sorting. $_"
        return SortEnhancedCalendarLogsByTimestamp -CalLogs $CalLogs
    }
}

# ===================================================================================================
# Functions to support the script
# ===================================================================================================

<#
.SYNOPSIS
Looks to see if there is a Mapping of ExternalMasterID to FolderName
#>
function MapSharedFolder {
    param(
        $ExternalMasterID
    )
    if ($null -eq $ExternalMasterID -or [string]::IsNullOrEmpty([string]$ExternalMasterID) -or $ExternalMasterID -eq "NotFound") {
        return "Not Shared"
    }

    if ($null -eq $script:SharedFolders -or -not $script:SharedFolders.ContainsKey($ExternalMasterID)) {
        return "UnknownSharedCalendarCopy"
    }

    return $script:SharedFolders[$ExternalMasterID]
}

<#
.SYNOPSIS
Replaces a value of NotFound with a blank string.
#>
function ReplaceNotFound {
    param (
        $Value
    )
    if ($Value -eq "NotFound") {
        return ""
    } else {
        return $Value
    }
}

<#
.SYNOPSIS
Creates a Mapping of ExternalMasterID to FolderName
#>
function CreateExternalMasterIDMap {
    # This function will create a Map of the log folder to ExternalMasterID
    $script:SharedFolders = [System.Collections.SortedList]::new()
    $unknownCount = 0
    Write-Verbose "Starting CreateExternalMasterIDMap"

    foreach ($ExternalID in $script:GCDO.ExternalSharingMasterId | Select-Object -Unique) {
        if ($ExternalID -eq "NotFound") {
            continue
        }

        $AllFolderNames = @($script:GCDO | Where-Object { $_.ExternalSharingMasterId -eq $ExternalID } | Select-Object -ExpandProperty OriginalParentDisplayName | Select-Object -Unique)

        # Default calendar folder names across the top localized versions of Exchange
        # cSpell:ignore Kalender Calendario Calendrier Calendário Календарь
        $DefaultCalendarNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [void]$DefaultCalendarNames.Add('Calendar')       # English
        [void]$DefaultCalendarNames.Add('Kalender')        # German, Dutch, Swedish, Norwegian, Danish
        [void]$DefaultCalendarNames.Add('Calendario')      # Spanish, Italian
        [void]$DefaultCalendarNames.Add('Calendrier')      # French
        [void]$DefaultCalendarNames.Add('Calendário')     # Portuguese
        [void]$DefaultCalendarNames.Add('Календарь')      # Russian

        # Remove empty/null entries
        $AllFolderNames = @($AllFolderNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        if ($AllFolderNames.count -gt 1) {
            # We have 2+ FolderNames, remove default calendar folder names (localized) by exact match
            $Filtered = $AllFolderNames | Where-Object { -not $DefaultCalendarNames.Contains($_) }
            if ($Filtered.Count -gt 0) {
                $AllFolderNames = @($Filtered)
            }
            # else keep the original list — all entries were default calendar names
        }

        if ($AllFolderNames.Count -eq 0) {
            $unknownCount++
            $script:SharedFolders[$ExternalID] = "UnknownSharedCalendarCopy$unknownCount"
            Write-Host -ForegroundColor red "Found Zero folder names to map to for ExternalID [$ExternalID]."
        } elseif ($AllFolderNames.Count -eq 1) {
            $script:SharedFolders[$ExternalID] = $AllFolderNames[0]
            Write-Verbose "Found map: [$($AllFolderNames[0])] is for $ExternalID"
        } else {
            # we still have multiple possible Folder Names, need to chose one or combine
            Write-Host -ForegroundColor Red "Unable to Get Exact Folder for $ExternalID"
            Write-Host -ForegroundColor Red "Found $($AllFolderNames.count) possible folders: $($AllFolderNames -join ', ')"

            if ($AllFolderNames.Count -eq 2) {
                $script:SharedFolders[$ExternalID] = $AllFolderNames[0] + " + " + $AllFolderNames[1]
            } else {
                $unknownCount++
                $script:SharedFolders[$ExternalID] = "UnknownSharedCalendarCopy$unknownCount"
            }
        }
    }

    Write-Host -ForegroundColor Green "Created the following Shared Calendar Mapping:"
    foreach ($Key in $script:SharedFolders.Keys) {
        Write-Host -ForegroundColor Green "$Key : $($script:SharedFolders[$Key])"
    }
    Write-Verbose "Created the following Mapping :"
    Write-Verbose $script:SharedFolders
}

<#
.SYNOPSIS
Convert a csv value to multiLine.
#>
function MultiLineFormat {
    param(
        $PassedString
    )
    $PassedString = $PassedString -replace "},", "},`n"
    return $PassedString.Trim()
}

# ===================================================================================================
# Build CSV to output
# ===================================================================================================

<#
.SYNOPSIS
Builds the CSV output from the Calendar Diagnostic Objects
#>
function BuildCSV {

    Write-Host "Starting to Process Calendar Logs..."
    # De-duplicate while preserving the original collection order for RAW output.
    $rawNullCount = @($script:GCDO).Count - @($script:GCDO | Where-Object { $null -ne $_ }).Count
    if ($rawNullCount -gt 0) {
        Write-Host -ForegroundColor Yellow "Removed [$rawNullCount] null raw calendar log row(s) before processing."
    }
    $dedupedCalLogs = New-Object 'System.Collections.Generic.List[object]'
    $seenCalLogKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    $duplicateCount = 0
    foreach ($calLog in @($script:GCDO | Where-Object { $null -ne $_ })) {
        $calLogKey = Get-CalendarDiagnosticObjectDeduplicationKey -CalLog $calLog
        if ($seenCalLogKeys.Add($calLogKey)) {
            [void]$dedupedCalLogs.Add($calLog)
        } else {
            $duplicateCount++
        }
    }
    if ($duplicateCount -gt 0) {
        Write-Host -ForegroundColor Yellow "Removed [$duplicateCount] duplicate Calendar Log entries before processing."
    }
    $script:GCDO = $dedupedCalLogs.ToArray()
    $script:MailboxList = @{}
    # Initialize lookup caches to avoid redundant CN resolution across hundreds of log entries
    $script:SMTPAddressCache = @{}
    $script:DisplayNameCache = @{}
    Write-Host "Creating Map of Mailboxes to CNs..."
    CreateExternalMasterIDMap
    ConvertCNtoSMTP
    FixCalendarItemType($script:GCDO)

    Write-Host "Making Calendar Logs more readable..."
    [void](Test-LogTimestampOrder -Entries $script:GCDO -Name 'RAW Tab before sorting' -ValuePropertyName 'LogTimestamp')
    Write-UnknownTimestampDiagnostics -Entries $script:GCDO -Name 'RAW Tab before sorting' -ValuePropertyName 'LogTimestamp'
    $Index = 0
    $GCDOResults = foreach ($CalLog in $script:GCDO) {
        $Index++
        $ItemType = GetItemType $CalLog.ItemClass

        # CleanNotFounds
        $PropsToClean = "FreeBusyStatus", "ClientIntent", "AppointmentSequenceNumber", "AppointmentLastSequenceNumber", "RecurrencePattern", "AppointmentAuxiliaryFlags", "EventEmailReminderTimer", "IsSeriesCancelled", "AppointmentCounterProposal", "MeetingRequestType", "SendMeetingMessagesDiagnostics", "AttendeeCollection"
        foreach ($Prop in $PropsToClean) {
            # Exception objects, etc. don't have these properties.
            if ($null -ne $CalLog.$Prop) {
                $CalLog.$Prop = ReplaceNotFound($CalLog.$Prop)
            }
        }

        # Output one row (collected by the foreach assignment)
        [PSCustomObject]@{
            #'LogRow'                         = $Index
            'LogTimestamp'                   = ConvertDateTime($CalLog.LogTimestamp)
            'LogRowType'                     = ConvertValueToString($CalLog.LogRowType)
            'SubjectProperty'                = $CalLog.SubjectProperty
            'Client'                         = $CalLog.ShortClientInfoString
            'LogClientInfoString'            = $CalLog.LogClientInfoString
            'TriggerAction'                  = $CalLog.CalendarLogTriggerAction
            'ItemClass'                      = $ItemType
            'Seq:Exp:ItemVersion'            = CompressVersionInfo($CalLog)
            'Organizer'                      = GetDisplayName($CalLog.From)
            'From'                           = GetSMTPAddress($CalLog.From)
            'FreeBusy'                       = ConvertValueToString($CalLog.FreeBusyStatus)
            'ResponsibleUser'                = GetSMTPAddress($CalLog.ResponsibleUserName)
            'Sender'                         = GetSMTPAddress($CalLog.Sender)
            'LogFolder'                      = $CalLog.ParentDisplayName
            'OriginalLogFolder'              = $CalLog.OriginalParentDisplayName
            'SharedFolderName'               = MapSharedFolder($CalLog.ExternalSharingMasterId)
            'ReceivedRepresenting'           = GetSMTPAddress($CalLog.ReceivedRepresenting)
            'MeetingRequestType'             = ConvertValueToString($CalLog.MeetingRequestType)
            'StartTime'                      = ConvertDateTime($CalLog.StartTime)
            'EndTime'                        = ConvertDateTime($CalLog.EndTime)
            'OriginalStartDate'              = ConvertDateTime($CalLog.OriginalStartDate)
            'Location'                       = $CalLog.Location
            'CalendarItemType'               = ConvertValueToString($CalLog.CalendarItemType)
            'RecurrencePattern'              = $CalLog.RecurrencePattern
            'AppointmentAuxiliaryFlags'      = ConvertValueToString($CalLog.AppointmentAuxiliaryFlags)
            'DisplayAttendeesAll'            = $(if ($CalLog.DisplayAttendeesAll -eq "NotFound") { "-" } else { $CalLog.DisplayAttendeesAll })
            'AttendeeCount'                  = GetAttendeeCount($CalLog.DisplayAttendeesAll)
            'AppointmentState'               = ConvertValueToString($CalLog.AppointmentState)
            'ResponseType'                   = ConvertValueToString($CalLog.ResponseType)
            'ClientIntent'                   = ConvertValueToString($CalLog.ClientIntent)
            'AppointmentRecurring'           = $CalLog.AppointmentRecurring
            'HasAttachment'                  = $CalLog.HasAttachment
            'IsCancelled'                    = $CalLog.IsCancelled
            'IsAllDayEvent'                  = $CalLog.IsAllDayEvent
            'Sensitivity'                    = $CalLog.Sensitivity
            'IsSeriesCancelled'              = $CalLog.IsSeriesCancelled
            'SendMeetingMessagesDiagnostics' = $CalLog.SendMeetingMessagesDiagnostics
            'AttendeeCollection'             = MultiLineFormat($CalLog.AttendeeCollection)
            'CalendarLogRequestId'           = ConvertValueToString($CalLog.CalendarLogRequestId)    # Move to front.../ Format in groups???
            'CleanGlobalObjectId'            = $CalLog.CleanGlobalObjectId
        }
    }
    [void](Test-LogTimestampOrder -Entries $GCDOResults -Name 'Enhanced Tab before sorting' -ValuePropertyName 'LogTimestamp')
    Write-UnknownTimestampDiagnostics -Entries $GCDOResults -Name 'Enhanced Tab before sorting' -ValuePropertyName 'LogTimestamp'
    # Keep RAW output in collected order; only the Enhanced projection is re-sorted for display and Timeline generation.
    $script:EnhancedCalLogs = SortEnhancedCalendarLogs -CalLogs $GCDOResults
    [void](Test-LogTimestampOrder -Entries $script:GCDO -Name 'RAW Tab' -ValuePropertyName 'LogTimestamp')

    Write-Host -ForegroundColor Green "Calendar Logs have been processed, Exporting logs to file..."
    BuildOrganizerUserNameMap

    # Resolve $script:ShortId / $script:FileName for this user before role classification so
    # the cross-user post-pass can find the correct worksheet by ShortId.
    Get-FileName

    # Refine the user's role now that SMTP-resolved Enhanced logs are available. SetIsOrganizer
    # is re-evaluated here so that the user-identity / From check can be performed against the
    # resolved SMTPs, and Delegate-of-Organizer / Delegate-of-Attendee are classified.
    Set-UserRoleClassification

    Export-CalLog
}

<#
.SYNOPSIS
Re-evaluates IsOrganizer with the resolved SMTPs and assigns the Delegate role for the
current user using $script:EnhancedCalLogs. Also records the per-user role into
$script:UserRoles so a final cross-user pass can color the Attendee tabs that have a
Delegate among the analyzed identities.
#>
function Set-UserRoleClassification {
    # Re-run IsOrganizer now that MailboxList is populated so the From check is accurate.
    $script:IsOrganizer = (SetIsOrganizer -CalLogs $script:GCDO -Identity $script:Identity)

    # Re-compute IsRoomMB so all paths (MeetingID + Subject) produce consistent classification.
    $script:IsRoomMB = (SetIsRoom -CalLogs $script:GCDO)

    # Determine the Delegate role (only set when not already Organizer / Room).
    SetDelegateRole -EnhancedCalLogs $script:EnhancedCalLogs -Identity $script:Identity

    # Record the role for the cross-user "Attendee with Delegate" post-pass.
    if ($null -eq $script:UserRoles) {
        $script:UserRoles = [ordered]@{}
    }

    $script:UserRoles[$script:Identity] = [PSCustomObject]@{
        Identity              = $script:Identity
        ShortId               = $script:ShortId
        IsOrganizer           = [bool]$script:IsOrganizer
        IsRoomMB              = [bool]$script:IsRoomMB
        IsDelegateOfOrganizer = [bool]$script:IsDelegateOfOrganizer
        IsDelegateOfAttendee  = [bool]$script:IsDelegateOfAttendee
        DelegateForSmtp       = $script:DelegateForSmtp
        HasDelegate           = $false
    }
}

<#
.SYNOPSIS
    Builds a set of all known identifiers (display names and email addresses) for the Organizer.
    This allows change-detection code to treat different representations of the same person as equal.
    Sources: From, Sender, ReceivedBy, ReceivedRepresenting, and AttendeeListDetails from raw CalLogs.
#>
function BuildOrganizerUserNameMap {
    $script:OrganizerIdentities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Seed with the enhanced Organizer display name and From SMTP from the first qualifying log
    $firstOrgLog = $script:EnhancedCalLogs | Where-Object {
        ($_.ItemClass -eq 'Ipm.Appointment' -or $_.ItemClass -like 'Exception*') -and
        $_.SharedFolderName -eq 'Not Shared'
    } | Select-Object -First 1

    if ($null -ne $firstOrgLog) {
        if (-not [string]::IsNullOrEmpty($firstOrgLog.From) -and $firstOrgLog.From -ne '-') {
            [void]$script:OrganizerIdentities.Add($firstOrgLog.From.Trim())
        }
        if (-not [string]::IsNullOrEmpty($firstOrgLog.Organizer) -and $firstOrgLog.Organizer -ne '-') {
            [void]$script:OrganizerIdentities.Add($firstOrgLog.Organizer.Trim())
        }
    }

    # Walk raw CalLogs for additional representations on qualifying rows
    foreach ($CalLog in $script:GCDO) {
        if ($null -eq $CalLog.ItemClass -or
            ((GetItemType $CalLog.ItemClass) -ne 'Ipm.Appointment' -and -not (IsExceptionItemType (GetItemType $CalLog.ItemClass)))) {
            continue
        }

        # From field — extract display name and email
        AddIdentitiesFromCNField $CalLog.From

        # ReceivedBy and ReceivedRepresenting — "Display Name" <email>
        AddIdentitiesFromCNField $CalLog.ReceivedBy
        AddIdentitiesFromCNField $CalLog.ReceivedRepresenting

        # AttendeeListDetails — JSON mapping; look for the organizer's entry by matching known identities
        if ($null -ne $CalLog.AttendeeListDetails -and -not [string]::IsNullOrEmpty([string]$CalLog.AttendeeListDetails) -and [string]$CalLog.AttendeeListDetails -ne 'NotFound') {
            try {
                $attendeeMap = $CalLog.AttendeeListDetails | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -ne $attendeeMap) {
                    foreach ($prop in $attendeeMap.PSObject.Properties) {
                        $email = $prop.Name
                        $displayName = $prop.Value.DisplayName
                        # Only add if we already know this email belongs to the organizer
                        if ($script:OrganizerIdentities.Contains($email)) {
                            if (-not [string]::IsNullOrEmpty($displayName)) {
                                [void]$script:OrganizerIdentities.Add($displayName.Trim())
                            }
                        }
                    }
                }
            } catch {
                Write-Verbose "BuildOrganizerUserNameMap: Unable to parse AttendeeListDetails: $_"
            }
        }
    }

    if ($script:OrganizerIdentities.Count -gt 0) {
        Write-Verbose "OrganizerIdentities map contains $($script:OrganizerIdentities.Count) entries:"
        foreach ($id in $script:OrganizerIdentities) { Write-Verbose "`t$id" }
    } else {
        Write-Verbose "OrganizerIdentities map is empty — organizer change detection may be less accurate."
    }
}

<#
.SYNOPSIS
    Extracts display name and email address from a CN-format field value and adds them to the organizer identity set.
#>
function AddIdentitiesFromCNField {
    param($FieldValue)

    if ($null -eq $FieldValue -or [string]::IsNullOrEmpty([string]$FieldValue) -or [string]$FieldValue -eq 'NotFound') {
        return
    }

    $text = [string]$FieldValue

    # Extract SMTP address from <email@domain.com> format
    $smtpMatch = [regex]::Match($text, '<([^>]+@[^>]+)>')
    if ($smtpMatch.Success) {
        [void]$script:OrganizerIdentities.Add($smtpMatch.Groups[1].Value.Trim())
    }

    # Extract display name — text before < or quoted text
    if ($text -match '<') {
        $displayPart = ($text -split '<')[0].Trim().Trim('"').Trim()
        if (-not [string]::IsNullOrEmpty($displayPart)) {
            [void]$script:OrganizerIdentities.Add($displayPart)
        }
    }

    # Also resolve via existing helpers — the resolved SMTP and display name
    $resolvedSmtp = GetSMTPAddress $FieldValue
    if (-not [string]::IsNullOrEmpty($resolvedSmtp) -and $resolvedSmtp -ne '-' -and $resolvedSmtp -ne 'NotFound') {
        [void]$script:OrganizerIdentities.Add($resolvedSmtp.Trim())
    }
    $resolvedDisplay = GetDisplayName $FieldValue
    if (-not [string]::IsNullOrEmpty($resolvedDisplay) -and $resolvedDisplay -ne '-' -and $resolvedDisplay -ne 'NotFound') {
        [void]$script:OrganizerIdentities.Add($resolvedDisplay.Trim())
    }
}

<#
.SYNOPSIS
    Returns $true if two organizer identity values refer to the same person,
    using the OrganizerIdentities map for case-insensitive lookup.
#>
function IsSameOrganizerIdentity {
    param(
        [string]$Value1,
        [string]$Value2
    )

    if ([string]::Equals($Value1, $Value2, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    if ($null -ne $script:OrganizerIdentities -and $script:OrganizerIdentities.Count -gt 0) {
        $v1Known = (-not [string]::IsNullOrEmpty($Value1)) -and $script:OrganizerIdentities.Contains($Value1.Trim())
        $v2Known = (-not [string]::IsNullOrEmpty($Value2)) -and $script:OrganizerIdentities.Contains($Value2.Trim())
        if ($v1Known -and $v2Known) {
            return $true
        }
    }

    return $false
}

function ConvertDateTime {
    param(
        [string] $DateTime
    )
    if ([string]::IsNullOrEmpty($DateTime) -or
        $DateTime -eq "N/A" -or
        $DateTime -eq "NotFound") {
        return ""
    }

    $InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
    $DateStyles = [System.Globalization.DateTimeStyles]::None
    $Parsed = [DateTime]::MinValue

    # Priority 1 & 2: InvariantCulture TryParse
    # Handles ISO 8601 and M/d/yyyy (the default EXO output format)
    if ([DateTime]::TryParse($DateTime, $InvariantCulture, $DateStyles, [ref]$Parsed)) {
        return $Parsed
    }

    # Priority 3: Explicit non-US formats via TryParseExact
    # Reached when day > 12 makes InvariantCulture fail (e.g., "22/07/2024")
    if ([DateTime]::TryParseExact($DateTime, $script:DateFormats, $InvariantCulture, $DateStyles, [ref]$Parsed)) {
        return $Parsed
    }

    # Priority 4: Current culture (last resort for unexpected formats)
    if ([DateTime]::TryParse($DateTime, [ref]$Parsed)) {
        return $Parsed
    }

    # Priority 5: Return MinValue so sorting is not broken by mixed types
    Write-Warning "Unable to parse date: [$DateTime]"
    return [DateTime]::MinValue
}

function GetAttendeeCount {
    param(
        [string] $AttendeesAll
    )
    if ($AttendeesAll -ne "NotFound") {
        return ($AttendeesAll -split ';').Count
    } else {
        return "-"
    }
}

<#
.SYNOPSIS
Corrects the CalenderItemType column
#>
function FixCalendarItemType {
    param(
        $CalLogs
    )
    foreach ($CalLog in $CalLogs) {
        if ($CalLog.OriginalStartDate -ne "NotFound" -and ![string]::IsNullOrEmpty($CalLog.OriginalStartDate)) {
            $CalLog.CalendarItemType = "Exception"
            $CalLog.isException = $true
        }
    }
}

function CompressVersionInfo {
    param(
        $CalLog
    )
    [string] $CompressedString = ""
    if ($CalLog.AppointmentSequenceNumber -eq "NotFound" -or [string]::IsNullOrEmpty($CalLog.AppointmentSequenceNumber)) {
        $CompressedString = "-:"
    } else {
        $CompressedString = $CalLog.AppointmentSequenceNumber.ToString() + ":"
    }
    if ($CalLog.AppointmentLastSequenceNumber -eq "NotFound" -or [string]::IsNullOrEmpty($CalLog.AppointmentLastSequenceNumber)) {
        $CompressedString += "-:"
    } else {
        $CompressedString += $CalLog.AppointmentLastSequenceNumber.ToString() + ":"
    }
    if ($CalLog.ItemVersion -eq "NotFound" -or [string]::IsNullOrEmpty($CalLog.ItemVersion)) {
        $CompressedString += "-"
    } else {
        $CompressedString += $CalLog.ItemVersion.ToString()
    }

    return $CompressedString
}
