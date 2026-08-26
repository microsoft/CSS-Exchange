# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Read-UInt16LE {
    param(
        [byte[]]$Bytes,
        [ref]$Offset
    )

    if (($Offset.Value + 2) -gt $Bytes.Length) {
        throw "Unexpected end of AppointmentRecurrenceBlob while reading UInt16 at offset [$($Offset.Value)]."
    }

    $value = [BitConverter]::ToUInt16($Bytes, $Offset.Value)
    $Offset.Value += 2
    return $value
}

function Read-UInt32LE {
    param(
        [byte[]]$Bytes,
        [ref]$Offset
    )

    if (($Offset.Value + 4) -gt $Bytes.Length) {
        throw "Unexpected end of AppointmentRecurrenceBlob while reading UInt32 at offset [$($Offset.Value)]."
    }

    $value = [BitConverter]::ToUInt32($Bytes, $Offset.Value)
    $Offset.Value += 4
    return $value
}

function Convert-RecurMinutesToDateTime {
    param(
        [UInt32]$Minutes
    )

    return ([datetime]'1601-01-01').AddMinutes([double]$Minutes)
}

function Get-RecurrencePatternSpecificSize {
    param(
        [UInt16]$PatternType
    )

    switch ($PatternType) {
        0 { return 0 }
        1 { return 4 }
        2 { return 4 }
        3 { return 8 }
        4 { return 4 }
        10 { return 4 }
        11 { return 8 }
        12 { return 4 }
        default {
            throw "Unsupported recurrence PatternType [$PatternType] in AppointmentRecurrenceBlob."
        }
    }
}

function Convert-AppointmentRecurrenceBlobToBytes {
    param(
        $AppointmentRecurrenceBlob
    )

    if ($AppointmentRecurrenceBlob -is [byte[]]) {
        return $AppointmentRecurrenceBlob
    }

    $blobText = [string]$AppointmentRecurrenceBlob
    if ([string]::IsNullOrWhiteSpace($blobText)) {
        throw "AppointmentRecurrenceBlob is empty."
    }

    $blobText = ($blobText -replace '\s+', '').Trim()
    if (($blobText.Length % 2) -ne 0) {
        throw "AppointmentRecurrenceBlob length is invalid. Expected an even-length hex string."
    }

    $bytes = [byte[]]::new($blobText.Length / 2)
    for ($index = 0; $index -lt $blobText.Length; $index += 2) {
        $bytes[$index / 2] = [Convert]::ToByte($blobText.Substring($index, 2), 16)
    }

    return $bytes
}

function Get-RecentExceptionCutoff {
    if (-not $ClassicExceptions.IsPresent -and -not $AllExceptions.IsPresent) {
        return (Get-Date).Date.AddMonths(-3)
    }

    return $null
}

function Get-CalendarDiagnosticObjectDeduplicationKey {
    param(
        $CalLog
    )

    $itemId = ""
    if ($null -ne $CalLog.ItemId) {
        if ($CalLog.ItemId.PSObject.Properties.Name -contains 'ObjectId') {
            $itemId = [string]$CalLog.ItemId.ObjectId
        } else {
            $itemId = [string]$CalLog.ItemId
        }
    }

    $calendarLogRequestId = if ($null -ne $CalLog.CalendarLogRequestId) { [string]$CalLog.CalendarLogRequestId } else { "" }
    $logTimestamp = if ($null -ne $CalLog.LogTimestamp) { [string]$CalLog.LogTimestamp } else { "" }
    $originalStartDate = if ($null -ne $CalLog.OriginalStartDate) { [string]$CalLog.OriginalStartDate } else { "" }
    $triggerAction = if ($null -ne $CalLog.CalendarLogTriggerAction) { [string]$CalLog.CalendarLogTriggerAction } else { "" }
    $itemClass = if ($null -ne $CalLog.ItemClass) { [string]$CalLog.ItemClass } else { "" }
    $itemVersion = if ($null -ne $CalLog.ItemVersion) { [string]$CalLog.ItemVersion } else { "" }
    $logRowType = if ($null -ne $CalLog.LogRowType) { [string]$CalLog.LogRowType } else { "" }
    $responsibleUserName = if ($null -ne $CalLog.ResponsibleUserName) { [string]$CalLog.ResponsibleUserName } else { "" }
    $clientInfo = if ($null -ne $CalLog.LogClientInfoString) { [string]$CalLog.LogClientInfoString } else { "" }

    return "$itemId|$calendarLogRequestId|$logTimestamp|$originalStartDate|$triggerAction|$itemClass|$itemVersion|$logRowType|$responsibleUserName|$clientInfo"
}

function RemoveDuplicateCalendarDiagnosticObjects {
    param(
        [array]$CalLogs,
        [switch]$Quiet
    )

    if ($null -eq $CalLogs -or $CalLogs.Count -le 1) {
        return @($CalLogs)
    }

    $uniqueLogs = @($CalLogs | Group-Object -Property { Get-CalendarDiagnosticObjectDeduplicationKey -CalLog $_ } | ForEach-Object {
            $_.Group | Select-Object -First 1
        } | Sort-Object { ConvertDateTime($_.LogTimestamp.ToString()) })

    $duplicateCount = $CalLogs.Count - $uniqueLogs.Count
    if (($duplicateCount -gt 0) -and (-not $Quiet.IsPresent)) {
        Write-Host -ForegroundColor Yellow "Removed [$duplicateCount] duplicate Calendar Log entries before processing."
    }

    return $uniqueLogs
}

function Merge-CalendarDiagnosticObjects {
    param(
        [array]$BaseLogs,
        [array]$AdditionalLogs
    )

    $combinedLogs = @($BaseLogs) + @($AdditionalLogs)
    return RemoveDuplicateCalendarDiagnosticObjects -CalLogs $combinedLogs -Quiet
}

function FilterExceptionLogsByRecency {
    param(
        [array]$ExceptionLogs
    )

    $cutoffDate = Get-RecentExceptionCutoff
    if ($null -eq $cutoffDate) {
        return @($ExceptionLogs)
    }

    return @($ExceptionLogs | Where-Object {
            if ($null -eq $_.OriginalStartDate -or [string]::IsNullOrEmpty([string]$_.OriginalStartDate) -or $_.OriginalStartDate -eq "NotFound") {
                return $false
            }

            $originalStartDate = ConvertDateTime($_.OriginalStartDate.ToString())
            return ($originalStartDate -is [datetime]) -and $originalStartDate -ne [datetime]::MinValue -and $originalStartDate -ge $cutoffDate
        })
}

function Get-AppointmentExceptionDatesFromBlob {
    param(
        $AppointmentRecurrenceBlob
    )

    [byte[]]$bytes = Convert-AppointmentRecurrenceBlobToBytes -AppointmentRecurrenceBlob $AppointmentRecurrenceBlob
    $offset = [ref]0

    $readerVersion = Read-UInt16LE -Bytes $bytes -Offset $offset
    $writerVersion = Read-UInt16LE -Bytes $bytes -Offset $offset
    $null = Read-UInt16LE -Bytes $bytes -Offset $offset
    $patternType = Read-UInt16LE -Bytes $bytes -Offset $offset
    $null = Read-UInt16LE -Bytes $bytes -Offset $offset
    $null = Read-UInt32LE -Bytes $bytes -Offset $offset
    $null = Read-UInt32LE -Bytes $bytes -Offset $offset
    $null = Read-UInt32LE -Bytes $bytes -Offset $offset

    $patternSpecificSize = Get-RecurrencePatternSpecificSize -PatternType $patternType
    if (($offset.Value + $patternSpecificSize) -gt $bytes.Length) {
        throw "AppointmentRecurrenceBlob ended before PatternTypeSpecific data was fully read."
    }
    $offset.Value += $patternSpecificSize

    $null = Read-UInt32LE -Bytes $bytes -Offset $offset
    $null = Read-UInt32LE -Bytes $bytes -Offset $offset
    $null = Read-UInt32LE -Bytes $bytes -Offset $offset

    $deletedInstanceCount = Read-UInt32LE -Bytes $bytes -Offset $offset
    $deletedInstanceDates = [System.Collections.Generic.List[datetime]]::new()
    for ($index = 0; $index -lt $deletedInstanceCount; $index++) {
        $deletedInstanceDates.Add((Convert-RecurMinutesToDateTime -Minutes (Read-UInt32LE -Bytes $bytes -Offset $offset)).Date)
    }

    $modifiedInstanceCount = Read-UInt32LE -Bytes $bytes -Offset $offset
    $modifiedInstanceDates = [System.Collections.Generic.List[datetime]]::new()
    for ($index = 0; $index -lt $modifiedInstanceCount; $index++) {
        $modifiedInstanceDates.Add((Convert-RecurMinutesToDateTime -Minutes (Read-UInt32LE -Bytes $bytes -Offset $offset)).Date)
    }

    $seriesStartDate = Convert-RecurMinutesToDateTime -Minutes (Read-UInt32LE -Bytes $bytes -Offset $offset)
    $seriesEndDate = Convert-RecurMinutesToDateTime -Minutes (Read-UInt32LE -Bytes $bytes -Offset $offset)
    $readerVersion2 = Read-UInt32LE -Bytes $bytes -Offset $offset
    $writerVersion2 = Read-UInt32LE -Bytes $bytes -Offset $offset
    $null = Read-UInt32LE -Bytes $bytes -Offset $offset
    $null = Read-UInt32LE -Bytes $bytes -Offset $offset
    $exceptionCount = Read-UInt16LE -Bytes $bytes -Offset $offset

    if ($readerVersion -ne 0x3004 -or $writerVersion -ne 0x3004) {
        throw "Unexpected recurrence blob header versions [$readerVersion/$writerVersion]."
    }
    if ($readerVersion2 -lt 0x3006 -or $writerVersion2 -lt 0x3006) {
        throw "Unexpected recurrence blob secondary versions [$readerVersion2/$writerVersion2]."
    }
    if ($modifiedInstanceCount -lt $exceptionCount) {
        throw "ModifiedInstanceCount [$modifiedInstanceCount] is less than ExceptionCount [$exceptionCount]."
    }

    return [PSCustomObject]@{
        DeletedInstanceCount  = $deletedInstanceCount
        ModifiedInstanceCount = $modifiedInstanceCount
        ExceptionCount        = $exceptionCount
        DeletedInstanceDates  = @($deletedInstanceDates)
        ModifiedInstanceDates = @($modifiedInstanceDates)
        Dates                 = @($deletedInstanceDates + $modifiedInstanceDates | Sort-Object -Unique)
        SeriesStartDate       = $seriesStartDate
        SeriesEndDate         = $seriesEndDate
        PatternType           = $patternType
    }
}

function Get-ExceptionDatesFromMostRecentAppointmentBlob {
    param(
        [array]$CalLogs
    )

    $recurringAppointments = @($CalLogs | Where-Object {
            $_.ItemClass -eq 'IPM.Appointment' -and
            $_.AppointmentRecurring -and
            $null -ne $_.AppointmentRecurrenceBlob -and
            -not [string]::IsNullOrWhiteSpace([string]$_.AppointmentRecurrenceBlob)
        })

    if ($recurringAppointments.Count -eq 0) {
        throw "No recurring IPM.Appointment with an AppointmentRecurrenceBlob was found in the Calendar Logs."
    }

    $blobSource = $recurringAppointments | Where-Object { $_.CalendarItemType.ToString() -eq 'RecurringMaster' } | Sort-Object @{ Expression = { $itemVersion = 0; [void][int]::TryParse([string]$_.ItemVersion, [ref]$itemVersion); $itemVersion } }, @{ Expression = { ConvertDateTime($_.LogTimestamp.ToString()) } } -Descending | Select-Object -First 1
    if ($null -eq $blobSource) {
        $blobSource = $recurringAppointments | Sort-Object @{ Expression = { $itemVersion = 0; [void][int]::TryParse([string]$_.ItemVersion, [ref]$itemVersion); $itemVersion } }, @{ Expression = { ConvertDateTime($_.LogTimestamp.ToString()) } } -Descending | Select-Object -First 1
    }

    $parsedBlob = Get-AppointmentExceptionDatesFromBlob -AppointmentRecurrenceBlob $blobSource.AppointmentRecurrenceBlob
    $exceptionDates = @($parsedBlob.Dates)

    $cutoffDate = Get-RecentExceptionCutoff
    if ($null -ne $cutoffDate) {
        $exceptionDates = @($exceptionDates | Where-Object { $_ -ge $cutoffDate })
    }

    return [PSCustomObject]@{
        SourceLog      = $blobSource
        ParsedBlob     = $parsedBlob
        ExceptionDates = $exceptionDates
    }
}

function CollectExceptionLogsLegacy {
    param(
        [string]$Identity,
        [string]$MeetingID,
        [switch]$UsedAsFallback
    )

    $ExceptionLogs = @()
    $LogToExamine = @()
    $LogToExamine = $script:GCDO | Where-Object { $_.ItemClass -like 'IPM.Appointment*' } | Sort-Object ItemVersion

    Write-Host -ForegroundColor Cyan "Found $($LogToExamine.count) CalLogs to examine for Exception Logs."
    if ($LogToExamine.count -gt 100) {
        Write-Host -ForegroundColor Cyan "`t This is a large number of logs to examine, this may take a while."
    }
    $logLeftCount = $LogToExamine.count

    $ExceptionLogs = $LogToExamine | ForEach-Object {
        $logLeftCount -= 1
        Write-Verbose "Getting Exception Logs for [$($_.ItemId.ObjectId)]"
        Get-CalendarDiagnosticObjects -Identity $Identity -ItemIds $_.ItemId.ObjectId -ShouldFetchRecurrenceExceptions $true -CustomPropertyNames $CustomPropertyNameList -ShouldBindToItem $true 3>$null
        if (($logLeftCount % 10 -eq 0) -and ($logLeftCount -gt 0)) {
            Write-Host -ForegroundColor Cyan "`t [$($logLeftCount)] logs left to examine..."
        }
    }

    $ExceptionLogs = $ExceptionLogs | Where-Object { $_.ItemClass -notlike "IPM.Appointment*" }
    $cutoffDate = Get-RecentExceptionCutoff
    if ($null -ne $cutoffDate) {
        Write-Host -ForegroundColor Yellow "Filtering legacy Exception logs to only keep items with OriginalStartDate in the last 3 months."
        $ExceptionLogs = FilterExceptionLogsByRecency -ExceptionLogs $ExceptionLogs
    }

    Write-Host -ForegroundColor Cyan "Found $($ExceptionLogs.count) Exception Logs, adding them into the CalLogs."
    $script:GCDO = Merge-CalendarDiagnosticObjects -BaseLogs $script:GCDO -AdditionalLogs $ExceptionLogs
    if ($UsedAsFallback.IsPresent) {
        $script:ExceptionCollectionStatus = "CollectedLegacyFallback"
    } else {
        $script:ExceptionCollectionStatus = "Collected"
    }
}

function CollectExceptionLogsFast {
    param(
        [string]$Identity,
        [string]$MeetingID
    )

    $blobResult = Get-ExceptionDatesFromMostRecentAppointmentBlob -CalLogs $script:GCDO
    $exceptionDates = @($blobResult.ExceptionDates | Sort-Object -Unique)

    Write-Host -ForegroundColor Cyan "Fast exception collection selected blob from ItemVersion [$($blobResult.SourceLog.ItemVersion)] with [$($blobResult.ParsedBlob.ExceptionCount)] exception entries."
    Write-Host -ForegroundColor Cyan "Found [$($blobResult.ParsedBlob.DeletedInstanceCount)] deleted exception dates and [$($blobResult.ParsedBlob.ModifiedInstanceCount)] modified exception dates in the recurrence blob."

    $cutoffDate = Get-RecentExceptionCutoff
    if ($null -ne $cutoffDate) {
        Write-Host -ForegroundColor Cyan "Keeping only Exception dates from the last 3 months: [$($cutoffDate.ToString('yyyy-MM-dd'))] and newer."
        Write-Host -ForegroundColor Cyan "[$($exceptionDates.Count)] Exception date(s) match the 3 month time frame."
    }

    if ($exceptionDates.Count -eq 0) {
        $script:ExceptionCollectionStatus = "NoExceptionDates"
        Write-Host -ForegroundColor Cyan "No matching Exception dates were found in the AppointmentRecurrenceBlob."
        return
    }

    $collectedExceptionLogs = @(
        foreach ($exceptionOriginalStartDate in $exceptionDates) {
            GetCalendarDiagnosticObjects -Identity $Identity -MeetingID $MeetingID -ExceptionDateOverride $exceptionOriginalStartDate
        }
    )

    $collectedExceptionLogs = @($collectedExceptionLogs | Where-Object {
            $_.ItemClass -notlike "IPM.Appointment*" -or
            ($null -ne $_.OriginalStartDate -and $_.OriginalStartDate -ne "NotFound" -and -not [string]::IsNullOrEmpty([string]$_.OriginalStartDate))
        })

    Write-Host -ForegroundColor Cyan "Collected $($collectedExceptionLogs.count) Exception-related logs from [$($exceptionDates.count)] ExceptionDate queries."
    $script:GCDO = Merge-CalendarDiagnosticObjects -BaseLogs $script:GCDO -AdditionalLogs $collectedExceptionLogs
    $script:ExceptionCollectionStatus = "CollectedFast"
}

function CollectExceptionLogs {
    param(
        [string]$Identity,
        [string]$MeetingID
    )

    Write-Verbose "Looking for Exception Logs..."
    $IsRecurring = SetIsRecurring -CalLogs $script:GCDO
    Write-Verbose "Meeting IsRecurring: $IsRecurring"

    if ($IsRecurring) {
        if (-not $ClassicExceptions.IsPresent -and [string]::IsNullOrEmpty($ExceptionDate)) {
            try {
                CollectExceptionLogsFast -Identity $Identity -MeetingID $MeetingID
            } catch {
                $script:ExceptionCollectionStatus = "CollectedLegacyFallback"
                Write-DashLineBoxColor "FAST EXCEPTION COLLECTION FAILED",
                "Error: $($_.Exception.Message)",
                "Falling back to the legacy per-appointment Exception collector." -Color Red -DashChar "="
                CollectExceptionLogsLegacy -Identity $Identity -MeetingID $MeetingID -UsedAsFallback
            }
        } else {
            CollectExceptionLogsLegacy -Identity $Identity -MeetingID $MeetingID
        }
    } else {
        $script:ExceptionCollectionStatus = "NotRecurring"
        Write-Host -ForegroundColor Cyan "No Recurring Meetings found, no Exception Logs to collect."
    }
}
