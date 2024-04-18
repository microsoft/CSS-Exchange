# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Checks if a set of Calendar Logs is from the Organizer.
#>
function SetIsOrganizer {
    param(
        $CalLogs
    )
    [bool] $IsOrganizer = $false

    foreach ($CalLog in $CalLogs) {
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            ($CalLog.ResponseType -eq "1" -or $CalLogs.ResponseType -eq "Organizer")) {
            $IsOrganizer = $true
            Write-Verbose "IsOrganizer: [$IsOrganizer]"
            return $IsOrganizer
        }
    }
    Write-Verbose "IsOrganizer: [$IsOrganizer]"
    return $IsOrganizer
}

<#
.SYNOPSIS
Checks if a set of Calendar Logs is from a Resource Mailbox.
#>
function SetIsRoom {
    param(
        $CalLogs
    )
    [bool] $IsRoom = $false
    # Simple logic is if RBA is running on the MB, it is a Room MB, otherwise it is not.
    foreach ($CalLog in $CalLogs) {
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            $CalLog.Client -eq "ResourceBookingAssistant" ) {
            $IsRoom = $true
            return $IsRoom
        }
    }
    return $IsRoom
}

<#
.SYNOPSIS
Checks if a set of Calendar Logs is from a Recurring Meeting.
#>
function SetIsRecurring {
    param(
        $CalLogs
    )
    Write-Host -ForegroundColor Yellow "Looking for signs of a recurring meeting."
    [bool] $IsRecurring = $false
    # See if this is a recurring meeting
    foreach ($CalLog in $CalLogs) {
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            ($CalLog.CalendarItemType.ToString() -eq "RecurringMaster" -or
            $CalLog.IsException -eq $true)) {
            $IsRecurring = $true
            Write-Verbose "Found recurring meeting."
            return $IsRecurring
        }
    }
    Write-Verbose "Did not find signs of recurring meeting."
    return $IsRecurring
}

<#
.SYNOPSIS
Checks to see if the Calendar Log is Ignorable.
Many updates are not interesting in the Calendar Log, marking these as ignorable. 99% of the time this is correct.
#>
function SetIsIgnorable {
    param(
        $CalLog
    )

    if ($CalLog.ItemClass -eq "(Occurrence Deleted)") {
        return "Ignorable"
    } elseif ($ShortClientName -like "TBA*SharingSyncAssistant" -or
        $ShortClientName -eq "CalendarReplication" -or
        $CalendarItemTypes.($CalLog.ItemClass) -eq "SharingCFM" -or
        $CalendarItemTypes.($CalLog.ItemClass) -eq "SharingDelete") {
        return "Sharing"
    } elseif ($ShortClientName -like "EBA*" -or
        $ShortClientName -like "TBA*" -or
        $ShortClientName -eq "LocationProcessor" -or
        $ShortClientName -eq "GriffinRestClient" -or
        $ShortClientName -eq "RestConnector" -or
        $ShortClientName -eq "ELC-B2" -or
        $ShortClientName -eq "TimeService" ) {
        return "Ignorable"
    } elseif ($CalLog.ItemClass -eq "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}" ) {
        return "Exception"
    } elseif (($CalendarItemTypes.($CalLog.ItemClass) -like "*Resp*" -and $CalLog.CalendarLogTriggerAction -ne "Create" ) -or
        $CalendarItemTypes.($CalLog.ItemClass) -eq "AttendeeList" ) {
        return "Cleanup"
    } else {
        return "False"
    }
}
