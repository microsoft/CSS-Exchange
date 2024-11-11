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
        if ($CalLog.ItemClass -eq "Ipm.Appointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            ($CalLog.ResponseType -eq "1" -or $CalLog.ResponseType -eq "Organizer")) {
            $IsOrganizer = $true
            Write-Host -ForegroundColor Green "IsOrganizer: [$IsOrganizer]"
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

    # See if we have already determined this is a Room MB.
    if ($script:Rooms -contains $Identity) {
        return $true
    }

    # Simple logic is if RBA is running on the MB, it is a Room MB, otherwise it is not.
    foreach ($CalLog in $CalLogs) {
        Write-Verbose "Checking if this is a Room Mailbox. [$($CalLog.ItemClass)] [$($CalLog.ExternalSharingMasterId)] [$($CalLog.LogClientInfoString)]"
        if ($CalLog.ItemClass -eq "IPM.Appointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            $CalLog.LogClientInfoString -like "*ResourceBookingAssistant*" ) {
            return $true
        }
    }
    return $false
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
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "Ipm.Appointment" -and
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
Check for Bifurcation issue
#>
function CheckForBifurcation {
    param (
        $CalLogs
    )
    Write-Verbose  "Looking for signs of the Bifurcation Issue."
    [bool] $IsBifurcated = $false
    # See if there is an IPM.Appointment in the CalLogs.
    foreach ($CalLog in $CalLogs) {
        if ($CalLog.ItemClass -eq "IPM.Appointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound") {
            $IsBifurcated = $false
            Write-Verbose "Found Ipm.Appointment, likely not a bifurcation issue."
            return $IsBifurcated
        }
    }
    Write-Host -ForegroundColor Red "Did not find any Ipm.Appointments in the CalLogs. If this is the Organizer of the meeting, this could the the Outlook Bifurcation issue."
    Write-Host -ForegroundColor Yellow "`t This could be the Outlook Bifurcation issue, where Outlook saves to the Organizers Mailbox on one thread and send to the attendee via transport on another thread.  If the save to Organizers mailbox failed, we get into the Bifurcated State, where the Organizer does not have the meeting but the Attendees do."
    Write-Host -ForegroundColor Yellow "`t See https://support.microsoft.com/en-us/office/meeting-request-is-missing-from-organizers-calendar-c13c47cd-18f9-4ef0-b9d0-d9e174912c4a"
    return $IsBifurcated
}

