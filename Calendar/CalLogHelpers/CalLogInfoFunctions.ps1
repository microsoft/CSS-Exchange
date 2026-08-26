# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Checks if a set of Calendar Logs is from the Organizer.

Modern Sharing can replicate the Organizer's items into a Delegate's mailbox, so a
positive ResponseType/ExternalSharingMasterId match is not sufficient on its own. When
an Identity is supplied this function additionally validates that the From / Organizer
on the qualifying row resolves to the user being analyzed.
#>
function SetIsOrganizer {
    param(
        $CalLogs,
        [string] $Identity
    )
    [bool] $IsOrganizer = $false

    foreach ($CalLog in $CalLogs) {
        if ($CalLog.ItemClass -eq "Ipm.Appointment" -and
            $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            ($CalLog.ResponseType -eq "1" -or $CalLog.ResponseType -eq "Organizer")) {

            if (-not [string]::IsNullOrEmpty($Identity) -and -not (Test-CalLogFromMatchesIdentity -CalLog $CalLog -Identity $Identity)) {
                Write-Verbose "SetIsOrganizer: ResponseType is Organizer on this row but From does not resolve to [$Identity]. Likely a Modern Sharing copy; skipping."
                continue
            }

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
Returns $true when the raw CalLog's From / Sender / SenderEmailAddress resolves to the
supplied Identity (SMTP address). Used to confirm that an Organizer-typed row really
belongs to the user being analyzed, and not a Modern-Sharing copy of someone else's data.
#>
function Test-CalLogFromMatchesIdentity {
    param(
        $CalLog,
        [string] $Identity
    )

    if ([string]::IsNullOrEmpty($Identity)) {
        return $false
    }

    $candidates = @()
    if ($null -ne $CalLog.From) { $candidates += [string]$CalLog.From }
    if ($null -ne $CalLog.Sender) { $candidates += [string]$CalLog.Sender }
    if ($null -ne $CalLog.SenderEmailAddress) { $candidates += [string]$CalLog.SenderEmailAddress }

    $identityLocal = ($Identity -split '@')[0]

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrEmpty($candidate)) { continue }

        # Try the resolved SMTP first (requires MailboxList to be populated by BuildCSV).
        if ($null -ne $script:MailboxList -and $script:MailboxList.Count -gt 0) {
            $resolved = GetSMTPAddress $candidate
            if (-not [string]::IsNullOrEmpty($resolved) -and
                [string]::Equals($resolved.Trim(), $Identity.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }

        # Embedded SMTP form: '"Name" <user@contoso.com>'
        if ($candidate -match '<([^>]+@[^>]+)>') {
            if ([string]::Equals($Matches[1].Trim(), $Identity.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }

        # Direct SMTP match
        if ([string]::Equals($candidate.Trim(), $Identity.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }

        # Last-resort: the CN often contains the SMTP local-part as a hint.
        if (-not [string]::IsNullOrEmpty($identityLocal) -and
            $candidate -match [regex]::Escape($identityLocal)) {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
Classifies the user being analyzed as a Delegate-of-Organizer, Delegate-of-Attendee,
or Attendee based on the Enhanced CalLogs.

A user is a Delegate when their logs contain a Modern Sharing copy of another mailbox's
calendar entries (SharedFolderName != 'Not Shared') AND they either (a) take changes on
those shared rows themselves, or (b) receive Resp.* messages on behalf of the shared
mailbox owner.

The DelegateForSmtp output is the SMTP of the mailbox the user is delegating for.
When the meeting Organizer's SMTP matches DelegateForSmtp the user is a Delegate of the
Organizer; otherwise the user is a Delegate of some Attendee.

This function must be called after BuildCSV has populated $script:EnhancedCalLogs and
the SMTP lookup caches.
#>
function SetDelegateRole {
    param(
        [array] $EnhancedCalLogs,
        [string] $Identity
    )

    $script:IsDelegateOfOrganizer = $false
    $script:IsDelegateOfAttendee = $false
    $script:DelegateForSmtp = $null

    if ($null -eq $EnhancedCalLogs -or $EnhancedCalLogs.Count -eq 0) {
        return
    }

    if ($script:IsOrganizer -or $script:IsRoomMB) {
        return
    }

    [array] $sharedRows = $EnhancedCalLogs | Where-Object { $_.SharedFolderName -ne 'Not Shared' }
    if ($sharedRows.Count -eq 0) {
        Write-Verbose "SetDelegateRole: No Modern Sharing rows for [$Identity]."
        return
    }

    # Determine whether the user takes action on the shared rows themselves.
    [array] $userChangesOnShared = $sharedRows | Where-Object {
        $_.TriggerAction -in @('Create', 'Update', 'SoftDelete', 'MoveToDeletedItems', 'HardDelete') -and
        (Test-ResponsibleUserMatchesIdentity -ResponsibleUser $_.ResponsibleUser -SenderSmtp $_.Sender -Identity $Identity)
    }

    # Resp.* rows that arrived inside the shared folder are the "received all Resp's" signal.
    [array] $sharedRespRows = $sharedRows | Where-Object { $_.ItemClass -like 'Resp.*' }

    if ($userChangesOnShared.Count -eq 0 -and $sharedRespRows.Count -eq 0) {
        Write-Verbose "SetDelegateRole: User [$Identity] has Modern Sharing rows but no delegate activity."
        return
    }

    # Identify the mailbox the user is delegating for. ReceivedRepresenting is the strongest
    # signal because it's set by transport when mail is delivered on behalf of someone else.
    [array] $representingValues = $sharedRows |
        Where-Object {
            -not [string]::IsNullOrEmpty($_.ReceivedRepresenting) -and
            $_.ReceivedRepresenting -ne '-' -and
            $_.ReceivedRepresenting -ne 'NotFound'
        } |
        ForEach-Object { ([string]$_.ReceivedRepresenting).Trim() }

    if ($representingValues.Count -gt 0) {
        $script:DelegateForSmtp = ($representingValues | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name
    }

    # Determine the meeting Organizer's SMTP (most common From across all appointment rows).
    $organizerSmtp = Get-MeetingOrganizerSmtp -EnhancedCalLogs $EnhancedCalLogs

    # Fall back to the Organizer SMTP if ReceivedRepresenting was not informative.
    if ([string]::IsNullOrEmpty($script:DelegateForSmtp)) {
        $script:DelegateForSmtp = $organizerSmtp
    }

    if (-not [string]::IsNullOrEmpty($organizerSmtp) -and
        -not [string]::IsNullOrEmpty($script:DelegateForSmtp) -and
        [string]::Equals($script:DelegateForSmtp, $organizerSmtp, [System.StringComparison]::OrdinalIgnoreCase)) {
        $script:IsDelegateOfOrganizer = $true
        Write-Host -ForegroundColor Magenta "IsDelegateOfOrganizer: [$Identity] is acting as a Delegate of the Organizer [$($script:DelegateForSmtp)]."
    } else {
        $script:IsDelegateOfAttendee = $true
        Write-Host -ForegroundColor Magenta "IsDelegateOfAttendee: [$Identity] is acting as a Delegate of the Attendee [$($script:DelegateForSmtp)]."
    }
}

<#
.SYNOPSIS
Compares a ResponsibleUser / Sender SMTP value (from EnhancedCalLogs) to the Identity.
#>
function Test-ResponsibleUserMatchesIdentity {
    param(
        [string] $ResponsibleUser,
        [string] $SenderSmtp,
        [string] $Identity
    )

    if ([string]::IsNullOrEmpty($Identity)) { return $false }

    foreach ($value in @($ResponsibleUser, $SenderSmtp)) {
        if ([string]::IsNullOrEmpty($value) -or $value -eq '-' -or $value -eq 'NotFound') { continue }
        if ([string]::Equals($value.Trim(), $Identity.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

<#
.SYNOPSIS
Returns the most-common From SMTP across appointment rows in the Enhanced CalLogs, which
is treated as the meeting Organizer's SMTP.
#>
function Get-MeetingOrganizerSmtp {
    param(
        [array] $EnhancedCalLogs
    )

    if ($null -eq $EnhancedCalLogs -or $EnhancedCalLogs.Count -eq 0) {
        return $null
    }

    [array] $appointmentFrom = $EnhancedCalLogs |
        Where-Object {
            ($_.ItemClass -eq 'Ipm.Appointment' -or $_.ItemClass -like 'Exception*') -and
            -not [string]::IsNullOrEmpty($_.From) -and
            $_.From -ne '-' -and
            $_.From -ne 'NotFound'
        } |
        ForEach-Object { ([string]$_.From).Trim() }

    if ($appointmentFrom.Count -eq 0) {
        return $null
    }

    return ($appointmentFrom | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name
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
    $rbaLog = $CalLogs | Where-Object {
        $_.ItemClass -eq "IPM.Appointment" -and
        $_.ExternalSharingMasterId -eq "NotFound" -and
        $_.LogClientInfoString -like "*ResourceBookingAssistant*"
    } | Select-Object -First 1

    if ($null -ne $rbaLog) {
        Write-Host -ForegroundColor Green "Found Room Mailbox indicator: [$($rbaLog.LogClientInfoString)]"
        return $true
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
        if ($null -ne $CalLog.ItemClass -and
            (GetItemType $CalLog.ItemClass) -eq "Ipm.Appointment" -and
            # Commenting this out will get all the updates for shared calendars, which is important with Delegates.
            #      $CalLog.ExternalSharingMasterId -eq "NotFound" -and
            $CalLog.CalendarItemType.ToString() -eq "RecurringMaster") {
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
    Write-Host -ForegroundColor Red "Did not find any Ipm.Appointments in the CalLogs. If this is the Organizer of the meeting, this could be the Outlook Bifurcation issue."
    Write-Host -ForegroundColor Yellow "`t The Outlook Bifurcation issue is where Outlook saves to the Organizer's Mailbox on one thread and sends to the attendees via transport on another thread. If the save to the Organizer's mailbox failed, we get into the Bifurcated State, where the Organizer does not have the meeting but the Attendees do."
    Write-Host -ForegroundColor Yellow "`t See https://support.microsoft.com/en-us/office/meeting-request-is-missing-from-organizers-calendar-c13c47cd-18f9-4ef0-b9d0-d9e174912c4a"
    return $IsBifurcated
}
