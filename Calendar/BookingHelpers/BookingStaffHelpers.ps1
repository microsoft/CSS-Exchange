# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-MBPermissions {
    param($Identity)
    # Get the Mailbox Permissions
    $MBPermissions = Get-MailboxPermission -Identity $Identity -ErrorAction SilentlyContinue
    return $MBPermissions
}

function Get-MBRecipientPermissions {
    param($Identity)
    # Get the Mailbox Recipient Permissions
    $MBRecipientPermissions = Get-RecipientPermission -Identity $Identity -ErrorAction SilentlyContinue
    return $MBRecipientPermissions
}

function CheckMyBaseOptionsRBACRole($Identity) {
    $RBACRole = Get-ManagementRoleAssignment -RoleAssignee $Identity -Role "MyBaseOptions" | Select-Object -Property RoleAssignee, Role
    return $RBACRole
}

# This method is used to check if a staff member has Bookings Persisted Capabilities
function CheckPersistedCapabilities($Identity) {
    $PC = Get-Mailbox -Identity $Identity | Select-Object -ExpandProperty PersistedCapabilities
    return $PC
}

function Get-GraphBookingsStaff {
    param (
        [string]$Identity
    )

    $MBstaff = Get-MgBookingBusinessStaffMember -BookingBusinessId $Identity
    $Staff = @()
    foreach ($StaffMember in $MBstaff) {
        $Staff += [PSCustomObject]@{
            Id                                       = $StaffMember.Id
            displayName                              = $StaffMember.AdditionalProperties["displayName"]
            emailAddress                             = $StaffMember.AdditionalProperties["emailAddress"]
            availabilityIsAffectedByPersonalCalendar = $StaffMember.AdditionalProperties["availabilityIsAffectedByPersonalCalendar"]
            role                                     = $StaffMember.AdditionalProperties["role"]
            useBusinessHours                         = $StaffMember.AdditionalProperties["useBusinessHours"]
            isEmailNotificationEnabled               = $StaffMember.AdditionalProperties["isEmailNotificationEnabled"]
            membershipStatus                         = $StaffMember.AdditionalProperties["membershipStatus"]
            timeZone                                 = $StaffMember.AdditionalProperties["timeZone"]
            createdDateTime                          = $StaffMember.AdditionalProperties["createdDateTime"]
            lastUpdatedDateTime                      = $StaffMember.AdditionalProperties["lastUpdatedDateTime"]
            # workingHours is a complex object type to write to excel, so, storing as JSON for easier visualization
            workingHours                             = $StaffMember.AdditionalProperties["workingHours"]  | ConvertTo-Json -Depth 10
        }
    }

    return $Staff
}
