function Get-MBPermissions {
    param($identity)
    # Get the Mailbox Permissions
    $MBPermissions = Get-MailboxPermission -Identity $identity -ErrorAction SilentlyContinue
    return $MBPermissions
}

function Get-MBRecipientPermissions {
    param($identity)
    # Get the Mailbox Recipient Permissions
    $MBRecipientPermissions = Get-RecipientPermission -Identity $identity -ErrorAction SilentlyContinue
    return $MBRecipientPermissions
}


function CheckMyBaseOptionsRBACRole($identity) {
    $RBACRole = Get-ManagementRoleAssignment -RoleAssignee $identity -Role "MyBaseOptions" | Select-Object -Property RoleAssignee, Role
    return $RBACRole
}

function CheckPersistedCapabilities($identity) {
    $PC = Get-Mailbox -Identity $identity | Select-Object -ExpandProperty PersistedCapabilities
    return $PC
}



function Get-GraphBookingsStaff {
    param (
        [string]$Identity
    )

    $MBstaff = Get-MgBookingBusinessStaffMember -BookingBusinessId $identity
    $staff = @()
    foreach ($staffMember in $MBstaff) {
        $staff += [PSCustomObject]@{
            Id                                       = $staffMember.Id
            displayName                              = $staffMember.AdditionalProperties["displayName"]
            emailAddress                             = $staffMember.AdditionalProperties["emailAddress"]
            availabilityIsAffectedByPersonalCalendar = $staffMember.AdditionalProperties["availabilityIsAffectedByPersonalCalendar"]
            role                                     = $staffMember.AdditionalProperties["role"]
            useBusinessHours                         = $staffMember.AdditionalProperties["useBusinessHours"]
            isEmailNotificationEnabled               = $staffMember.AdditionalProperties["isEmailNotificationEnabled"]
            membershipStatus                         = $staffMember.AdditionalProperties["membershipStatus"]
            timeZone                                 = $staffMember.AdditionalProperties["timeZone"]
            createdDateTime                          = $staffMember.AdditionalProperties["createdDateTime"]
            lastUpdatedDateTime                      = $staffMember.AdditionalProperties["lastUpdatedDateTime"]
            #workingHours is a complexobject type to write to excel, so, storing as JSON for easier visualization
            workingHours                             = $staffMember.AdditionalProperties["workingHours"]  | ConvertTo-Json -Depth 10
        }
    }


    return $staff
}