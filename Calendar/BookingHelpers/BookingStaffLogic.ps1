# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-StaffData {
    $StaffData = @()

    foreach ($StaffMember in $script:MBPermissions) {
        if ($StaffMember.User -ne "NT AUTHORITY\SELF") {
            $StaffData += [PSCustomObject]@{
                User                  = $StaffMember.User
                AccessRights          = $StaffMember.AccessRights
                IsOwner               = $StaffMember.IsOwner
                RBACRole              = CheckMyBaseOptionsRBACRole -identity $StaffMember.User
                PersistedCapabilities = CheckPersistedCapabilities -identity $StaffMember.User
            }
        }
    }

    return $StaffData
}
