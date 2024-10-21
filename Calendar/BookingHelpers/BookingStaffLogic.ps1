# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-StaffData {
    $staffData = @()

    foreach ($staffMember in $script:MBPermissions) {
        if ($staffMember.User -ne "NT AUTHORITY\SELF") {
            $staffData += [PSCustomObject]@{
                User                  = $staffMember.User
                AccessRights          = $staffMember.AccessRights
                IsOwner               = $staffMember.IsOwner
                RBACRole              = CheckMyBaseOptionsRBACRole -identity $staffMember.User
                PersistedCapabilities = CheckPersistedCapabilities -identity $staffMember.User
            }
        }
    }

    return $staffData
}
