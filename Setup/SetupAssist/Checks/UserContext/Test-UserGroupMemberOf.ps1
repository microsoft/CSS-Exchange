# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-TokenGroupsGlobalAndUniversal.ps1
. $PSScriptRoot\..\..\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-WellKnownGroupSid.ps1
. $PSScriptRoot\..\New-TestResult.ps1
function Test-UserGroupMemberOf {
    [CmdletBinding()]
    param(
        [bool]$PrepareAdRequired,
        [bool]$PrepareSchemaRequired,
        [bool]$PrepareDomainOnly
    )

    $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $tokenGroups = Get-TokenGroupsGlobalAndUniversal -UserSid $windowsIdentity.User.Value

    $groupRequirements = @(
        @{
            Name   = "Organization Management"
            Role   = "Organization Management"
            Reason = "User must be in the Organization Management Group"
        }
    )

    if ($PrepareSchemaRequired) {
        $groupRequirements += @{
            Name   = "Schema Admins"
            Role   = (Get-WellKnownGroupSid "Schema Admins")
            Reason = "User must be in Schema Admins to update Schema which is required."
        }
    }

    if ($PrepareAdRequired) {

        if (-not ($PrepareDomainOnly)) {
            $groupRequirements += @{
                Name   = "Enterprise Admins"
                Role   = (Get-WellKnownGroupSid "Enterprise Admins")
                Reason = "User must be Enterprise Admins to do PrepareSchema or PrepareAD."
            }
        }

        $groupRequirements += @{
            Name   = "Domain Admins"
            Role   = (Get-WellKnownGroupSid "Domain Admins")
            Reason = "User must be in Domain Admins to do PrepareAD which is required."
        }
    }

    $principal = (New-Object System.Security.Principal.WindowsPrincipal($windowsIdentity))
    $params = @{
        TestName = [string]::Empty
        Details  = [string]::Empty
    }

    foreach ($group in $groupRequirements) {
        $params.TestName = "User Group - $($group.Name)"
        $params.Details = "$($group.Role)"
        if ($principal.IsInRole($group.Role)) {
            New-TestResult @params -Result "Passed"
        } else {
            # If not running under admin, IsInRole doesn't work properly provide error on this.
            # Then check to see if they are in a token group, if they are need to sign out to have it applied.
            # Otherwise, they are not in the group.
            if (-not (Confirm-Administrator)) {
                New-TestResult @params -Result "Failed" -ReferenceInfo "Must run as Administrator to properly test"
            } elseif ($null -ne $tokenGroups -and
            ($tokenGroups.SID.Contains($group.Role.ToString()))) {
                New-TestResult @params -Result "Warning" -ReferenceInfo "Need to log off and log back in"
            } else {
                New-TestResult @params -Result "Failed" -ReferenceInfo $group.Reason
            }
        }
    }
}
