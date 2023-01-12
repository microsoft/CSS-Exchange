# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\New-TestResult.ps1
function Test-UserIsAdministrator {
    $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $params = @{
        TestName = "User Administrator"
        Details  = "$($windowsIdentity.Name) $($windowsIdentity.User.Value)"
    }

    if (Confirm-Administrator) {
        New-TestResult @params -Result "Passed"
    } else {
        New-TestResult @params -Result "Failed"
    }
}
