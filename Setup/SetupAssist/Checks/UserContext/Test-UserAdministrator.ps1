# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\New-TestResult.ps1
Function Test-UserAdministrator {

    $params = @{
        TestName          = "User Administrator"
        AdditionalContext = (whoami)
        CustomData        = $null
    }

    if (Confirm-Administrator) {
        New-TestResult @params -Result "Passed"
    } else {
        New-TestResult @params -Result "Failed"
    }
}
