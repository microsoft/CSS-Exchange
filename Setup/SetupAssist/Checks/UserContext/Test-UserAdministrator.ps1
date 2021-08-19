# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\New-TestResult.ps1
Function Test-UserAdministrator {
    [CmdletBinding()]
    param()
    process {
        $user = whoami
        $passed = Confirm-Administrator
        $result = "Failed"

        if ($passed) { $result = "Passed" }
    }
    end {
        $params = @{
            TestName          = "User Administrator"
            Result            = $result
            AdditionalContext = $user
            CustomData        = $null
        }
        return (New-TestResult @params)
    }
}
