# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


. $PSScriptRoot\..\New-TestResult.ps1
Function Test-ExecutionPolicy {
    [CmdletBinding()]
    param()
    process {
        $executionPolicy = Get-ExecutionPolicy

        if ($executionPolicy -ne "Unrestricted" -and
            $executionPolicy -ne "Bypass") {
            $result = "Warning"
        } else {
            $result = "Passed"
        }
    }
    end {
        $params = @{
            TestName          = "Execution Policy"
            Result            = $result
            AdditionalContext = $executionPolicy
            CustomData        = $null
        }
        return (New-TestResult @params)
    }
}
