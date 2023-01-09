# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-ExecutionPolicy {

    $executionPolicy = Get-ExecutionPolicy

    $params = @{
        TestName = "Execution Policy"
        Details  = $executionPolicy
    }
    if ($executionPolicy -ne "Unrestricted" -and
        $executionPolicy -ne "Bypass") {
        New-TestResult @params -Result "Warning"
    } else {
        New-TestResult @params -Result "Passed"
    }
}
