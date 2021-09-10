# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ServerRebootPending.ps1
Function Test-PendingReboot {
    $rebootPending = Get-ServerRebootPending
    $params = @{
        TestName      = "Pending Reboot"
        Details       = $rebootPending.PendingRebootLocations
        ReferenceInfo = "https://aka.ms/SA-RebootPending"
    }

    if ($rebootPending.PendingReboot) {
        New-TestResult @params -Result "Failed"
    } else {
        New-TestResult @params -Result "Passed"
    }
}
