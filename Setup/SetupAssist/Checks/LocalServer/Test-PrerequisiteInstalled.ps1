# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\..\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\New-TestResult.ps1
function Test-PrerequisiteInstalled {
    $netVersion = Get-NETFrameworkVersion
    $params = @{
        TestName   = ".NET Framework"
        CustomData = $netVersion
    }

    if ($netVersion.MinimumValue -lt 528040) {
        New-TestResult @params -Result "Failed"
    }

    $installed = @(Get-VisualCRedistributableInstalledVersion)
    $years = @(2012, 2013)

    foreach ($year in $years) {
        $info = Get-VisualCRedistributableInfo -Year $year
        $params = @{
            TestName   = $info.DisplayName.Replace("*", "")
            CustomData = $info.DownloadUrl
        }

        if (-not (Test-VisualCRedistributableUpToDate -Year $year -Installed $installed)) {
            New-TestResult @params -Result "Failed"
        } else {
            New-TestResult @params -Result "Passed"
        }
    }
}
