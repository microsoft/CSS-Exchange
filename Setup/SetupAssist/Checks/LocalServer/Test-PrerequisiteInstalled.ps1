# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\..\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\New-TestResult.ps1
function Test-PrerequisiteInstalled {
    $netVersion = Get-NETFrameworkVersion
    $params = @{
        TestName      = ".NET Framework"
        Details       = ".NET $($netVersion.FriendlyName)"
        ReferenceInfo = "https://aka.ms/SA-NetDownload"
    }

    if ($netVersion.MinimumValue -lt 528040) {
        New-TestResult @params -Result "Failed"
    }

    $params = @{
        TestName      = "IIS URL Rewrite"
        Details       = "Not Installed"
        ReferenceInfo = "https://aka.ms/SA-IISRewrite"
    }

    try {
        $results = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite\" -Name Version -ErrorAction Stop
        $params.Details = "Installed Version $($results.Version)"
        New-TestResult @params -Result "Passed"
    } catch {
        New-TestResult @params -Result "Failed"
    }

    $installed = @(Get-VisualCRedistributableInstalledVersion)
    $years = @(2012, 2013)

    foreach ($year in $years) {
        $info = Get-VisualCRedistributableInfo -Year $year
        $params = @{
            TestName      = $info.DisplayName.Replace("*", "")
            Details       = "Visual C++ $year Redistributable"
            ReferenceInfo = $info.DownloadUrl
        }

        if (-not (Test-VisualCRedistributableUpToDate -Year $year -Installed $installed)) {
            New-TestResult @params -Result "Failed"
        } else {
            New-TestResult @params -Result "Passed"
        }
    }
}
