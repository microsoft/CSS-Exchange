# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\..\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
. $PSScriptRoot\..\New-TestResult.ps1
function Test-PrerequisiteInstalled {
    [CmdletBinding()]
    param()
    begin {
        $result = "Passed"
        $context = [string]::Empty
        #TODO: add context for failed stuff
    }
    process {
        $netVersion = Get-NETFrameworkVersion

        if ($netVersion.MinimumValue -lt 528040) {
            $result = "Failed"
        }

        $installed = @(Get-VisualCRedistributableInstalledVersion)

        if (-not (Test-VisualCRedistributableUpToDate -Year 2012 -Installed $installed)) {
            $result = "Failed"
        }

        if (-not (Test-VisualCRedistributableUpToDate -Year 2013 -Installed $installed)) {
            $result = "Failed"
        }
    }
    end {
        $params = @{
            TestName          = "Prerequisites Installed"
            Result            = $result
            AdditionalContext = $context
            CustomData        = $null
        }

        return (New-TestResult @params)
    }
}
