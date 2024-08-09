# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\SetupLogReviewerFunctions.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-DelegatedInstallerHasProperRights.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-ExpiredCertificate.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-InvalidWKObjectTargetException.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-IsHybridObjectFoundOnPremises.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-KnownIssuesByErrors.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-KnownLdifErrors.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-KnownMsiIssuesCheck.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-OtherWellKnownObjects.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-PrerequisiteCheck.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Test-SharedConfigDc.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\FindContext\Write-LastErrorInformation.ps1
. $PSScriptRoot\..\SetupLogReviewer\Checks\Write-Result.ps1
function Invoke-SetupLogReviewer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
            Position = 0)]
        [System.IO.FileInfo]$SetupLog,
        [switch]$DelegatedSetup
    )
    function InvokeTests {
        [CmdletBinding()]
        param(
            [object]$SetupLogReviewer,
            [string[]]$Tests
        )

        foreach ($test in $Tests) {
            $result = $SetupLogReviewer | & $test

            if ($null -ne $result) {
                $result | Write-Result
                break
            }
        }
    }

    if (-not ([IO.File]::Exists($SetupLog))) {
        Write-Error "Could not find file: $SetupLog"
        return
    }

    $setupLogReviewer = Get-SetupLogReviewer -SetupLog $SetupLog
    $color = "Gray"
    $ranDate = $setupLogReviewer.SetupRunDate

    if ($ranDate -lt ([DateTime]::Now.AddDays(-14))) { $color = "Yellow" }
    Write-Host "Setup Mode: $($setupLogReviewer.SetupMode)"
    Write-Host "Setup.exe Run Date: $ranDate" -ForegroundColor $color
    Write-Host "Setup.exe Build Number: $($setupLogReviewer.SetupBuildNumber)"

    if (-not ([string]::IsNullOrEmpty($setupLogReviewer.LocalBuildNumber))) {
        Write-Host "Current Exchange Build: $($setupLogReviewer.LocalBuildNumber)"

        try {
            $localBuild = New-Object System.Version $setupLogReviewer.LocalBuildNumber -ErrorAction Stop
            $setupBuild = New-Object System.Version $setupLogReviewer.SetupBuildNumber -ErrorAction Stop

            if (($localBuild -eq $setupBuild -or
                ($localBuild.Minor -eq $setupBuild.Minor -and
                    $localBuild.Build -eq $setupBuild.Build)) -and
                ($setupLogReviewer.SetupMode -ne "Install")) {
                Write-Host "Same build number detected..... if using powershell.exe to start setup. Make sure you do '.\setup.exe'" -ForegroundColor "Red"
            }
        } catch {
            Write-Verbose "Failed to convert to System.Version"
        }
    }

    $successFullInstall = $setupLogReviewer | SelectStringLastRunOfExchangeSetup -Pattern "The Exchange Server setup operation completed successfully\."

    if ($null -ne $successFullInstall) {
        Write-Host "The most recent setup attempt completed successfully based off this line:"
        Write-Host $successFullInstall.Line
        Write-Host "`r`nNo Action is required."
        return
    }

    if ($DelegatedSetup) {
        $setupLogReviewer | Test-DelegatedInstallerHasProperRights
        return
    }

    InvokeTests -SetupLogReviewer $setupLogReviewer -Tests @(
        "Test-PrerequisiteCheck",
        "Test-KnownLdifErrors",
        "Test-KnownMsiIssuesCheck",
        "Test-KnownIssuesByErrors",
        "Test-ExpiredCertificate",
        "Test-OtherWellKnownObjects",
        "Test-IsHybridObjectFoundOnPremises",
        "Test-InvalidWKObjectTargetException",
        "Test-SharedConfigDc",
        "Write-LastErrorInformation"
    )
}
