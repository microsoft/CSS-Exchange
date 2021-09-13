# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This script reviews the ExchangeSetup.log and determines if it is a known issue and reports an
# action to take to resolve the issue.
#
# Use the DelegateSetup switch if the log is from a Delegated Setup and you are running into a Prerequisite Check issue
#
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true,
        Position = 0)]
    [System.IO.FileInfo]$SetupLog,
    [switch]$DelegatedSetup
)

. $PSScriptRoot\..\Shared\SetupLogReviewerFunctions.ps1
. $PSScriptRoot\Checks\Test-KnownIssuesByErrors.ps1
. $PSScriptRoot\Checks\Test-KnownLdifErrors.ps1
. $PSScriptRoot\Checks\Test-KnownMsiIssuesCheck.ps1
. $PSScriptRoot\Checks\Test-KnownOrganizationPreparationErrors.ps1
. $PSScriptRoot\Checks\Test-PrerequisiteCheck.ps1
. $PSScriptRoot\Checks\Write-LastErrorInformation.ps1
. $PSScriptRoot\Checks\Write-Result.ps1

Function InvokeTests {
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

Function Main {

    if (-not ([IO.File]::Exists($SetupLog))) {
        Write-Error "Could not find file: $SetupLog"
        return
    }

    $setupLogReviewer = Get-SetupLogReviewer -SetupLog $SetupLog
    $color = "Gray"
    $ranDate = $setupLogReviewer.SetupRunDate

    if ($ranDate -lt ([DateTime]::Now.AddDays(-14))) { $color = "Yellow" }
    Write-Host "Setup.exe Run Date: $ranDate" -ForegroundColor $color
    Write-Host "Setup.exe Build Number: $($setupLogReviewer.SetupBuildNumber)"

    if (-not ([string]::IsNullOrEmpty($setupLogReviewer.LocalBuildNumber))) {
        Write-Host "Current Exchange Build: $($setupLogReviewer.LocalBuildNumber)"

        if ($setupLogReviewer.LocalBuildNumber -eq $setupLogReviewer.SetupBuildNumber) {
            Write-Host "Same build number detected..... if using powershell.exe to start setup. Make sure you do '.\setup.exe'" -ForegroundColor "Red"
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
        "Test-KnownOrganizationPreparationErrors",
        "Test-KnownMsiIssuesCheck",
        "Test-KnownIssuesByErrors",
        "Write-LastErrorInformation"
    )
}

try {
    Main
} catch {
    "$($Error[0].Exception)" | Write-Output
    "$($Error[0].ScriptStackTrace)" | Write-Output
    Write-Warning ("Ran into an issue with the script. If possible please email the Setup Log to 'ExToolsFeedback@microsoft.com', or at least notify them of the issue.")
}
