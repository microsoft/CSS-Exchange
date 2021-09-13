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

    <#
    try {

        if (-not ([IO.File]::Exists($SetupLog))) {
            Write-Error "Could not find file: $SetupLog"
            return
        }

        $setupLogReviewer = New-SetupLogReviewer -SetupLog $SetupLog -ErrorAction Stop
        $runDate = $setupLogReviewer.SetupRunDate
        $color = "Gray"

        if ($runDate -lt ([datetime]::Now.AddDays(-14))) { $color = "Yellow" }
        $setupLogReviewer.ReceiveOutput("Setup.exe Run Date: $runDate", $color)
        $setupLogReviewer.ReceiveOutput("Setup.exe Build Number: $($setupLogReviewer.SetupBuildNumber)")

        if ($null -ne $setupLogReviewer.LocalBuildNumber) {
            Write-Output "Current Exchange Build: $($setupLogReviewer.LocalBuildNumber)"

            if ($setupLogReviewer.LocalBuildNumber -eq $setupLogReviewer.SetupBuildNumber) {
                $setupLogReviewer.ReceiveOutput("Same build number detected..... if using powershell.exe to start setup. Make sure you do '.\setup.exe'", "Red")
            }
        }

        if ($DelegatedSetup) {
            Get-DelegatedInstallerHasProperRights -SetupLogReviewer $setupLogReviewer
            return
        }

        $prerequisiteCheck = Test-PrerequisiteCheck -SetupLogReviewer $setupLogReviewer
        if ($setupLogReviewer.WriteTestObject(
                $prerequisiteCheck)) {

            Write-Output "`r`nAdditional Context:"
            Write-Output ("User Logged On: $($setupLogReviewer.User)")

            $serverFQDN = $setupLogReviewer.GetEvaluatedSettingOrRule("ComputerNameDnsFullyQualified", "Setting", ".")

            if ($null -ne $serverFQDN) {
                $serverFQDN = $serverFQDN.Matches.Groups[1].Value
                Write-Output "Setup Running on: $serverFQDN"
                $setupDomain = $serverFQDN.Split('.')[1]
                Write-Output "Setup Running in Domain: $setupDomain"
            }

            $siteName = $setupLogReviewer.GetEvaluatedSettingOrRule("SiteName", "Setting", ".")

            if ($null -ne $siteName) {
                $siteName = $siteName.Matches.Groups[1].Value
                Write-Output "Setup Running in AD Site Name: $siteName"
            }

            $schemaMaster = $setupLogReviewer.SelectStringLastRunOfExchangeSetup("Setup will attempt to use the Schema Master domain controller (.+)")

            if ($null -ne $schemaMaster) {
                Write-Output "----------------------------------"
                Write-Output "Schema Master: $($schemaMaster.Matches.Groups[1].Value)"
                $smDomain = $schemaMaster.Matches.Groups[1].Value.Split(".")[1]
                Write-Output "Schema Master in Domain: $smDomain"
                $schemaSiteName = [string]::Empty

                if ($null -ne $prerequisiteCheck.WriteWarning) {

                    $siteNameSls = $prerequisiteCheck.DisplayContext.Line | Select-String "on a computer in the domain (\w+) and site (.+)\, and wait for replication to complete"

                    if ($null -ne $siteNameSls) {
                        $schemaSiteName = $siteNameSls.Matches.Groups[2].Value
                        Write-Output "Schema Master in AD Site Name: $schemaSiteName"
                    }
                }

                if ($smDomain -ne $setupDomain) {
                    $setupLogReviewer.ReceiveOutput("Unable to run setup in current domain.", "Red")
                }

                if ($schemaSiteName -ne [string]::Empty -and
                    $schemaSiteName -ne $siteName) {
                    $setupLogReviewer.ReceiveOutput("Unable to run setup in the current AD Site", "Red")
                }
            }
            return
        }

        if ($setupLogReviewer.WriteTestObject(
                (Test-KnownLdifErrors -SetupLogReviewer $setupLogReviewer))) {
            return
        }

        if ($setupLogReviewer.WriteTestObject(
                (Test-KnownOrganizationPreparationErrors -SetupLogReviewer $setupLogReviewer))) {
            return
        }

        if ($setupLogReviewer.WriteTestObject(
                (Test-KnownIssuesByErrors -SetupLogReviewer $setupLogReviewer))) {
            return
        }

        if ($setupLogReviewer.WriteTestObject(
                (Test-KnownMsiIssuesCheck -SetupLogReviewer $setupLogReviewer))) {
            return
        }

        $successFullInstall = $setupLogReviewer.SelectStringLastRunOfExchangeSetup("The Exchange Server setup operation completed successfully\.")

        if ($null -ne $successFullInstall) {
            Write-Output "The most recent setup attempt completed successfully based off this line:"
            Write-Output $successFullInstall.Line
            Write-Output "`r`nNo Action is required."
            return
        }

        #Last Error Information
        $lastErrorInfo = $setupLogReviewer.FirstErrorWithContextToLine(-1, 30, 200)

        if ($null -ne $lastErrorInfo) {
            Write-Output "Failed to determine known cause, but here is your error context that we are seeing"
            $setupLogReviewer.WriteErrorContext($lastErrorInfo)
        }

        Write-Output "Looks like we weren't able to determine the cause of the issue with Setup. Please run SetupAssist.ps1 on the server." `
            "If that doesn't find the cause, please notify $($setupLogReviewer.FeedbackEmail) to help us improve the scripts."
    } catch {
        Write-Output "$($Error[0].Exception)"
        Write-Output "$($Error[0].ScriptStackTrace)"
        Write-Warning ("Ran into an issue with the script. If possible please email the Setup Log to 'ExToolsFeedback@microsoft.com', or at least notify them of the issue.")
    }
    #>
}

try {
    Main
} catch {
    "$($Error[0].Exception)" | Write-Output
    "$($Error[0].ScriptStackTrace)" | Write-Output
    Write-Warning ("Ran into an issue with the script. If possible please email the Setup Log to 'ExToolsFeedback@microsoft.com', or at least notify them of the issue.")
}
