# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# SetupAssist.ps1 is used for running on the Exchange Server that we are wanting to install or upgrade.
# We validate common prerequisites that or overlooked and look at AD to make sure it is able to upgrade
#
# TODO: Add AD Object Permissions check
#
[CmdletBinding()]
param(
    [switch]$OtherWellKnownObjects
)

. $PSScriptRoot\Checks\Domain\Test-ComputersContainerExists.ps1
. $PSScriptRoot\Checks\Domain\Test-DomainControllerDnsHostName.ps1
. $PSScriptRoot\Checks\Domain\Test-ExchangeADSetupLevel.ps1
. $PSScriptRoot\Checks\Domain\Test-OtherWellKnownObjects.ps1
. $PSScriptRoot\Checks\Domain\Test-ReadOnlyDomainControllerLocation.ps1
. $PSScriptRoot\Checks\Domain\Test-ValidHomeMdb.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExecutionPolicy.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExchangeServices.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MissingDirectory.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MsiCacheFiles.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PendingReboot.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PrerequisiteInstalled.ps1
. $PSScriptRoot\Checks\LocalServer\Test-VirtualDirectoryConfiguration.ps1
. $PSScriptRoot\..\..\Shared\Out-Columns.ps1


Function RunAllTests {
    Test-ExchangeADSetupLevel
    Test-ExecutionPolicy
    Test-ExchangeServices
    Test-ComputersContainerExists
    Test-DomainControllerDnsHostName
    Test-MissingDirectory
    Test-MsiCacheFiles
    Test-PrerequisiteInstalled
    Test-ReadOnlyDomainControllerLocation
    Test-OtherWellKnownObjects
    Test-PendingReboot
    Test-ValidHomeMDB
    Test-VirtualDirectoryConfiguration
}

Function Main {

    $results = RunAllTests
    $results | Export-Csv "$PSScriptRoot\SetupAssistResults-$((Get-Date).ToString("yyyyMMddhhmm")).csv" -NoTypeInformation

    $sbResults = {
        param($o, $p)

        if ($p -eq "Result") {
            if ($o."$p" -eq "Failed") {
                "Red"
            } elseif ($o."$p" -eq "Warning") {
                "Yellow"
            } else {
                "Green"
            }
        }
    }

    #TODO: Add check for log reviewer check that was there
    $quickResults = $results | Group-Object TestName |
        ForEach-Object {
            $result = $_.Group.Result | Where-Object { $_ -ne "Passed" } | Select-Object -First 1

            if ($_.Group.Count -gt 1) {
                $details = [string]::Empty
            } else {
                $details = $_.Group.Details
            }
            if ([string]::IsNullOrEmpty($result)) { $result = "Passed" }
            $params = @{
                TestName = $_.Name
                Result   = $result
                Details  = $details
            }
            New-TestResult @params
        }
    $quickResults | Out-Columns -Properties @("TestName", "Result", "Details") -ColorizerFunctions $sbResults

    Write-Host ""
    Write-Host "-----Results That Didn't Pass-----"
    Write-Host ""
    $failedResultGroups = $results | Where-Object { $_.Result -ne "Passed" } | Group-Object TestName
    $failedResultGroups | ForEach-Object {
        [PSCustomObject]@{
            TestName      = $_.Name
            Details       = $_.Group.Details
            ReferenceInfo = $_.Group.ReferenceInfo | Select-Object -Unique
        }
    } | Out-Columns -IndentSpaces 5 -LinesBetweenObjects 2
}

try {
    if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
        Write-Error "PowerShell is not in FullLanguage mode. Exchange Setup requires FullLanguage mode. The SetupAssist script also requires it. Cannot continue."
        return
    }

    Main
} catch {
    "$($_.Exception)" | Write-Output
    "$($_.ScriptStackTrace)" | Write-Output
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}

