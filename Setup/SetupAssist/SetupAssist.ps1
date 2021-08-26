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
. $PSScriptRoot\Checks\UserContext\Test-UserGroupMemberOf.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExecutionPolicy.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExchangeServices.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MissingDirectory.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MsiCacheFiles.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PendingReboot.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PrerequisiteInstalled.ps1
. $PSScriptRoot\Checks\Test-FullLanguageMode.ps1
. $PSScriptRoot\..\..\Shared\Out-Columns.ps1


Function RunAllTests {
    Test-UserGroupMemberOf
    Test-ExecutionPolicy
    Test-ExchangeServices
    Test-ComputersContainerExists
    Test-DomainControllerDnsHostName
    Test-MissingDirectory
    Test-MsiCacheFiles
    Test-PrerequisiteInstalled
    Test-ReadOnlyDomainControllerLocation
    Test-OtherWellKnownObjects
    Test-ExchangeADSetupLevel
    Test-PendingReboot
    Test-ValidHomeMDB
}

Function Main {

    $results = RunAllTests

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

    #TODO: Clean this up later
    $quickResults = $results | Group-Object TestName |
        ForEach-Object {
            $result = $_.Group.Result | Where-Object { $_ -ne "Passed" } | Select-Object -First 1
            if ([string]::IsNullOrEmpty($result)) { $result = "Passed" }
            $params = @{
                TestName = $_.Name
                Result   = $result
                Details  = $_.Group.Details | Where-Object { if (-not([string]::IsNullOrEmpty($_))) { return $_ } } | Select-Object -First 1
            }
            New-TestResult @params
        }
    $quickResults | Out-Columns -Properties @("TestName", "Result", "Details") -ColorizerFunctions $sbResults

    Write-Host ""
    Write-Host "Results That Didn't Pass"
    $results | Where-Object { $_.Result -ne "Passed" } | Out-Columns -Properties @("TestName", "Details", "ReferenceInfo")
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
