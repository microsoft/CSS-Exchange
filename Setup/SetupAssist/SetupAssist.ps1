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
. $PSScriptRoot\Checks\Domain\Test-DomainMultiActiveSyncVirtualDirectories.ps1
. $PSScriptRoot\Checks\Domain\Test-ExchangeADSetupLevel.ps1
. $PSScriptRoot\Checks\Domain\Test-DomainOtherWellKnownObjects.ps1
. $PSScriptRoot\Checks\Domain\Test-ReadOnlyDomainControllerLocation.ps1
. $PSScriptRoot\Checks\Domain\Test-ValidHomeMdb.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExecutionPolicy.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExchangeServices.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MissingDirectory.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MsiCacheFiles.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PendingReboot.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PrerequisiteInstalled.ps1
. $PSScriptRoot\Checks\LocalServer\Test-VirtualDirectoryConfiguration.ps1
. $PSScriptRoot\..\Shared\SetupLogReviewerLogic.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\Shared\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\Write-Host.ps1
. $PSScriptRoot\WriteFunctions.ps1

Function WriteCatchInfo {
    Write-Host "$($Error[0].Exception)"
    Write-Host "$($Error[0].ScriptStackTrace)"
    $Script:ErrorOccurred = $true
}

Function RunAllTests {
    $tests = @("Test-ExchangeADSetupLevel",
        "Test-ExecutionPolicy",
        "Test-ExchangeServices",
        "Test-ComputersContainerExists",
        "Test-DomainControllerDnsHostName",
        "Test-DomainMultiActiveSyncVirtualDirectories",
        "Test-MissingDirectory",
        "Test-MsiCacheFiles",
        "Test-PrerequisiteInstalled",
        "Test-ReadOnlyDomainControllerLocation",
        "Test-DomainOtherWellKnownObjects",
        "Test-PendingReboot",
        "Test-ValidHomeMDB",
        "Test-VirtualDirectoryConfiguration")

    foreach ($test in $tests) {
        try {
            Write-Verbose "Working on test $test"
            & $test
        } catch {
            Write-Host "Failed to properly run $test"
            WriteCatchInfo
        }
    }
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
    $quickResults | Write-OutColumns -Properties @("TestName", "Result", "Details") -ColorizerFunctions $sbResults

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
    } | Write-OutColumns -IndentSpaces 5 -LinesBetweenObjects 2

    Write-Host ""
    Write-Host "Setup Log Reviewer Results"
    Write-Host "--------------------------"
    Write-Host ""
    $setupLog = "C:\ExchangeSetupLogs\ExchangeSetup.log"
    if ((Test-Path $setupLog)) {
        Invoke-SetupLogReviewer -SetupLog $SetupLog
    } else {
        Write-Host "No Exchange Setup Log to test against"
    }
}

try {
    if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
        Write-Error "PowerShell is not in FullLanguage mode. Exchange Setup requires FullLanguage mode. The SetupAssist script also requires it. Cannot continue."
        return
    }

    $Script:Logger = Get-NewLoggerInstance -LogName "SetupAssist-Debug" `
        -AppendDateTimeToFileName $false `
        -ErrorAction SilentlyContinue
    SetWriteHostAction ${Function:Write-DebugLog}

    if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/SA-VersionsUrl")) {
        Write-Host "Script was updated. Please rerun the script."
        return
    }

    Main
} catch {
    Write-Host "Failed in Main"
    WriteCatchInfo
} finally {
    if ($Script:ErrorOccurred) {
        Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing including the SetupAssist-Debug.txt file.")
    } elseif (-not ($PSBoundParameters["Verbose"])) {
        $Script:Logger | Invoke-LoggerInstanceCleanup
    }
}
