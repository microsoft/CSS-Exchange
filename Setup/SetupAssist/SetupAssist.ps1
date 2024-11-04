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
. $PSScriptRoot\Checks\Domain\Test-ValidMailboxProperties.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExecutionPolicy.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExchangeServices.ps1
. $PSScriptRoot\Checks\LocalServer\Test-InstallWatermark.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MissingDirectory.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MsiCacheFiles.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PendingReboot.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PrerequisiteInstalled.ps1
. $PSScriptRoot\Checks\LocalServer\Test-VirtualDirectoryConfiguration.ps1
. $PSScriptRoot\Checks\UserContext\Test-UserIsAdministrator.ps1
. $PSScriptRoot\..\Shared\SetupLogReviewerLogic.ps1
. $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\Shared\Write-ErrorInformation.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Warning.ps1
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\WriteFunctions.ps1

$BuildVersion = ""

function WriteCatchInfo {
    Write-HostErrorInformation $Error[0]
    $Script:ErrorOccurred = $true
}

function RunAllTests {
    $tests = @("Test-UserIsAdministrator",
        "Test-ExchangeADSetupLevel",
        "Test-ExecutionPolicy",
        "Test-ExchangeServices",
        "Test-ComputersContainerExists",
        "Test-DomainControllerDnsHostName",
        "Test-DomainMultiActiveSyncVirtualDirectories",
        "Test-InstallWatermark",
        "Test-MissingDirectory",
        "Test-MsiCacheFiles",
        "Test-PrerequisiteInstalled",
        "Test-DomainOtherWellKnownObjects",
        "Test-PendingReboot",
        "Test-ValidMailboxProperties",
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

function Main {

    $results = RunAllTests
    $exportObject = New-Object 'System.Collections.Generic.List[object]'

    $results |
        ForEach-Object {
            $exportObject.Add([PSCustomObject]@{
                    TestName      = $_.TestName
                    Result        = $_.Result
                    Details       = $_.Details | Out-String
                    ReferenceInfo = $_.ReferenceInfo | Out-String
                })
        }

    $exportObject | Export-Csv "$PSScriptRoot\SetupAssistResults-$((Get-Date).ToString("yyyyMMddhhmm")).csv" -NoTypeInformation

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
    $setupLog = "$env:SystemDrive\ExchangeSetupLogs\ExchangeSetup.log"
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

    $instance = (Get-Date).ToString("yyyyMMddhhmmss")
    $Script:DebugLogger = Get-NewLoggerInstance -LogName "SetupAssist-$instance-Debug" `
        -AppendDateTimeToFileName $false `
        -ErrorAction SilentlyContinue
    $Script:HostLogger = Get-NewLoggerInstance -LogName "SetupAssist-$instance" `
        -AppendDateTimeToFileName $false `
        -ErrorAction SilentlyContinue
    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteVerboseAction ${Function:Write-DebugLog}
    SetWriteWarningAction ${Function:Write-DebugLog}

    if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/SA-VersionsUrl")) {
        Write-Host "Script was updated. Please rerun the script."
        return
    }

    Write-Host "Setup Assist Version $BuildVersion"

    Main
} catch {
    Write-Host "Failed in Main"
    WriteCatchInfo
} finally {
    if ($Script:ErrorOccurred) {
        Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing including the SetupAssist-Debug.txt file.")
    }

    Write-Host("Do you like the script? Visit https://aka.ms/ExchangeSetupAssist-Feedback to rate it and to provide feedback.") -ForegroundColor Green

    if ((-not ($Script:ErrorOccurred)) -and
        (-not ($PSBoundParameters["Verbose"]))) {
        $Script:DebugLogger | Invoke-LoggerInstanceCleanup
    }
}
