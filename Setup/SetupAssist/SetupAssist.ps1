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
. $PSScriptRoot\Checks\UserContext\Test-UserGroupMemberOf.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExecutionPolicy.ps1
. $PSScriptRoot\Checks\LocalServer\Test-ExchangeServices.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MissingDirectory.ps1
. $PSScriptRoot\Checks\LocalServer\Test-MsiCacheFiles.ps1
. $PSScriptRoot\Checks\LocalServer\Test-PrerequisiteInstalled.ps1
. $PSScriptRoot\Checks\Test-FullLanguageMode.ps1
. $PSScriptRoot\..\..\Shared\Out-Columns.ps1

$Script:ScriptLogging = "$PSScriptRoot\SetupAssist_$(([DateTime]::Now).ToString('yyyyMMddhhmmss')).log"

Function Write-LogInformation {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [bool]$VerboseEnabled = $VerbosePreference
    )

    process {

        if ($VerboseEnabled) {
            $Object | Write-Verbose -Verbose
        }

        $Object | Out-File -FilePath $Script:ScriptLogging -Append
    }
}

Function Receive-Output {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [switch]$Diagnostic,
        [switch]$IsWarning,
        [switch]$IsError
    )

    process {

        if (($Diagnostic -and
                $VerbosePreference) -or
            (-not $Diagnostic -and
                -not $IsWarning -and
                -not $IsError)) {
            $Object | Write-Output
        } elseif ($IsWarning) {
            $Object | Write-Warning
        } elseif ($IsError) {
            $Object | Write-Error
        } else {
            $Object | Write-Verbose
        }

        Write-LogInformation $Object -VerboseEnabled $false
    }
}

function IsAdministrator {
    $ident = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object System.Security.Principal.WindowsPrincipal($ident)
    return $prin.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function MainUse {

    if (IsAdministrator) {
        "User is an administrator." | Receive-Output
    } else {
        "User is not an administrator." | Receive-Output -IsWarning
    }

    Test-UserGroupMemberOf
    Test-MissingMsiFiles
    Test-PrerequisiteInstalled

    $powershellProcesses = @(Get-Process -IncludeUserName powershell)

    if ($powershellProcesses.Count -gt 1) {
        "More than one PowerShell process was found. Please close other instances of PowerShell." | Receive-Output -IsWarning
        $powershellProcesses | Format-Table -AutoSize | Out-String | Receive-Output
    } else {
        "No other PowerShell instances were detected." | Receive-Output
    }

    if (Test-PendingReboot) {
        "Reboot pending." | Receive-Output -IsWarning
    } else {
        "No reboot pending." | Receive-Output
    }

    Test-CriticalService
    Test-ValidHomeMDB
    Test-MissingDirectory
    Test-ExchangeAdSetupObjects
    Test-ComputersContainerExists
    Test-DomainControllerDnsHostName
    Test-ReadOnlyDomainControllerLocation
    Confirm-VirtualDirectoryConfiguration

    $exSetupLog = "$($env:HOMEDRIVE)\ExchangeSetupLogs\ExchangeSetup.log"

    if ((Test-Path $exSetupLog)) {

        try {
            $setupLogReviewer = New-SetupLogReviewer -SetupLog $exSetupLog
            $successFullInstall = $setupLogReviewer.SelectStringLastRunOfExchangeSetup("The Exchange Server setup operation completed successfully\.")
            "Setup Last Run: $($setupLogReviewer.SetupRunDate)" | Receive-Output
            "Setup Build: $($setupLogReviewer.SetupBuildNumber)" | Receive-Output

            if ($null -ne $successFullInstall) {
                "Last Setup Run Appears Successful" | Receive-Output
            } else {
                "Last Setup Run Appears to have Failed" | Receive-Output -IsWarning
                "" | Receive-Output
                "Try to run SetupLogReviewer.ps1 again the script to determine a possible action plan: https://microsoft.github.io/CSS-Exchange/Setup/SetupLogReviewer/" | Receive-Output
                "If not a known issue, please include the following to support:" | Receive-Output
                "`t - $exSetupLog" | Receive-Output

                $logs = @(
                    "$($env:HOMEDRIVE)\ExchangeSetupLogs\PatchVerboseLogging.log",
                    "$($env:HOMEDRIVE)\ExchangeSetupLogs\ServiceControl.log",
                    "$($env:HOMEDRIVE)\ExchangeSetupLogs\UpdateCas.log",
                    "$($env:HOMEDRIVE)\ExchangeSetupLogs\UpdateConfigFile.log"
                )

                foreach ($log in $logs) {

                    if ((Test-Path $log)) {
                        "`t - $log" | Receive-Output
                    }
                }

                "`t - $Script:ScriptLogging" | Receive-Output
            }
        } catch {
            "Failed to determine state of the Setup Log" | Receive-Output
            "$($_.Exception)" | Receive-Output
            "$($_.ScriptStackTrace)" | Receive-Output
        }
    } else {
        "Failed to find Exchange Setup Log" | Receive-Output
    }
}

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
}

Function Main {

    $results = RunAllTests

    $sbResults = {
        param($r)

        if ($r -eq "Failed") {
            "Red"
        } elseif ($r -eq "Passed") {
            "Green"
        } else {
            "Yellow"
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
    $quickResults | Out-Columns -Properties @("TestName", "Result", "Details") -ColorizerFunctions @($null, $sbResults, $null)

    Write-Host ""
    Write-Host "Results That Didn't Pass"
    $results | Where-Object { $_.Result -ne "Passed" } | Out-Columns -Properties @("TestName", "Details", "ReferenceInfo") @($null, { "yellow" }, { "yellow" })

    <#
    if ($OtherWellKnownObjects) {
        Test-OtherWellKnownObjects
    } else {
        MainUse
    }
#>
}

try {
    if (-not (Test-FullLanguageMode)) {
        return
    }

    Main
} catch {
    Receive-Output "$($_.Exception)"
    Receive-Output "$($_.ScriptStackTrace)"
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}
