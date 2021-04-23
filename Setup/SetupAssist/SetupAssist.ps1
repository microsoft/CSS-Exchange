# SetupAssist.ps1 is used for running on the Exchange Server that we are wanting to install or upgrade.
# We validate common prerequisites that or overlooked and look at AD to make sure it is able to upgrade
#
# TODO: Add AD Object Permissions check
#
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameter is used')]
[CmdletBinding()]
param(
    [switch]$OtherWellKnownObjects
)

. .\Checks\Confirm-VirtualDirectoryConfiguration.ps1
. .\Checks\Test-CriticalService.ps1
. .\Checks\Test-ExchangeAdLevel.ps1
. .\Checks\Test-MissingDirectory.ps1
. .\Checks\Test-MissingMsiFiles.ps1
. .\Checks\Test-OtherWellKnownObjects.ps1
. .\Checks\Test-PendingReboot.ps1
. $PSScriptRoot\Checks\Test-PrerequisiteInstalled.ps1
. .\Checks\Test-UserGroupMemberOf.ps1
. .\Checks\Test-ValidHomeMdb.ps1
. .\Utils\ConvertFrom-Ldif.ps1

#Local Shared
. $PSScriptRoot\..\Shared\Get-FileInformation.ps1
. $PSScriptRoot\..\Shared\Get-InstallerPackages.ps1
. $PSScriptRoot\..\Shared\New-SetupLogReviewer.ps1

#REPO Shared
. $PSScriptRoot\..\..\Shared\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\Get-NETFrameworkVersion.ps1
. $PSScriptRoot\..\..\Shared\Get-VisualCRedistributableVersion.ps1

#REPO Shared Dependencies
. $PSScriptRoot\..\..\Shared\Get-RemoteRegistrySubKey.ps1
. $PSScriptRoot\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\..\Shared\Invoke-ScriptBlockHandler.ps1

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

Function Main {

    if ($OtherWellKnownObjects) {
        Test-OtherWellKnownObjects
    } else {
        MainUse
    }
}

try {
    Out-File -FilePath $Script:ScriptLogging -Force | Out-Null
    Receive-Output "Starting Script At: $([DateTime]::Now)" -Diagnostic
    Receive-Output "Test Latest Script Version" -Diagnostic

    if (Test-ScriptVersion -AutoUpdate) {
        Receive-Output "Script was updated. Please rerun the command."
        return
    }

    Main
    Receive-Output "Finished Script At: $([DateTime]::Now)" -Diagnostic
    Write-Output "File Written at: $Script:ScriptLogging"
} catch {
    Receive-Output "$($_.Exception)"
    Receive-Output "$($_.ScriptStackTrace)"
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}
