#################################################################################
# Purpose:
# This script will allow you to test VSS functionality on Exchange server using DiskShadow.
# The script will automatically detect active and passive database copies running on the server.
# The general logic is:
# - start a PowerShell transcript
# - enable ExTRA tracing
# - enable VSS tracing
# - optionally: create the diskshadow config file with shadow expose enabled,
#               execute VSS backup using diskshadow,
#               delete the VSS snapshot post-backup
# - stop PowerShell transcript
#
#################################################################################
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'Allowing empty catch blocks for now as we need to be able to handle the exceptions.')]
[CmdletBinding()]
param(
)

. .\extern\Confirm-ExchangeShell.ps1
. .\extern\Write-HostWriter.ps1
. .\extern\Write-VerboseWriter.ps1
. .\DiskShadow\Invoke-CreateDiskShadowFile.ps1
. .\DiskShadow\Invoke-DiskShadow.ps1
. .\DiskShadow\Invoke-RemoveExposedDrives.ps1
. .\ExchangeInformation\Get-CopyStatus.ps1
. .\ExchangeInformation\Get-Databases.ps1
. .\ExchangeInformation\Get-DbToBackup.ps1
. .\ExchangeInformation\Get-ExchangeVersion.ps1
. .\Logging\Get-WindowsEventLogs.ps1
. .\Logging\Get-VSSWritersAfter.ps1
. .\Logging\Get-VSSWritersBefore.ps1
. .\Logging\Invoke-CreateExtraTracingConfig.ps1
. .\Logging\Invoke-DisableDiagnosticsLogging.ps1
. .\Logging\Invoke-DisableExtraTracing.ps1
. .\Logging\Invoke-DisableVSSTracing.ps1
. .\Logging\Invoke-EnableDiagnosticsLogging.ps1
. .\Logging\Invoke-EnableExtraTracing.ps1
. .\Logging\Invoke-EnableVSSTracing.ps1

Function Main {

    # if a transcript is running, we need to stop it as this script will start its own
    try {
        Stop-Transcript | Out-Null
    } catch [System.InvalidOperationException] { }

    Write-Host "****************************************************************************************"
    Write-Host "****************************************************************************************"
    Write-Host "**                                                                                    **" -BackgroundColor DarkMagenta
    Write-Host "**                 VSSTESTER SCRIPT (for Exchange 2013, 2016, 2019)                   **" -ForegroundColor Cyan -BackgroundColor DarkMagenta
    Write-Host "**                                                                                    **" -BackgroundColor DarkMagenta
    Write-Host "****************************************************************************************"
    Write-Host "****************************************************************************************"

    $Script:LocalExchangeShell = Confirm-ExchangeShell

    if (!$Script:LocalExchangeShell.ShellLoaded) {
        Write-Host "Failed to load Exchange Shell. Stopping the script."
        exit
    }

    if ($Script:LocalExchangeShell.RemoteShell -or
        $Script:LocalExchangeShell.ToolsOnly) {
        Write-Host "Can't run this script from a non Exchange Server."
        exit
    }

    #newLine shortcut
    $script:nl = "`r`n"
    $nl

    $script:serverName = $env:COMPUTERNAME

    #start time
    $Script:startInfo = Get-Date
    Get-Date

    if ($DebugPreference -ne 'SilentlyContinue') {
        $nl
        Write-Host 'This script is running in DEBUG mode since $DebugPreference is not set to SilentlyContinue.' -ForegroundColor Red
    }

    $nl
    Write-Host "Please select the operation you would like to perform from the following options:" -ForegroundColor Green
    $nl
    Write-Host "  1. " -ForegroundColor Yellow -NoNewline; Write-Host "Test backup using built-in Diskshadow"
    Write-Host "  2. " -ForegroundColor Yellow -NoNewline; Write-Host "Enable logging to troubleshoot backup issues"
    $nl

    $matchCondition = "^[1|2]$"
    Write-Debug "matchCondition: $matchCondition"
    Do {
        Write-Host "Selection: " -ForegroundColor Yellow -NoNewline;
        $Selection = Read-Host
        if ($Selection -notmatch $matchCondition) {
            Write-Host "Error! Please select a valid option!" -ForegroundColor Red
        }
    }
    while ($Selection -notmatch $matchCondition)


    try {

        $nl
        Write-Host "Please specify a directory other than root of a volume to save the configuration and output files." -ForegroundColor Green

        $pathExists = $false

        # get path, ensuring it exists
        do {
            Write-Host "Directory path (e.g. C:\temp): " -ForegroundColor Yellow -NoNewline
            $script:path = Read-Host
            Write-Debug "path: $path"
            try {
                $pathExists = Test-Path -Path "$path"
            } catch { }
            Write-Debug "pathExists: $pathExists"
            if ($pathExists -ne $true) {
                Write-Host "Error! The path does not exist. Please enter a valid path." -ForegroundColor red
            }
        } while ($pathExists -ne $true)

        $nl
        Get-Date
        Write-Host "Starting transcript..." -ForegroundColor Green $nl
        Write-Host "--------------------------------------------------------------------------------------------------------------"

        Start-Transcript -Path "$($script:path)\vssTranscript.log"
        $nl

        if ($Selection -eq 1) {
            Get-ExchangeVersion
            Get-VSSWritersBefore
            Get-Databases
            Get-DBtoBackup
            Get-CopyStatus
            Invoke-CreateDiskShadowFile #---
            Invoke-EnableDiagnosticsLogging
            Invoke-EnableVSSTracing
            Invoke-CreateExTRATracingConfig
            Invoke-EnableExTRATracing
            Invoke-DiskShadow #---
            Get-VSSWritersAfter
            Invoke-RemoveExposedDrives #---
            Invoke-DisableExTRATracing
            Invoke-DisableDiagnosticsLogging
            Invoke-DisableVSSTracing
            Get-WindowsEventLogs
        } elseif ($Selection -eq 2) {
            Get-ExchangeVersion
            Get-VSSWritersBefore
            Get-Databases
            Get-DBtoBackup
            Get-CopyStatus
            Invoke-EnableDiagnosticsLogging
            Invoke-EnableVSSTracing
            Invoke-CreateExTRATracingConfig
            Invoke-EnableExTRATracing

            #Here is where we wait for the end user to perform the backup using the backup software and then come back to the script to press "Enter", thereby stopping data collection
            Get-Date
            Write-Host "Data Collection" -ForegroundColor green $nl
            Write-Host "--------------------------------------------------------------------------------------------------------------"
            " "
            Write-Host "Data collection is now enabled." -ForegroundColor Yellow
            Write-Host "Please start your backup using the third party software so the script can record the diagnostic data." -ForegroundColor Yellow
            Write-Host "When the backup is COMPLETE, use the <Enter> key to terminate data collection..." -ForegroundColor Yellow -NoNewline
            Read-Host

            Invoke-DisableExTRATracing
            Invoke-DisableDiagnosticsLogging
            Invoke-DisableVSSTracing
            Get-VSSWritersAfter
            Get-WindowsEventLogs
        }
    } finally {
        # always stop our transcript at end of script's execution
        # we catch a failure here if we try to stop a transcript that's not running
        try {
            " " + $nl
            Get-Date
            Write-Host "Stopping transcript log..." -ForegroundColor Green $nl
            Write-Host "--------------------------------------------------------------------------------------------------------------"
            " "
            Stop-Transcript
            " " + $nl
            do {
                Write-Host
                $continue = Read-Host "Please use the <Enter> key to exit..."
            }
            While ($null -notmatch $continue)
            exit
        } catch { }
    }
}

try {
    Clear-Host
    Main
} catch { } finally { }