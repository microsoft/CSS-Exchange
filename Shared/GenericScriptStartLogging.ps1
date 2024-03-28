# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    This file is designed to inline code that we use to start the scripts and handle the logging.
#>

. $PSScriptRoot\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\OutputOverrides\Write-Progress.ps1
. $PSScriptRoot\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\OutputOverrides\Write-Warning.ps1
. $PSScriptRoot\Confirm-Administrator.ps1
. $PSScriptRoot\LoggerFunctions.ps1
. $PSScriptRoot\Show-Disclaimer.ps1

function Write-DebugLog ($Message) {
    $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $Message
}

function Write-HostLogAndDebugLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
    Write-DebugLog $Message
}

$Script:DebugLogger = Get-NewLoggerInstance -LogName "$($script:MyInvocation.MyCommand.Name)-Debug"

SetWriteVerboseAction ${Function:Write-DebugLog}
SetWriteProgressAction ${Function:Write-DebugLog}
SetWriteWarningAction ${Function:Write-DebugLog}

# Dual Logging is for when you have a secondary file designed for debug logic and one that is simplified for everything that was displayed to the screen.
Write-Verbose "Dual Logging $(if(-not ($Script:DualLoggingEnabled)){ "NOT "})Enabled."
if ($Script:DualLoggingEnabled) {
    $params = @{
        LogName                  = ([System.IO.Path]::GetFileNameWithoutExtension($Script:DebugLogger.FullPath).Replace("-Debug", ""))
        AppendDateTime           = $false
        AppendDateTimeToFileName = $false
    }
    $Script:Logger = Get-NewLoggerInstance @params
    SetWriteHostAction ${Function:Write-HostLogAndDebugLog}
} else {
    SetWriteHostAction ${Write-DebugLog}
}

if (-not(Confirm-Administrator)) {
    Write-Host "The script needs to be executed in elevated mode. Start the PowerShell as an administrator." -ForegroundColor Yellow
    exit
}
