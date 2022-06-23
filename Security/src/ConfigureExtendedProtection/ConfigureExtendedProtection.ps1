# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    This script enables extended protection on all Exchange servers in the forest.
.DESCRIPTION
    The Script does the following by default.
        1. Enables Extended Protection to the recommended value for the corresponding virtual directory and site.
    Extended Protection is a windows security feature which blocks MiTM attacks.
.PARAMETER Rollback
    If set then the script execution will Rollback the applicationHost.config file to the original state that was backed up with the script.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1
    This will run the default mode which does the following:
        1. It will set Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers in the forest.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -ExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers provided in ExchangeServerNames
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -SkipExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers in the forest except the Exchange Servers whose names are provided in the SkipExchangeServerNames parameter.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -Rollback
    This will set the applicationHost.config file back to the original state prior to changes made with this script.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter (Mandatory = $false, HelpMessage = "Enter the list of server names on which the script should execute on")]
    [string[]]$ExchangeServerNames = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [string[]]$SkipExchangeServerNames = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Use this switch to Enable require SSL flag across all IIS vdirs which don't have it enabled by default.")]
    [switch]$EnforceSSL,
    [Parameter (Mandatory = $false, ParameterSetName = 'Rollback', HelpMessage = "Use this switch to set the ExtendedProtection value on VDirs in 'Default Web Site' and 'Exchange Back End' to 'None'")]
    [switch]$Rollback
)

. $PSScriptRoot\Write-Verbose.ps1
. $PSScriptRoot\WriteFunctions.ps1
. $PSScriptRoot\ConfigurationAction\Configure-ExtendedProtection.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Write-Host.ps1


$Script:Logger = Get-NewLoggerInstance -LogName "ConfigureExtendedProtection-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" `
    -AppendDateTimeToFileName $false `
    -ErrorAction SilentlyContinue

SetWriteHostAction ${Function:Write-HostLog}


$BuildVersion = ""
Write-Host "Version $BuildVersion"

if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/CEP-VersionsUrl")) {
    Write-Warning "Script was updated. Please rerun the command."
    return
}

Write-Verbose ("Running Get-ExchangeServer to get list of all exchange servers")
Set-ADServerSettings -ViewEntireForest $true
$ExchangeServers = Get-ExchangeServer | Where-Object { $_.AdminDisplayVersion -like "Version 15*" -and $_.ServerRole -ne "Edge" }

if ($null -ne $ExchangeServerNames -and $ExchangeServerNames.Count -gt 0) {
    Write-Verbose "Running only on servers: $([string]::Join(", " ,$ExchangeServerNames))"
    $ExchangeServers = $ExchangeServers | Where-Object { $_.Name -in $ExchangeServerNames }
}

if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
    Write-Verbose "Skipping servers: $([string]::Join(", ", $SkipExchangeServerNames))"

    # Remove all the servers present in the SkipExchangeServerNames list
    $ExchangeServers = $ExchangeServers | Where-Object { $_.Name -notin $SkipExchangeServerNames }
}

# Configure Extended Protection based on given parameters
Configure-ExtendedProtection
