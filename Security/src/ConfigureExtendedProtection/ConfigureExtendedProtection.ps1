# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    This script enables extended protection on all Exchange servers in the forest.
.DESCRIPTION
    The Script does the following by default.
        1. Enables Extended Protection with the 'Require' flag on "Default Web Site" Vdirs and 'Require' on "Exchange Back End" Vdirs
        2. Stops and Disables the Print Spooler service
    Extended Protection is a windows security feature which blocks MiTM attacks.
.PARAMETER Rollback
    If set then the script execution will Rollback the Extended Protection back to 'None'.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1
    This will run the default mode which does the following:
        1. It will set Extended Protection as 'Require' on "Default Web Site" Vdirs on all the Exchange Servers.
        2. If will set Extended Protection as 'Require' on "Exchange Back End" Vdirs on all the Exchange Servers.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -ExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection on all 'Default Web Site' and 'Exchange Back End' Vdirs only on the Exchange Servers whose names are provided in the ExchangeServerNames parameter.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -SkipExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection on all 'Default Web Site' and 'Exchange Back End' Vdirs except the Exchange Servers whose names are provided in the SkipExchangeServerNames parameter.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -Rollback
    This will set the Extended Protection on all 'Default Web Site' Vdirs and 'Exchange Back End' Vdirs back to None.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter (Mandatory = $false, HelpMessage = "Enter the list of server names on which the script should execute on")]
    [string[]]$ExchangeServerNames = $null,
    [Parameter (Mandatory = $true, ParameterSetName = 'VDirOverride', HelpMessage = "Enter the name of the Virtual Directory on which you want to execute on")]
    [string]$VirtualDirectoryName = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [string[]]$SkipExchangeServerNames = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Use this switch to Enable require SSL flag across all IIS vdirs which don't have it enabled by default.")]
    [switch]$EnforceSSL,
    [Parameter (Mandatory = $false, ParameterSetName = 'Rollback', HelpMessage = "Use this switch to set the ExtendedProtection value on VDirs in 'Default Web Site' and 'Exchange Back End' to 'None'")]
    [switch]$Rollback
)

. $PSScriptRoot\ConfigurationAction\Configure-ExtendedProtection.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

$BuildVersion = ""
Write-Host "Version $BuildVersion"

if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/CEP-VersionsUrl")) {
    Write-Warning "Script was updated. Please rerun the command."
    return
}

Write-Verbose ("Running Get-ExchangeServer to get list of all exchange servers")
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
