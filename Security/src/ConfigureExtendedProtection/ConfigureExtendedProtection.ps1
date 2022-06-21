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
.PARAMETER FEExtendedProtection
    If set then the script execution will change the Extended Protection on 'Default Web Site' Vdirs to the value provided in this parameter.
.PARAMETER BEExtendedProtection
    If set then the script execution will change the Extended Protection on 'Exchange Back End' Vdirs to the value provided in this parameter.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1
    This will run the default mode which does the following:
        1. It will set Extended Protection as 'Require' on "Default Web Site" Vdirs on all the Exchange Servers.
        2. If will set Extended Protection as 'Require' on "Exchange Back End" Vdirs on all the Exchange Servers.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -StopSpoolerService
    This will run the default mode which does the following:
        1. It will set Extended Protection as 'Require' on "Default Web Site" Vdirs on all the Exchange Servers.
        2. If will set Extended Protection as 'Require' on "Exchange Back End" Vdirs on all the Exchange Servers.
        3. Stops and Disables the Print Spooler service on all the Exchange Servers.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -FEExtendedProtection Allow
    This will set all the 'Default Web Site' Vdirs with Extended Protection 'Allow'.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -FEExtendedProtection Allow -VirtualDirectoryName 'EWS'
    This will set 'Default Web Site' 'EWS' Vdir with Extended Protection 'Allow'.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -BEExtendedProtection Allow
    This will set all the 'Exchange Web Site' Vdirs with Extended Protection 'Allow'.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -ExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection on all 'Default Web Site' and 'Exchange Back End' Vdirs only on the Exchange Servers whose names are provided in the ExchangeServerNames parameter.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -SkipExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection on all 'Default Web Site' and 'Exchange Back End' Vdirs except the Exchange Servers whose names are provided in the SkipExchangeServerNames parameter.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -SkipEx2013OrOlderServers
    This will set the Extended Protection on all 'Default Web Site' and 'Exchange Back End' Vdirs except the Exchange Servers which are running Ex2013 or older version.
.EXAMPLE
    PS C:\> .\ConfigureExtendedProtection.ps1 -Rollback
    This will set the Extended Protection on all 'Default Web Site' Vdirs and 'Exchange Back End' Vdirs back to None.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'EnableExtendedProtection')]
param(
    [Parameter (Mandatory = $false, ParameterSetName = "EnableExtendedProtection", HelpMessage = "Enter ExtendedProtection value to set for the VDirs in the 'Default Web Site'")]
    [Parameter (Mandatory = $false, ParameterSetName = "VDirOverride")]
    [ValidateSet("None", "Allow", "Require")]
    [string]$FEExtendedProtection = "Require",
    [Parameter (Mandatory = $false, ParameterSetName = "EnableExtendedProtection", HelpMessage = "Enter ExtendedProtection value to set for the VDirs in the 'Exchange Back End'")]
    [Parameter (Mandatory = $false, ParameterSetName = "VDirOverride")]
    [ValidateSet("None", "Allow", "Require")]
    [string]$BEExtendedProtection = "Require",
    [Parameter (Mandatory = $false, HelpMessage = "Enter the list of server names on which the script should execute on")]
    [string[]]$ExchangeServerNames = $null,
    [Parameter (Mandatory = $true, ParameterSetName = 'VDirOverride', HelpMessage = "Enter the name of the Virtual Directory on which you want to execute on")]
    [string]$VirtualDirectoryName = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [string[]]$SkipExchangeServerNames = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Use this switch to skip enabling/disabling extended protection on Ex2013 or older servers.")]
    [switch]$SkipEx2013OrOlderServers,
    [Parameter (Mandatory = $false, HelpMessage = "Use this switch to Enable require SSL flag across all IIS vdirs which don't have it enabled by default.")]
    [switch]$EnforceSSL,
    [Parameter (Mandatory = $false, ParameterSetName = 'Rollback', HelpMessage = "Use this switch to set the ExtendedProtection value on VDirs in 'Default Web Site' and 'Exchange Back End' to 'None'")]
    [switch]$Rollback,
    [Parameter (Mandatory = $false, HelpMessage = "Use this switch to Stop and Disable Printer Spooler Service on the Exchange Servers")]
    [switch]$StopSpoolerService
)

. $PSScriptRoot\ConfigurationAction\Configure-ExtendedProtection.ps1
. $PSScriptRoot\ConfigurationAction\Retry-Command.ps1
. $PSScriptRoot\ConfigurationAction\Stop-SpoolerService.ps1

$BuildVersion = ""
Write-Host "Version $BuildVersion"

if ($PSCmdlet.ParameterSetName.Equals("VDirOverride")) {
    if (-not ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("FEExtendedProtection") -or $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BEExtendedProtection"))) {
        Write-Error ("Operation failed, missing required FEExtendedProtection or BEExtendedProtection parameter")
        exit
    }
}

Write-Verbose ("Running Get-ExchangeServer to get list of all exchange servers")
$ExchangeServers = Get-ExchangeServer

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

# If the StopSpoolerService switch is provided, then Stop/Disable Printer Spooler Service on all the exchange servers.
if ($StopSpoolerService) {
    # Loop all the Exchange servers
    foreach ($server in $ExchangeServers) {
        # Stops the spooler service
        Retry-Command -Params ({ Stop-SpoolerService -Server $server })
    }
}
