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
    [Parameter (Mandatory = $false, HelpMessage = "Use this switch to skip the TLS prerequisites check. Be careful, because a faulty TLS configuration in combination with EP can lead to problems.")]
    [switch]$SkipTlsPrerequisitesCheck,
    [Parameter (Mandatory = $false, ParameterSetName = 'Rollback', HelpMessage = "Use this switch to set the ExtendedProtection value on VDirs in 'Default Web Site' and 'Exchange Back End' to 'None'")]
    [switch]$Rollback
)

. $PSScriptRoot\Write-Verbose.ps1
. $PSScriptRoot\WriteFunctions.ps1
. $PSScriptRoot\..\ConfigureExtendedProtection\DataCollection\Invoke-ExtendedProtectionTlsPrerequisitesCheck.ps1
. $PSScriptRoot\ConfigurationAction\Configure-ExtendedProtection.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\..\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Write-Host.ps1


if (-not (Confirm-Administrator)) {
    Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator."
    exit
}

$Script:Logger = Get-NewLoggerInstance -LogName "ConfigureExtendedProtection-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" `
    -AppendDateTimeToFileName $false `
    -ErrorAction SilentlyContinue

SetWriteHostAction ${Function:Write-HostLog}

if (-not((Confirm-ExchangeShell -Identity $env:COMPUTERNAME).ShellLoaded)) {
    Write-Warning "Failed to load the Exchange Management Shell. Start the script using the Exchange Management Shell."
    exit
}

$BuildVersion = ""
Write-Host "Version $BuildVersion"

if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/CEP-VersionsUrl")) {
    Write-Warning "Script was updated. Please rerun the command."
    return
}

Write-Verbose ("Running Get-ExchangeServer to get list of all exchange servers")
Set-ADServerSettings -ViewEntireForest $true
$ExchangeServers = Get-ExchangeServer | Where-Object { $_.AdminDisplayVersion -like "Version 15*" -and $_.ServerRole -ne "Edge" }
$ExchangeServersTlsSettingsCheck = $ExchangeServers

if ($null -ne $ExchangeServerNames -and $ExchangeServerNames.Count -gt 0) {
    Write-Verbose "Running only on servers: $([string]::Join(", " ,$ExchangeServerNames))"
    $ExchangeServers = $ExchangeServers | Where-Object { $_.Name -in $ExchangeServerNames }
}

if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
    Write-Verbose "Skipping servers: $([string]::Join(", ", $SkipExchangeServerNames))"

    # Remove all the servers present in the SkipExchangeServerNames list
    $ExchangeServers = $ExchangeServers | Where-Object { $_.Name -notin $SkipExchangeServerNames }
}

if ((-not($Rollback)) -and
    (-not($SkipTlsPrerequisitesCheck))) {
    Write-Verbose "Running 'Invoke-ExtendedProtectionTlsPrerequisitesCheck' to validate required configurations to run the Extended Protection feature"
    $tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -ExchangeServers $ExchangeServersTlsSettingsCheck.Fqdn

    if ($null -ne $tlsPrerequisites) {

        Write-Host ""
        foreach ($tlsSettings in $tlsPrerequisites.TlsSettings) {
            Write-Host "The following servers have the TLS Configuration below"
            Write-Host "$([string]::Join(", " ,$tlsSettings.MatchedServer))"
            $tlsSettings.TlsSettings.Registry.Tls.Values |
                Select-Object TLSVersion, ServerEnabled, ClientEnabled, TLSConfiguration |
                Sort-Object TLSVersion |
                Format-Table |
                Out-String |
                Write-Host
            $tlsSettings.TlsSettings.Registry.Net.Values |
                Select-Object NetVersion, SystemDefaultTlsVersions, WowSystemDefaultTlsVersions, SchUseStrongCrypto, WowSchUseStrongCrypto |
                Sort-Object NetVersion |
                Format-Table |
                Out-String |
                Write-Host
            Write-Host ""
            Write-Host ""
        }

        if ($tlsPrerequisites.CheckPassed) {
            Write-Host "TLS prerequisites check successfully passed!" -ForegroundColor Green
            Write-Host ""
        } else {
            foreach ($entry in $tlsPrerequisites.ActionsRequired) {
                Write-Host "Test Failed: $($entry.Name)" -ForegroundColor Red
                if ($null -ne $entry.List) {
                    foreach ($list in $entry.List) {
                        Write-Host "System affected: $list" -ForegroundColor Red
                    }
                }
                Write-Host "Action required: $($entry.Action)" -ForegroundColor Red
                Write-Host ""
            }

            $askForConfirmationWording = ("We found problems with your TLS configuration that can lead " +
                "to problems once Extended Protection is turned on.`n`r" +
                "We recommend to run the 'Exchange HealthChecker (https://aka.ms/ExchangeHealthChecker)' " +
                "to validate the TLS settings on your servers before processing with Extended Protection.`n`r" +
                "Do you want to continue? (Y/N)")
        }
    } else {
        $askForConfirmationWording = ("We were not able to query and check the TLS settings of your servers. " +
            "Misconfigured TLS settings may lead to problems onces Extended Protection is turned on.`n`r" +
            "We recommend to run the 'Exchange HealthChecker (https://aka.ms/ExchangeHealthChecker)' " +
            "to validate your TLS settings before processing with Extended Protection.`n`r" +
            "Do you want to continue? (Y/N)")
    }

    if ($null -ne $askForConfirmationWording) {
        $shouldProcess = $(Write-Host $askForConfirmationWording -ForegroundColor Red -NoNewline; Read-Host)
    } else {
        $shouldProcess = "y"
    }
} else {
    Write-Host "TLS prerequisited check will be skipped due to: $(if ($Rollback) {'Rollback'} elseif ($SkipTlsPrerequisitesCheck) {'SkipTlsPrerequisitesCheck'})"
}

if (($shouldProcess -eq "y") -or
    ($Rollback) -or
    ($SkipTlsPrerequisitesCheck)) {
    # Configure Extended Protection based on given parameters
    Configure-ExtendedProtection
} else {
    Write-Host "Process was cancelled and no configuration has been changed"
}
