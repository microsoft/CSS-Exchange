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
. $PSScriptRoot\..\ConfigureExtendedProtection\DataCollection\Test-ExtendedProtectionTlsPrerequisites.ps1
. $PSScriptRoot\ConfigurationAction\Configure-ExtendedProtection.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\..\Shared\Confirm-Administrator.ps1
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


$BuildVersion = ""
Write-Host "Version $BuildVersion"

if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/CEP-VersionsUrl")) {
    Write-Warning "Script was updated. Please rerun the command."
    return
}

Write-Verbose ("Running Get-ExchangeServer to get list of all exchange servers")
Set-ADServerSettings -ViewEntireForest $true
$ExchangeServers = Get-ExchangeServer | Where-Object { $_.AdminDisplayVersion -like "Version 15*" -and $_.ServerRole -ne "Edge" }
$AllSupportedExchangeServers = $ExchangeServers

if ($null -ne $ExchangeServerNames -and $ExchangeServerNames.Count -gt 0) {
    Write-Verbose "Running only on servers: $([string]::Join(", " ,$ExchangeServerNames))"
    $ExchangeServers = $ExchangeServers | Where-Object { $_.Name -in $ExchangeServerNames }
}

if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
    Write-Verbose "Skipping servers: $([string]::Join(", ", $SkipExchangeServerNames))"

    # Remove all the servers present in the SkipExchangeServerNames list
    $ExchangeServers = $ExchangeServers | Where-Object { $_.Name -notin $SkipExchangeServerNames }
}

Write-Verbose "Running 'Test-ExtendedProtectionTlsPrerequisites' to validate required configurations to run the Extended Protection feature"
$tlsPrerequisites = Test-ExtendedProtectionTlsPrerequisites -ExchangeServers $AllSupportedExchangeServers

if ($null -ne $tlsPrerequisites) {

    function NewActionObject {
        param(
            [string]$Name,
            [array]$List,
            [string]$Action
        )

        return [PSCustomObject]@{
            Name   = $Name
            List   = $List
            Action = $Action
        }
    }

    $askForConfirmation = $false
    $tlsConfig = $tlsPrerequisites.TlsConfiguration
    $tlsCompared = $tlsPrerequisites.TlsComparedInfo
    $actionsRequiredList = New-Object 'System.Collections.Generic.List[object]'

    if ($tlsConfig.NumberOfServersPassed -ne $tlsConfig.NumberOfTlsSettingsReturned) {
        $action = NewActionObject -Name "Not all servers are reachable" -List $tlsConfig.UnreachableServers -Action "Check connectivity and validate the TLS configuration manually"
        Write-Verbose "We were not able to compare the TLS configuration for all servers within your organization"
        $actionsRequiredList.Add($action)
    }

    if ($tlsCompared.MajorityFound -eq $false) {
        $action = NewActionObject -Name "No majority TLS configuration found" -Action "Please ensure that all of your servers are running the same TLS configuration"
        Write-Verbose "We were not able to find a majority of correct TLS configurations within your organization"
        $actionsRequiredList.Add($action)
    } else {
        $tlsVersionList = New-Object 'System.Collections.Generic.List[object]'
        Write-Host "Tested TLS configuration against reference from server: $($tlsCompared.MajorityServer)"
        $tlsCompared.MajorityConfig.Registry.TLS.GetEnumerator() | ForEach-Object {
            $tlsVersionObject = [PSCustomObject]@{
                TlsVersion    = $_.key
                ServerEnabled = $_.value.ServerEnabled
                ClientEnabled = $_.Value.ClientEnabled
            }
            $tlsVersionList.Add($tlsVersionObject)
        }
        $tlsVersionList | Sort-Object -Property TlsVersion | Format-Table | Out-String | Write-Host

        $netVersionList = New-Object 'System.Collections.Generic.List[object]'
        $tlsCompared.MajorityConfig.Registry.NET.GetEnumerator() | ForEach-Object {
            $netVersionObject = [PSCustomObject]@{
                NETVersion                  = $_.key
                SystemDefaultTlsVersions    = $_.value.SystemDefaultTlsVersions
                WowSystemDefaultTlsVersions = $_.value.WowSystemDefaultTlsVersions
                SchUseStrongCrypto          = $_.value.SchUseStrongCrypto
                WowSchUseStrongCrypto       = $_.value.WowSchUseStrongCrypto
            }
            $netVersionList.Add($netVersionObject)
            if ($_.key -ne "NETv2") {
                if (($_.value.SchUseStrongCrypto -eq $false) -or
                    ($_.value.WowSchUseStrongCrypto -eq $false)) {
                    $action = NewActionObject -Name "SchUseStrongCrypto is not configured as expected" -Action "Configure SchUseStrongCrypto for $($_.key) as described here: https://aka.ms/PlaceHolderLink"
                    $actionsRequiredList.Add($action)
                }

                if (($_.value.SystemDefaultTlsVersions -eq $false) -or
                    ($_.value.WowSystemDefaultTlsVersions -eq $false)) {
                    $action = NewActionObject -Name "SystemDefaultTlsVersions is not configured as expected" -Action "Configure SystemDefaultTlsVersions for $($_.key) as described here: https://aka.ms/PlaceHolderLink"
                    $actionsRequiredList.Add($action)
                }
            }
        }
        $netVersionList | Sort-Object -Property NETVersion | Format-Table | Out-String | Write-Host

        if ($tlsCompared.MisconfiguredList.Count -ge 1) {
            $action = NewActionObject -Name "$($tlsCompared.MisconfiguredList.Count) server(s) have a different TLS configuration" -List $tlsCompared.MisconfiguredList.ComputerName -Action "Please ensure that the listed servers are running the same TLS configuration as: $($tlsCompared.MajorityServer)"
            $actionsRequiredList.Add($action)
        } else {
            Write-Host "All servers in your envionrment are running the same TLS configuration" -ForegroundColor Green
            Write-Host ""
        }
    }

    foreach ($o in $actionsRequiredList) {
        $askForConfirmation = $true
        Write-Host "Test Failed: $($o.Name)" -ForegroundColor Red
        if ($null -ne $o.List) {
            foreach ($l in $o.List) {
                Write-Host "System affected: $l" -ForegroundColor Red
            }
        }
        Write-Host "Action required: $($o.Action)" -ForegroundColor Red
        Write-Host ""
    }

    if ($askForConfirmation) {
        $askForConfirmationWording = ("We found problems with your TLS configuration that can lead " +
            "to problems once Extended Protection is turned on.`n`r" +
            "We recommend to run the 'Exchange HealthChecker' script to validate the TLS settings on your " +
            "servers before processing with Extended Protection.`n`r" +
            "Do you want to continue? (Y/N)")
    }
} else {
    $askForConfirmationWording = ("We were not able to check the TLS settings of your servers. " +
        "Misconfigured TLS settings may lead to problems onces Extended Protection is turned on.`n`r" +
        "We recommend to run the 'Exchange HealthChecker' script to validate your TLS settings " +
        "before processing with Extended Protection.`n`r" +
        "Do you want to continue? (Y/N)")
}

if ($null -ne $askForConfirmationWording) {
    $shoudProcess = Read-Host $askForConfirmationWording
} else {
    $shoudProcess = "y"
}

if ($shoudProcess -eq "y") {
    # Configure Extended Protection based on given parameters
    Configure-ExtendedProtection
} else {
    Write-Host "Process was cancelled and no configuration has been changed"
}
