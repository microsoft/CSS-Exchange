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
    [Parameter (Mandatory = $false, ValueFromPipeline, HelpMessage = "Enter the list of server names on which the script should execute on")]
    [string[]]$ExchangeServerNames = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [string[]]$SkipExchangeServerNames = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Use this switch to skip over EWS Vdir")]
    [switch]$SkipEWS,
    [Parameter (Mandatory = $false, ParameterSetName = 'Rollback', HelpMessage = "Use this switch to set the ExtendedProtection value on VDirs in 'Default Web Site' and 'Exchange Back End' to 'None'")]
    [switch]$Rollback
)

begin {
    . $PSScriptRoot\Write-Verbose.ps1
    . $PSScriptRoot\WriteFunctions.ps1
    . $PSScriptRoot\..\ConfigureExtendedProtection\DataCollection\Get-ExtendedProtectionPrerequisitesCheck.ps1
    . $PSScriptRoot\..\ConfigureExtendedProtection\DataCollection\Invoke-ExtendedProtectionTlsPrerequisitesCheck.ps1
    . $PSScriptRoot\ConfigurationAction\Invoke-ConfigureExtendedProtection.ps1
    . $PSScriptRoot\ConfigurationAction\Invoke-RollbackExtendedProtection.ps1
    . $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
    . $PSScriptRoot\..\..\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\..\..\Shared\Confirm-ExchangeShell.ps1
    . $PSScriptRoot\..\..\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\..\..\Shared\Show-Disclaimer.ps1
    . $PSScriptRoot\..\..\..\Shared\Write-Host.ps1
    $includeExchangeServerNames = New-Object 'System.Collections.Generic.List[string]'
} process {
    foreach ($server in $ExchangeServerNames) {
        $includeExchangeServerNames.Add($server)
    }
} end {
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

    if (-not($Rollback)) {
        $epDisclaimer = "Extended Protection is currently not supported if you are using layer 7 load balancing " +
        "or systems that do ssl offloading. After turning Extended Protection on, " +
        "you will no longer be able to access Exchange protocols in such scenarios. " +
        "If using Exchange Online Archives, the Move to Archive Tag will no longer work if Extended Protection is enabled."
        "You can find more information on: https://aka.ms/PlaceHolderLink. Do you want to proceed?"
        Show-Disclaimer $epDisclaimer "Enabling Extended Protection"
    }

    Write-Verbose ("Running Get-ExchangeServer to get list of all exchange servers")
    Set-ADServerSettings -ViewEntireForest $true
    $ExchangeServers = Get-ExchangeServer | Where-Object { $_.AdminDisplayVersion -like "Version 15*" -and $_.ServerRole -ne "Edge" }
    $ExchangeServersPrerequisitesCheckSettingsCheck = $ExchangeServers

    if ($null -ne $includeExchangeServerNames -and $includeExchangeServerNames.Count -gt 0) {
        Write-Verbose "Running only on servers: $([string]::Join(", " ,$includeExchangeServerNames))"
        $ExchangeServers = $ExchangeServers | Where-Object { ($_.Name -in $includeExchangeServerNames) -or ($_.FQDN -in $includeExchangeServerNames) }
    }

    if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
        Write-Verbose "Skipping servers: $([string]::Join(", ", $SkipExchangeServerNames))"

        # Remove all the servers present in the SkipExchangeServerNames list
        $ExchangeServers = $ExchangeServers | Where-Object { ($_.Name -notin $SkipExchangeServerNames) -and ($_.FQDN -notin $SkipExchangeServerNames) }
    }

    $serverNames = New-Object 'System.Collections.Generic.List[string]'
    $ExchangeServers | ForEach-Object { $serverNames.Add($_.Name) }

    if (-not($Rollback)) {
        $prerequisitesCheck = Get-ExtendedProtectionPrerequisitesCheck -ExchangeServers $ExchangeServersPrerequisitesCheckSettingsCheck -SkipEWS $SkipEWS

        if ($null -ne $prerequisitesCheck) {

            Write-Host ""
            $tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -TlsConfiguration $prerequisitesCheck.TlsSettings
            foreach ($tlsSettings in $tlsPrerequisites.TlsSettings) {
                Write-Host "The following servers have the TLS Configuration below"
                Write-Host "$([string]::Join(", " ,$tlsSettings.MatchedServer))"
                $tlsSettings.TlsSettings.Registry.Tls.Values |
                    Select-Object TLSVersion,
                    @{Label = "ServerEnabled"; Expression = { $_.ServerEnabledValue } },
                    @{Label = "ServerDbD"; Expression = { $_.ServerDisabledByDefaultValue } },
                    @{Label = "ClientEnabled"; Expression = { $_.ClientEnabledValue } },
                    @{Label = "ClientDbD"; Expression = { $_.ClientDisabledByDefaultValue } },
                    TLSConfiguration |
                    Sort-Object TLSVersion |
                    Format-Table |
                    Out-String |
                    Write-Host
                $tlsSettings.TlsSettings.Registry.Net.Values |
                    Select-Object NetVersion,
                    @{Label = "SystemTlsVersions"; Expression = { $_.SystemDefaultTlsVersionsValue } },
                    @{Label = "WowSystemTlsVersions"; Expression = { $_.WowSystemDefaultTlsVersionsValue } },
                    @{Label = "SchUseStrongCrypto"; Expression = { $_.SchUseStrongCryptoValue } },
                    @{Label = "WowSchUseStrongCrypto"; Expression = { $_.WowSchUseStrongCryptoValue } } |
                    Sort-Object NetVersion |
                    Format-Table |
                    Out-String |
                    Write-Host
                Write-Host "Security Protocol: $($tlsSettings.TlsSettings.SecurityProtocol)"
                Write-Host ""
                Write-Host ""
            }

            # If TLS Prerequisites Check passed, then we are good to go.
            # If it doesn't, now we need to verify the servers we are trying to enable EP on
            # will pass the TLS Prerequisites and all other servers that have EP enabled on.
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
                $checkAgainst = $prerequisitesCheck |
                    Where-Object {
                        $_.ExtendedProtectionConfiguration.ExtendedProtectionConfigured -eq $true -or
                        $_.ComputerName -in $serverNames
                    }

                $results = Invoke-ExtendedProtectionTlsPrerequisitesCheck -TlsConfiguration $checkAgainst.TlsSettings

                if ($results.CheckPassed) {
                    Write-Host "All servers attempting to enable Extended Protection or already enabled passed the TLS prerequisites."
                    Write-Host ""
                } else {
                    Write-Warning "Failed to pass the TLS prerequisites. Unable to continue."
                    exit
                }
            }
        } else {
            Write-Warning "Failed to get Extended Protection Prerequisites Information to be able to continue"
            exit
        }
    } else {
        Write-Host "Prerequisite check will be skipped due to Rollback"
    }

    if ($Rollback) {
        Invoke-RollbackExtendedProtection -ExchangeServers $ExchangeServers
        return
    }

    # Configure Extended Protection based on given parameters
    $extendedProtectionConfigurations = ($prerequisitesCheck |
            Where-Object { $_.ComputerName -in $serverNames }).ExtendedProtectionConfiguration
    Invoke-ConfigureExtendedProtection -ExtendedProtectionConfigurations $extendedProtectionConfigurations
}
