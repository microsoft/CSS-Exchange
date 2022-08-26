# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    This script enables extended protection on all Exchange servers in the forest.
.DESCRIPTION
    The Script does the following by default.
        1. Enables Extended Protection to the recommended value for the corresponding virtual directory and site.
    Extended Protection is a windows security feature which blocks MiTM attacks.
.PARAMETER RollbackType
    Use this parameter to execute a Rollback Type that should be executed.
.EXAMPLE
    PS C:\> .\ExchangeExtendedProtectionManagement.ps1
    This will run the default mode which does the following:
        1. It will set Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers in the forest.
.EXAMPLE
    PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -ExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers provided in ExchangeServerNames
.EXAMPLE
    PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -SkipExchangeServerNames <Array_of_Server_Names>
    This will set the Extended Protection to the recommended value for the corresponding virtual directory and site on all Exchange Servers in the forest except the Exchange Servers whose names are provided in the SkipExchangeServerNames parameter.
.EXAMPLE
    PS C:\> .\ExchangeExtendedProtectionManagement.ps1 -RollbackType "RestoreIISAppConfig"
    This will set the applicationHost.config file back to the original state prior to changes made with this script.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter (Mandatory = $false, ValueFromPipeline, HelpMessage = "Enter the list of server names on which the script should execute on")]
    [string[]]$ExchangeServerNames = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Enter the list of servers on which the script should not execute on")]
    [string[]]$SkipExchangeServerNames = $null,
    [Parameter (Mandatory = $false, HelpMessage = "Enable to provide a result of the configuration for Extended Protection")]
    [switch]$ShowExtendedProtection,
    [Parameter (Mandatory = $false, HelpMessage = "Used for internal options")]
    [string]$InternalOption,
    [Parameter (Mandatory = $false, ParameterSetName = 'Rollback', HelpMessage = "Using this parameter will allow you to rollback using the type you specified.")]
    [ValidateSet("RestoreIISAppConfig")]
    [string]$RollbackType
)

begin {
    . $PSScriptRoot\Write-Verbose.ps1
    . $PSScriptRoot\WriteFunctions.ps1
    . $PSScriptRoot\ConfigurationAction\Invoke-ConfigureExtendedProtection.ps1
    . $PSScriptRoot\ConfigurationAction\Invoke-RollbackExtendedProtection.ps1
    . $PSScriptRoot\DataCollection\Get-ExtendedProtectionPrerequisitesCheck.ps1
    . $PSScriptRoot\DataCollection\Invoke-ExtendedProtectionTlsPrerequisitesCheck.ps1
    . $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
    . $PSScriptRoot\..\..\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\..\..\Shared\Confirm-ExchangeShell.ps1
    . $PSScriptRoot\..\..\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\..\..\Shared\Out-Columns.ps1
    . $PSScriptRoot\..\..\..\Shared\Show-Disclaimer.ps1
    . $PSScriptRoot\..\..\..\Shared\Write-Host.ps1
    $includeExchangeServerNames = New-Object 'System.Collections.Generic.List[string]'
    if ($PsCmdlet.ParameterSetName -eq "Rollback") {
        $RollbackSelected = $true
        if ($RollbackType -eq "RestoreIISAppConfig") {
            $RollbackRestoreIISAppConfig = $true
        }
    }
} process {
    foreach ($server in $ExchangeServerNames) {
        $includeExchangeServerNames.Add($server)
    }
} end {
    if (-not (Confirm-Administrator)) {
        Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator."
        exit
    }

    try {

        $Script:Logger = Get-NewLoggerInstance -LogName "ExchangeExtendedProtectionManagement-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" `
            -AppendDateTimeToFileName $false `
            -ErrorAction SilentlyContinue

        SetWriteHostAction ${Function:Write-HostLog}

        if ($InternalOption -eq "SkipEWS") {
            Write-Verbose "SkipEWS option enabled."
            $Script:SkipEWS = $true
        } else {
            $Script:SkipEWS = $false
        }

        $exchangeShell = Confirm-ExchangeShell -Identity $env:COMPUTERNAME
        if (-not($exchangeShell.ShellLoaded)) {
            Write-Warning "Failed to load the Exchange Management Shell. Start the script using the Exchange Management Shell."
            exit
        } elseif (-not ($exchangeShell.EMS)) {
            Write-Warning "This script requires to be run inside of Exchange Management Shell. Please run on an Exchange Management Server or an Exchange Server with Exchange Management Shell."
            exit
        }

        $BuildVersion = ""
        Write-Host "Version $BuildVersion"

        if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/CEP-VersionsUrl")) {
            Write-Warning "Script was updated. Please rerun the command."
            return
        }

        if (-not($RollbackSelected) -and
            -not($ShowExtendedProtection)) {
            $params = @{
                Message   = "Display Warning about Extended Protection"
                Target    = "Extended Protection is recommended to be enabled for security reasons. " +
                "Known Issues: Following scenarios will not work when Extended Protection is enabled." +
                "`r`n    - SSL offloading or SSL termination via Layer 7 load balancing." +
                "`r`n    - Automated Archiving using Archive policy" +
                "`r`n    - Exchange Hybrid Features if using Modern Hybrid." +
                "`r`n    - Access to Public folders on Exchange 2013 Servers." +
                "`r`nYou can find more information on: https://aka.ms/ExchangeEPDoc. Do you want to proceed?"
                Operation = "Enabling Extended Protection"
            }

            Show-Disclaimer @params
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

        if ($ShowExtendedProtection) {
            Write-Verbose "Showing Extended Protection Information Only"
            $extendedProtectionConfigurations = New-Object 'System.Collections.Generic.List[object]'
            foreach ($server in $ExchangeServers) {
                $params = @{
                    ComputerName         = $server.ToString()
                    IsClientAccessServer = $server.IsClientAccessServer
                    IsMailboxServer      = $server.IsMailboxServer
                    ExcludeEWS           = $SkipEWS
                }
                $extendedProtectionConfigurations.Add((Get-ExtendedProtectionConfiguration @params))
            }

            foreach ($configuration in $extendedProtectionConfigurations) {
                Write-Verbose "Working on server $($configuration.ComputerName)"
                $epOutputObjectDisplayValue = New-Object 'System.Collections.Generic.List[object]'
                foreach ($entry in $configuration.ExtendedProtectionConfiguration) {
                    $ssl = $entry.Configuration.SslSettings

                    $epOutputObjectDisplayValue.Add(([PSCustomObject]@{
                                VirtualDirectory  = $entry.VirtualDirectoryName
                                Value             = $entry.ExtendedProtection
                                SupportedValue    = $entry.ExpectedExtendedConfiguration
                                ConfigSupported   = $entry.SupportedExtendedProtection
                                RequireSSL        = "$($ssl.RequireSSL) $(if($ssl.Ssl128Bit) { "(128-bit)" })".Trim()
                                ClientCertificate = $ssl.ClientCertificate
                            }))
                }

                Write-Host "Results for Server: $($configuration.ComputerName)"
                $epOutputObjectDisplayValue | Format-Table | Out-String | Write-Host
                Write-Host ""
                Write-Host ""
            }

            return
        }

        if (-not($RollbackSelected)) {
            $prerequisitesCheck = Get-ExtendedProtectionPrerequisitesCheck -ExchangeServers $ExchangeServersPrerequisitesCheckSettingsCheck -SkipEWS $SkipEWS

            if ($null -ne $prerequisitesCheck) {

                Write-Host ""
                # Remove the down servers from $ExchangeServers list.
                $downServerName = New-Object 'System.Collections.Generic.List[string]'
                $onlineSupportedServers = New-Object 'System.Collections.Generic.List[object]'
                $unsupportedServers = New-Object 'System.Collections.Generic.List[string]'
                $unsupportedAndConfiguredServers = New-Object 'System.Collections.Generic.List[object]'
                $prerequisitesCheck | ForEach-Object {
                    if ($_.ExtendedProtectionConfiguration.ExtendedProtectionConfigured -eq $true -and
                        $_.ExtendedProtectionConfiguration.SupportedVersionForExtendedProtection -eq $false) {
                        $unsupportedAndConfiguredServers.Add($_)
                    } elseif ($_.ExtendedProtectionConfiguration.SupportedVersionForExtendedProtection -eq $false) {
                        $unsupportedServers.Add($_.ComputerName)
                    } elseif ($_.ServerOnline) {
                        $onlineSupportedServers.Add($_)
                    } else {
                        $downServerName.Add($_.ComputerName)
                    }
                }

                # We don't care about the TLS version on servers that aren't yet upgraded on
                # Therefore, we can skip over them for this check.
                # However, if there is an unsupported version of Exchange that does have EP enabled,
                # We need to prompt to the admin stating that we are going to revert the change to get back to a supported state.
                Write-Verbose ("Found the following servers configured for EP and Unsupported: " +
                    "$(if ($unsupportedAndConfiguredServers.Count -eq 0) { 'None' } else {[string]::Join(", " ,$unsupportedAndConfiguredServers.ComputerName)})")

                Write-Verbose ("Found the following servers that not supported to configure EP and not enabled: " +
                    "$(if ($unsupportedServers.Count -eq 0) { 'None' } else {[string]::Join(", " ,$unsupportedServers)})")

                if ($unsupportedAndConfiguredServers.Count -gt 0) {
                    $params = @{
                        Message   = "Display Warning about switching Extended Protection Back to None for Unsupported Build of Exchange"
                        Target    = "Found Servers that have Extended Protection Enabled, but are on an unsupported build of Exchange." +
                        "`r`nBecause of this, we will be setting them back to None for Extended Protection with the execution of this script to be in a supported state." +
                        "`r`nYou can find more information on: https://aka.ms/ExchangeEPDoc. Do you want to proceed?"
                        Operation = "Set Unsupported Version of Exchange Back to None for Extended Protection"
                    }

                    Show-Disclaimer @params
                    Write-Host ""
                }

                if ($unsupportedServers.Count -gt 0) {

                    $serversInList = @($ExchangeServers | Where-Object { $($_.Name -in $unsupportedServers) })

                    if ($serversInList.Count -gt 0) {
                        $line = "The following servers are not the minimum required version to support Extended Protection. Please update them, or re-run the script without including them in the list: $($serversInList -Join " ")"
                        Write-Verbose $line
                        Write-Warning $line
                        exit
                    }

                    Write-Verbose "The following servers are unsupported but not included in the list to configure: $([string]::Join(", " ,$unsupportedServers))"
                }

                if ($downServerName.Count -gt 0) {
                    $line = "Removing the following servers from the list to configure because we weren't able to reach them: $([string]::Join(", " ,$downServerName))"
                    Write-Verbose $line
                    Write-Warning $line
                    $ExchangeServers = $ExchangeServers | Where-Object { $($_.Name -notin $downServerName) }
                    Write-Host ""
                }

                # Only need to set the server names for the ones we are trying to configure and the ones that are up.
                # Also need to add Unsupported Configured EP servers to the list.
                $serverNames = New-Object 'System.Collections.Generic.List[string]'
                $ExchangeServers | ForEach-Object { $serverNames.Add($_.Name) }

                if ($unsupportedAndConfiguredServers.Count -gt 0) {
                    $unsupportedAndConfiguredServers |
                        Where-Object { $_.ComputerName -notin $serverNames } |
                        ForEach-Object { $serverNames.Add($_.ComputerName) }
                }

                # If there aren't any servers to check against for TLS settings, bypass this check.
                if ($null -ne $onlineSupportedServers.TlsSettings) {
                    $tlsPrerequisites = Invoke-ExtendedProtectionTlsPrerequisitesCheck -TlsConfiguration $onlineSupportedServers.TlsSettings

                    function NewDisplayObject {
                        param(
                            [string]$RegistryName,
                            [string]$Location,
                            [object]$Value
                        )
                        return [PSCustomObject]@{
                            RegistryName = $RegistryName
                            Location     = $Location
                            Value        = $Value
                        }
                    }

                    foreach ($tlsSettings in $tlsPrerequisites.TlsSettings) {
                        Write-Host "The following servers have the TLS Configuration below"
                        Write-Host "$([string]::Join(", " ,$tlsSettings.MatchedServer))"
                        $displayObject = @()
                        $tlsSettings.TlsSettings.Registry.Tls.Values |
                            ForEach-Object {
                                $displayObject += NewDisplayObject "Enabled" -Location $_.ServerRegistryPath -Value $_.ServerEnabledValue
                                $displayObject += NewDisplayObject "DisabledByDefault" -Location $_.ServerRegistryPath -Value $_.ServerDisabledByDefaultValue
                                $displayObject += NewDisplayObject "Enabled" -Location $_.ClientRegistryPath -Value $_.ClientEnabledValue
                                $displayObject += NewDisplayObject "DisabledByDefault" -Location $_.ClientRegistryPath -Value $_.ClientDisabledByDefaultValue
                            }

                        $tlsSettings.TlsSettings.Registry.Net.Values |
                            ForEach-Object {
                                $displayObject += NewDisplayObject "SystemTlsVersions" -Location $_.MicrosoftRegistryLocation -Value $_.SystemDefaultTlsVersionsValue
                                $displayObject += NewDisplayObject "SchUseStrongCrypto" -Location $_.MicrosoftRegistryLocation -Value $_.SchUseStrongCryptoValue
                                $displayObject += NewDisplayObject "SystemTlsVersions" -Location $_.WowRegistryLocation -Value $_.WowSystemDefaultTlsVersionsValue
                                $displayObject += NewDisplayObject "SchUseStrongCrypto" -Location $_.WowRegistryLocation -Value $_.WowSchUseStrongCryptoValue
                            }
                        $stringOutput = [string]::Empty
                        SetWriteHostAction $null
                        $displayObject | Sort-Object Location, RegistryName |
                            Out-Columns -StringOutput ([ref]$stringOutput)
                        Write-HostLog $stringOutput
                        SetWriteHostAction ${Function:Write-HostLog}
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
                        $checkAgainst = $onlineSupportedServers |
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

                    # now that we passed the TLS PrerequisitesCheck, now we need to do the RPC vdir check for SSLOffloading.
                    $rpcFailedServers = New-Object 'System.Collections.Generic.List[string]'
                    $rpcNullServers = New-Object 'System.Collections.Generic.List[string]'
                    $canNotConfigure = "Therefore, we can not configure Extended Protection."
                    $counter = 0
                    $totalCount = $ExchangeServers.Count
                    $outlookAnywhereCount = 0
                    $outlookAnywhereServers = $ExchangeServersPrerequisitesCheckSettingsCheck | Where-Object { $_.IsClientAccessServer -eq $true }
                    $outlookAnywhereTotalCount = $outlookAnywhereServers.Count

                    $progressParams = @{
                        Id              = 1
                        Activity        = "Prerequisites Check"
                        Status          = "Running Get-OutlookAnywhere"
                        PercentComplete = 0
                    }

                    $outlookAnywhereProgressParams = @{
                        ParentId        = 1
                        Activity        = "Collecting Get-OutlookAnywhere Results"
                        PercentComplete = 0
                    }

                    Write-Progress @progressParams
                    Write-Progress @outlookAnywhereProgressParams
                    # Needs to be SilentlyContinue to handle down servers, we must also exclude pre Exchange 2013 servers
                    $outlookAnywhere = $outlookAnywhereServers | Get-OutlookAnywhere -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            $outlookAnywhereCount++
                            $outlookAnywhereProgressParams.PercentComplete = ($outlookAnywhereCount / $outlookAnywhereTotalCount * 100)
                            Write-Progress @outlookAnywhereProgressParams
                            $_
                        }

                    if ($null -eq $outlookAnywhere) {
                        Write-Warning "Failed to run Get-OutlookAnywhere. Failing out the script."
                        exit
                    }

                    foreach ($server in $ExchangeServers) {
                        $counter++
                        $progressParams.Status = "Checking RPC FE SSLOffloading - $($server.Name)"
                        $progressParams.PercentComplete = ($counter / $totalCount * 100)
                        Write-Progress @progressParams
                        if (-not ($server.IsClientAccessServer)) {
                            Write-Verbose "Server $($server.Name) is not a CAS. Skipping over the RPC FE Check."
                            continue
                        }
                        $rpcSettings = $outlookAnywhere | Where-Object { $_.ServerName -eq $server.Name }

                        if ($null -eq $rpcSettings) {
                            $line = "Failed to find '$($server.Name)\RPC (Default Web Site)' Virtual Directory to determine SSLOffloading value. $canNotConfigure"
                            Write-Verbose $line
                            Write-Warning $line
                            $rpcNullServers.Add($server.Name)
                        } elseif ($rpcSettings.SSLOffloading -eq $true) {
                            $line = "'$($server.Name)\RPC (Default Web Site)' has SSLOffloading set to true. $canNotConfigure"
                            Write-Verbose $line
                            Write-Warning $line
                            $rpcFailedServers.Add($server.Name)
                        } else {
                            Write-Verbose "Server $($server.Name) passed RPC SSLOffloading check"
                        }
                    }
                    Write-Progress @progressParams -Completed
                    if ($rpcFailedServers.Count -gt 0) {
                        Write-Warning "Please address the following server regarding RPC (Default Web Site) and SSL Offloading: $([string]::Join(", " ,$rpcFailedServers))"
                        Write-Warning "The following cmdlet should be run against each of the servers: Set-OutlookAnywhere 'SERVERNAME\RPC (Default Web Site)' -SSLOffloading `$false -InternalClientsRequireSsl `$true -ExternalClientsRequireSsl `$true"
                        exit
                    } elseif ($rpcNullServers.Count -gt 0) {
                        Write-Warning "Failed to find the following servers RPC (Default Web Site) for SSL Offloading: $([string]::Join(", " ,$rpcFailedServers))"
                        Write-Warning $canNotConfigure
                        exit
                    }
                    Write-Host "All servers that we are trying to currently configure for Extended Protection have RPC (Default Web Site) set to false for SSLOffloading."
                } else {
                    Write-Verbose "No online servers that are in a supported state. Skipping over TLS Check."
                }
            } else {
                Write-Warning "Failed to get Extended Protection Prerequisites Information to be able to continue"
                exit
            }
        } else {
            Write-Host "Prerequisite check will be skipped due to Rollback"

            if ($RollbackRestoreIISAppConfig) {
                Invoke-RollbackExtendedProtection -ExchangeServers $ExchangeServers
            }
            return
        }

        # Configure Extended Protection based on given parameters
        # Prior to executing, add back any unsupported versions back into the list
        # for onlineSupportedServers, because the are online and we want to revert them.
        $unsupportedAndConfiguredServers | ForEach-Object { $onlineSupportedServers.Add($_) }
        $extendedProtectionConfigurations = ($onlineSupportedServers |
                Where-Object { $_.ComputerName -in $serverNames }).ExtendedProtectionConfiguration

        if ($null -ne $extendedProtectionConfigurations) {
            Invoke-ConfigureExtendedProtection -ExtendedProtectionConfigurations $extendedProtectionConfigurations
        } else {
            Write-Host "No servers are online or no Exchange Servers Support Extended Protection."
        }
    } finally {
        Write-Host "Do you have feedback regarding the script? Please email ExToolsFeedback@microsoft.com."
    }
}
