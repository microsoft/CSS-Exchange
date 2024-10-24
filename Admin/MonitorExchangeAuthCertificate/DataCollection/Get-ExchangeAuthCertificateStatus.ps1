# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeServerCertificate.ps1

function Get-ExchangeAuthCertificateStatus {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [bool]$IgnoreUnreachableServers = $false,
        [bool]$IgnoreHybridSetup = $false,
        [ScriptBlock]$CatchActionFunction
    )

    <#
        Returns an object which contains information if the current Auth Certificate and/or the next Auth Certificate must be renewed.
        The object contains the following properties:
            - CurrentAuthCertificateLifetimeInDays
            - ReplaceRequired
            - ConfigureNextAuthRequired
            - NumberOfUnreachableServers
            - UnreachableServerList
            - HybridSetupDetected
            - StopProcessingDueToHybrid
            - MultipleExchangeADSites
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $replaceRequired = $false
        $importCurrentAuthCertificateRequired = $false
        $configureNextAuthRequired = $false
        $importNextAuthCertificateRequired = $false

        # Make sure to initialize this with -1 as this is needed to properly run the validation in case that we're unable to query this information
        $currentAuthCertificateValidInDays = -1
        $nextAuthCertificateValidInDays = -1

        $exchangeServersUnreachableList = New-Object 'System.Collections.Generic.List[string]'
        $exchangeServersReachableList = New-Object 'System.Collections.Generic.List[string]'
        $currentAuthCertificateFoundOnServersList = New-Object 'System.Collections.Generic.List[string]'
        $nextAuthCertificateFoundOnServersList = New-Object 'System.Collections.Generic.List[string]'
        $currentAuthCertificateMissingOnServersList = New-Object 'System.Collections.Generic.List[string]'
        $nextAuthCertificateMissingOnServersList = New-Object 'System.Collections.Generic.List[string]'
    } process {
        $authConfiguration = Get-AuthConfig -ErrorAction SilentlyContinue
        $allMailboxServers = Get-ExchangeServer | Where-Object {
            ((($_.IsMailboxServer) -or
            ($_.IsClientAccessServer)) -and
            ($_.AdminDisplayVersion -match "^Version 15"))
        }

        $multipleExchangeSites = (($allMailboxServers.Site.Name | Sort-Object -Unique).Count -gt 1)
        Write-Verbose ("Exchange deployed to multiple AD sites? $($multipleExchangeSites)")

        try {
            $hybridConfiguration = Get-HybridConfiguration -ErrorAction Stop
        } catch {
            Write-Verbose ("We hit an exception while querying the Exchange Hybrid configuration state - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }

        if ($null -ne $authConfiguration) {
            Write-Verbose ("AuthConfig returned via 'Get-AuthConfig' call")

            if (-not([string]::IsNullOrEmpty($authConfiguration.CurrentCertificateThumbprint))) {
                Write-Verbose ("CurrentCertificateThumbprint is: $($authConfiguration.CurrentCertificateThumbprint)")
                foreach ($mbxServer in $allMailboxServers) {
                    try {
                        Write-Verbose ("Trying to query current Auth Certificate on server: $($mbxServer)")
                        $currentAuthCertificate = Get-ExchangeServerCertificate -Server $($mbxServer.Fqdn) -Thumbprint $authConfiguration.CurrentCertificateThumbprint -ErrorAction Stop
                        $exchangeServersReachableList.Add($mbxServer.Fqdn)
                        $currentAuthCertificateFoundOnServersList.Add($mbxServer.Fqdn)
                    } catch {
                        Write-Verbose ("We hit an exception - going to determine the reason")
                        Invoke-CatchActionError $CatchActionFunction

                        if ((($error[0].CategoryInfo).Reason) -eq "InvalidOperationException") {
                            # Auth Certificate must exist on all servers, if it doesn't, generate a new one and replace the existing one
                            Write-Verbose ("Current Auth Certificate not found on server: $($mbxServer)")
                            $exchangeServersReachableList.Add($mbxServer.Fqdn)
                            $currentAuthCertificateMissingOnServersList.Add($mbxServer.Fqdn)
                        } else {
                            Write-Verbose ("Computer: $($mbxServer.Fqdn) is unreachable and cannot take into account")
                            $exchangeServersUnreachableList.Add($mbxServer.Fqdn)
                        }
                    }
                }
            }

            if (-not([string]::IsNullOrEmpty($authConfiguration.NextCertificateThumbprint))) {
                Write-Verbose ("NextCertificateThumbprint is: $($authConfiguration.NextCertificateThumbprint)")
                foreach ($mbxServer in $exchangeServersReachableList) {
                    try {
                        Write-Verbose ("Trying to query next Auth Certificate on server: $($mbxServer)")
                        $nextAuthCertificate = Get-ExchangeServerCertificate -Server $mbxServer -Thumbprint $authConfiguration.NextCertificateThumbprint -ErrorAction Stop
                        $nextAuthCertificateFoundOnServersList.Add($mbxServer)
                    } catch {
                        Invoke-CatchActionError $CatchActionFunction

                        if ((($error[0].CategoryInfo).Reason) -eq "InvalidOperationException") {
                            # Next Auth Certificate must exist on all servers, if it doesn't, generate a new one and replace the existing
                            Write-Verbose ("Next Auth Certificate not found on server: $($mbxServer)")
                            $nextAuthCertificateMissingOnServersList.Add($mbxServer)
                        } else {
                            Write-Verbose ("Exception reason is: $(($error[0].CategoryInfo).Reason)")
                            Write-Verbose ("Do nothing as we can't say for sure if the Auth Certificate exists or not")
                        }
                    }
                }
            }

            Write-Verbose ("Number of unreachable servers: $($exchangeServersUnreachableList.Count) - IgnoreUnreachableServers? $($IgnoreUnreachableServers)")

            if (($exchangeServersUnreachableList.Count -eq 0) -or
            (($exchangeServersUnreachableList.Count -gt 0) -and
                ($IgnoreUnreachableServers))) {

                if ($exchangeServersReachableList.Count -gt $currentAuthCertificateMissingOnServersList.Count) {
                    if ($null -ne $currentAuthCertificate.NotAfter) {
                        $currentAuthCertificateValidInDays = (($currentAuthCertificate.NotAfter) - (Get-Date)).Days

                        if (($currentAuthCertificate.NotAfter).Date -lt (Get-Date)) {
                            if ($currentAuthCertificateValidInDays -eq 0) {
                                Write-Verbose ("The current Auth Certificate has expired today")
                                $currentAuthCertificateValidInDays = -1
                            } else {
                                Write-Verbose ("The current Auth Certificate has already expired {0} days ago" -f [System.Math]::Abs($currentAuthCertificateValidInDays))
                            }
                        } else {
                            Write-Verbose ("The current Auth Certificate is still valid")
                        }
                    } else {
                        Write-Verbose ("There is no Auth Certificate configured")
                    }
                }

                if ($exchangeServersReachableList.Count -gt $nextAuthCertificateMissingOnServersList.Count) {
                    if ($null -ne $nextAuthCertificate.NotAfter) {
                        $nextAuthCertificateValidInDays = (($nextAuthCertificate.NotAfter) - (Get-Date)).Days

                        if (($nextAuthCertificate.NotAfter).Date -lt (Get-Date)) {
                            if ($nextAuthCertificateValidInDays -eq 0) {
                                Write-Verbose ("The next Auth Certificate has expired today")
                                $nextAuthCertificateValidInDays = -1
                            } else {
                                Write-Verbose ("The next Auth Certificate has already expired {0} days ago" -f [System.Math]::Abs($nextAuthCertificateValidInDays))
                            }
                        } else {
                            Write-Verbose ("The next Auth Certificate is still valid")
                        }
                    } else {
                        Write-Verbose ("There is no next Auth Certificate configured")
                    }
                }

                if (($currentAuthCertificateValidInDays -lt 0) -and
                    ($nextAuthCertificateValidInDays -lt 0)) {
                    # Scenario 1: Current Auth Certificate has expired and no next Auth Certificate defined or the next Auth Certificate has expired
                    $replaceRequired = $true
                } elseif ((($currentAuthCertificateValidInDays -ge 0) -and
                    ($currentAuthCertificateValidInDays -le 60)) -and
                    (($nextAuthCertificateValidInDays -le 0) -or
                    ($nextAuthCertificateValidInDays -le 120)) -and
                    ($currentAuthCertificateMissingOnServersList.Count -eq 0) -and
                    ($nextAuthCertificateMissingOnServersList.Count -eq 0)) {
                    # Scenario 2: Current Auth Certificate is valid but no next Auth Certificate defined or next Auth Certificate will expire in < 120 days
                    $configureNextAuthRequired = $true
                } elseif (($currentAuthCertificateValidInDays -le 0) -and
                    ($nextAuthCertificateValidInDays -ge 0)) {
                    # Scenario 3: Unlikely but possible - current Auth Certificate has expired and next Auth Certificate is set but not yet active
                    $replaceRequired = $true
                } else {
                    if ($currentAuthCertificateMissingOnServersList.Count -gt 0) {
                        # Scenario 4: Current Auth Certificate is missing on at least one (1) mailbox or CAS server
                        $importCurrentAuthCertificateRequired = $true
                    }
                    if ($nextAuthCertificateMissingOnServersList.Count -gt 0) {
                        # Scenario 5: Next Auth Certificate is missing on at least one (1) mailbox or CAS server
                        $importNextAuthCertificateRequired = $true
                    }
                }

                $stopProcessingDueToHybrid = ((($null -ne $hybridConfiguration) -and ($IgnoreHybridSetup -eq $false)) -and
                (($replaceRequired) -or ($configureNextAuthRequired)))

                Write-Verbose ("Replace of the primary Auth Certificate required? $($replaceRequired)")
                Write-Verbose ("Import of the primary Auth Certificate required? $($importCurrentAuthCertificateRequired)")
                Write-Verbose ("Replace of the next Auth Certificate required? $($configureNextAuthRequired)")
                Write-Verbose ("Import of the next Auth Certificate required? $($importNextAuthCertificateRequired)")
                Write-Verbose ("Hybrid Configuration detected? $($null -ne $hybridConfiguration)")
                Write-Verbose ("Stop processing due to hybrid? $($stopProcessingDueToHybrid)")
            } else {
                Write-Verbose ("Unable to reach the following Exchange Servers: $([string]::Join(", ", $exchangeServersUnreachableList))")
                Write-Verbose ("No renewal action will be performed as we can't for sure validate the Auth Certificate state on the offline servers")
            }
        } else {
            Write-Verbose ("Unable to query AuthConfig - therefore no action will be executed")
        }
    } end {
        return [PSCustomObject]@{
            CurrentAuthCertificateThumbprint     = $authConfiguration.CurrentCertificateThumbprint
            CurrentAuthCertificateLifetimeInDays = $currentAuthCertificateValidInDays
            ReplaceRequired                      = $replaceRequired
            CurrentAuthCertificateImportRequired = $importCurrentAuthCertificateRequired
            NextAuthCertificateThumbprint        = $authConfiguration.NextCertificateThumbprint
            NextAuthCertificateLifetimeInDays    = $nextAuthCertificateValidInDays
            ConfigureNextAuthRequired            = $configureNextAuthRequired
            NextAuthCertificateImportRequired    = $importNextAuthCertificateRequired
            NumberOfUnreachableServers           = $exchangeServersUnreachableList.Count
            UnreachableServersList               = $exchangeServersUnreachableList
            AuthCertificateFoundOnServers        = $currentAuthCertificateFoundOnServersList
            AuthCertificateMissingOnServers      = $currentAuthCertificateMissingOnServersList
            NextAuthCertificateFoundOnServers    = $nextAuthCertificateFoundOnServersList
            NextAuthCertificateMissingOnServers  = $nextAuthCertificateMissingOnServersList
            HybridSetupDetected                  = ($null -ne $hybridConfiguration)
            StopProcessingDueToHybrid            = $stopProcessingDueToHybrid
            MultipleExchangeADSites              = $multipleExchangeSites
        }
    }
}
