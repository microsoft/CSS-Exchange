# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-JobExchangeInformationCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerName
    )
    begin {
        # Build Process to add functions.
        . $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeDiagnosticInformation.ps1
        . $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeSettingOverride.ps1
        . $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeWebSitesFromAd.ps1
        . $PSScriptRoot\..\..\..\..\Shared\CertificateFunctions\Get-ExchangeServerCertificateInformation.ps1
        . $PSScriptRoot\Get-ExchangeVirtualDirectories.ps1
        . $PSScriptRoot\Get-ExchangeServerMaintenanceState.ps1

        if ($PSSenderInfo) {
            $Script:ErrorsExcluded = @()
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $jobStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Invoke-DefaultConnectExchangeShell
    }
    process {

        foreach ($Server in $ServerName) {
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            Write-Verbose "Working on collecting information for $Server"
            $exchangeCertificateInformation = $null
            $exchangeConnectors = $null
            $serverMaintenance = $null
            $settingOverrides = $null
            $edgeTransportResourceThrottling = $null
            $serverMonitoringOverride = $null
            $getExchangeVirtualDirectories = $null

            $getExchangeServer = Get-ExchangeServer -Identity $Server -Status # TODO: Determine if we want to keep the cmdlet with the status or have it be passed to this job.
            Get-ExchangeServerCertificateInformation -Server $Server -CatchActionFunction ${Function:Invoke-CatchActions} | Invoke-RemotePipelineHandler -Result ([ref]$exchangeCertificateInformation)
            Get-ExchangeVirtualDirectories -Server $Server | Invoke-RemotePipelineHandler -Result ([ref]$getExchangeVirtualDirectories)

            try {
                $getReceiveConnectors = Get-ReceiveConnector -Server $Server -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to run Get-ReceiveConnectors"
                Invoke-CatchActions
            }

            if ($getExchangeServer.IsEdgeServer -eq $false) {

                try {
                    $getMailboxServer = (Get-MailboxServer -Identity $Server -ErrorAction Stop)
                } catch {
                    Write-Verbose "Failed to run Get-MailboxServer"
                    Invoke-CatchActions
                }
            }

            Get-ExchangeServerMaintenanceState -Server $Server -ComponentsToSkip "ForwardSyncDaemon", "ProvisioningRps" |
                Invoke-RemotePipelineHandler -Result ([ref]$serverMaintenance)
            Get-ExchangeSettingOverride -Server $Server -CatchActionFunction ${Function:Invoke-CatchActions} |
                Invoke-RemotePipelineHandler -Result ([ref]$settingOverrides)

            if (($getExchangeServer.IsMailboxServer) -or
                ($getExchangeServer.IsEdgeServer)) {
                try {
                    $exchangeServicesNotRunning = @()
                    $testServiceHealthResults = Test-ServiceHealth -Server $Server -ErrorAction Stop
                    foreach ($notRunningService in $testServiceHealthResults.ServicesNotRunning) {
                        if ($exchangeServicesNotRunning -notcontains $notRunningService) {
                            $exchangeServicesNotRunning += $notRunningService
                        }
                    }
                } catch {
                    Write-Verbose "Failed to run Test-ServiceHealth"
                    Invoke-CatchActions
                }

                try {
                    $getTransportService = Get-TransportService -Identity $Server -ErrorAction Stop
                } catch {
                    Write-Verbose "Failed to run Get-TransportService"
                    Invoke-CatchActions
                }
            }

            Write-Verbose "Getting Exchange Diagnostic Information for EdgeTransport"
            $params = @{
                Server    = $Server
                Process   = "EdgeTransport"
                Component = "ResourceThrottling"
            }
            Get-ExchangeDiagnosticInformation @params -CatchActionFunction ${Function:Invoke-CatchActions} | Invoke-RemotePipelineHandler -Result ([ref]$edgeTransportResourceThrottling)
            Get-MonitoringOverride -Server $Server | Invoke-RemotePipelineHandler -Result ([ref]$serverMonitoringOverride)

            try {
                $exchangeWebSites = $null
                Get-ExchangeWebSitesFromAd -ComputerName $Server | Invoke-RemotePipelineHandler -Result ([ref]$exchangeWebSites)

                if ($exchangeWebSites.Count -gt 2) {
                    Write-Verbose "Multiple OWA/ECP virtual directories detected"
                }
                Write-Verbose "Exchange websites detected: $([string]::Join(", " ,$exchangeWebSites))"
            } catch {
                Write-Verbose "Failed to get the Exchange Web Sites from Ad."
                $exchangeWebSites = $null
                Invoke-CatchActions
            }

            # TODO: Address issue https://github.com/microsoft/CSS-Exchange/issues/2252
            # AD Module cmdlets don't appear to work in remote context with Invoke-Command, this is why it is now moved outside of the Invoke-ScriptBlockHandler.
            try {
                Write-Verbose "Trying to get the computer DN"
                $adComputer = (Get-ADComputer ($Server.Split(".")[0]) -ErrorAction Stop -Properties MemberOf)
                $computerDN = $adComputer.DistinguishedName
                Write-Verbose "Computer DN: $computerDN"
                $params = @{
                    Identity    = $computerDN
                    ErrorAction = "Stop"
                }
                try {
                    $serverId = ([ADSI]("GC://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")).dnsHostName.ToString()
                    Write-Verbose "Adding ServerId '$serverId' to the Get-AD* cmdlets"
                    $params["Server"] = $serverId
                } catch {
                    Write-Verbose "Failed to find the root DSE. Inner Exception: $_"
                    Invoke-CatchActions
                }
                $adPrincipalGroupMembership = (Get-ADPrincipalGroupMembership @params)
            } catch [System.Management.Automation.CommandNotFoundException] {
                if ($_.TargetObject -eq "Get-ADComputer") {
                    $adPrincipalGroupMembership = "NoAdModule"
                    Invoke-CatchActions
                } else {
                    # If this occurs, do not run Invoke-CatchActions to let us know what is wrong here.
                    Write-Verbose "CommandNotFoundException thrown, but not for Get-ADComputer. Inner Exception: $_"
                }
            } catch {
                Write-Verbose "Failed to get the AD Principal Group Membership. Inner Exception: $_"
                Invoke-CatchActions
                if ($null -eq $adComputer -or
                    $null -eq $adComputer.MemberOf -or
                    $adComputer.MemberOf.Count -eq 0) {
                    Write-Verbose "Failed to get the ADComputer information to be able to find the MemberOf with Get-ADObject"
                } else {
                    $adPrincipalGroupMembership = New-Object System.Collections.Generic.List[object]
                    foreach ($memberDN in $adComputer.MemberOf) {
                        try {
                            $params = @{
                                Filter      = "distinguishedName -eq `"$memberDN`""
                                Properties  = "objectSid"
                                ErrorAction = "Stop"
                            }

                            if (-not([string]::IsNullOrEmpty($serverId))) {
                                $params["Server"] = "$($serverId):3268" # Needs to be a GC port incase we are looking for a group outside of this domain.
                            }
                            $adObject = Get-ADObject @params

                            if ($null -eq $adObject) {
                                Write-Verbose "Failed to find AD Object with filter '$($params.Filter)' on server '$($params.Server)'"
                                continue
                            }

                            $adPrincipalGroupMembership.Add([PSCustomObject]@{
                                    Name              = $adObject.Name
                                    DistinguishedName = $adObject.DistinguishedName
                                    ObjectGuid        = $adObject.ObjectGuid
                                    SID               = $adObject.objectSid
                                })
                        } catch {
                            # Currently do not add Invoke-CatchActions as we want to be aware if this doesn't fix some things.
                            Write-Verbose "Failed to run Get-ADObject against '$memberDN'. Inner Exception: $_"
                        }
                    }
                }
            }
            $computerMembership = [PSCustomObject]@{
                ADGroupMembership = $adPrincipalGroupMembership
            }

            if ($PSSenderInfo) {
                $jobHandledErrors = $Script:ErrorsExcluded
            }

            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to complete processing server."
            # Place the object on the pipeline
            [PSCustomObject]@{
                ServerObjectId                  = $Server
                GetExchangeServer               = $getExchangeServer
                VirtualDirectories              = $getExchangeVirtualDirectories
                GetMailboxServer                = $getMailboxServer
                GetReceiveConnector             = $getReceiveConnectors
                ExchangeConnectors              = $exchangeConnectors
                ExchangeServicesNotRunning      = [array]$exchangeServicesNotRunning
                GetTransportService             = $getTransportService
                ServerMaintenance               = $serverMaintenance
                EdgeTransportResourceThrottling = $edgeTransportResourceThrottling # If we want to checkout other diagnosticInfo, we should create a new object here.iisSettings
                SettingOverrides                = $settingOverrides
                ComputerMembership              = $computerMembership
                GetServerMonitoringOverride     = $serverMonitoringOverride
                ExchangeCertificateInformation  = $exchangeCertificateInformation
                ExchangeWebSiteNames            = $exchangeWebSites
                RemoteJob                       = $true -eq $PSSenderInfo
                JobHandledErrors                = $jobHandledErrors
            }
        }
    }
    end {
        Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($jobStopWatch.Elapsed.TotalSeconds) seconds"
    }
}
