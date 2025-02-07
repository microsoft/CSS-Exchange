# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-MonitoringOverride.ps1

function Add-JobExchangeInformationCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    process {
        <#
            Non Default Script Block Dependencies
                Invoke-DefaultConnectExchangeShell
                Get-ExchangeContainer
                Get-MonitoringOverride
                Get-RemoteRegistrySubKey
        #>
        function Invoke-JobExchangeInformationCmdlet {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$Server
            )
            begin {
                # Build Process to add functions.
                . $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeDiagnosticInformation.ps1
                . $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeSettingOverride.ps1
                . $PSScriptRoot\Get-ExchangeServerCertificates.ps1
                . $PSScriptRoot\Get-ExchangeVirtualDirectories.ps1
                . $PSScriptRoot\Get-ExchangeConnectors.ps1
                . $PSScriptRoot\Get-ExchangeServerMaintenanceState.ps1

                if ($PSSenderInfo) {
                    $Script:ErrorsExcluded = @()
                }
                $exchangeCertificates = $null
                $exchangeConnectors = $null
                $serverMaintenance = $null
                $settingOverrides = $null
                $edgeTransportResourceThrottling = $null
                $serverMonitoringOverride = $null
                $getExchangeVirtualDirectories = $null

                Invoke-DefaultConnectExchangeShell
            }
            process {

                $getExchangeServer = Get-ExchangeServer -Identity $Server -Status # TODO: Determine if we want to keep the cmdlet with the status or have it be passed to this job.
                Get-ExchangeServerCertificates -Server $Server | Invoke-RemotePipelineHandler -Result ([ref]$exchangeCertificates)
                Get-ExchangeVirtualDirectories -Server $Server | Invoke-RemotePipelineHandler -Result ([ref]$getExchangeVirtualDirectories)

                if ($getExchangeServer.IsEdgeServer -eq $false) {
                    Write-Verbose "Query Exchange Connector settings via 'Get-ExchangeConnectors'"
                    Get-ExchangeConnectors -ComputerName $Server -CertificateObject $exchangeCertificates | Invoke-RemotePipelineHandler -Result ([ref]$exchangeConnectors)

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

                Write-Verbose "Getting Exchange Diagnostic Information"
                $params = @{
                    Server    = $Server
                    Process   = "EdgeTransport"
                    Component = "ResourceThrottling"
                }
                Get-ExchangeDiagnosticInformation @params | Invoke-RemotePipelineHandler -Result ([ref]$edgeTransportResourceThrottling)
                Get-MonitoringOverride -Server $Server | Invoke-RemotePipelineHandler -Result ([ref]$serverMonitoringOverride)

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
            }
            end {
                Write-Verbose "Completed: $($MyInvocation.MyCommand)"
                [PSCustomObject]@{
                    GetExchangeServer               = $getExchangeServer
                    VirtualDirectories              = $getExchangeVirtualDirectories
                    GetMailboxServer                = $getMailboxServer
                    ExchangeConnectors              = $exchangeConnectors
                    ExchangeServicesNotRunning      = [array]$exchangeServicesNotRunning
                    GetTransportService             = $getTransportService
                    ServerMaintenance               = $serverMaintenance
                    ExchangeCertificates            = [array]$exchangeCertificates
                    EdgeTransportResourceThrottling = $edgeTransportResourceThrottling # If we want to checkout other diagnosticInfo, we should create a new object here.iisSettings
                    SettingOverrides                = $settingOverrides
                    ComputerMembership              = $computerMembership
                    GetServerMonitoringOverride     = $serverMonitoringOverride
                    RemoteJob                       = $true -eq $PSSenderInfo
                    JobHandledErrors                = $jobHandledErrors
                }
            }
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobExchangeInformationCmdlet}
            IncludeScriptBlock = @(${Function:Invoke-DefaultConnectExchangeShell}, ${Function:Get-ExchangeContainer},
                ${Function:Get-MonitoringOverride})
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
        $params = @{
            JobCommand   = "Start-Job"
            JobParameter = @{
                ScriptBlock  = $scriptBlock
                ArgumentList = $ComputerName
            }
            JobId        = "Invoke-JobExchangeInformationCmdlet-$ComputerName"
        }
        Add-JobQueue @params
    }
}
