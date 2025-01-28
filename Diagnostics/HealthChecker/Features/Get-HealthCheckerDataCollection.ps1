﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Analyzer\Add-AsyncJobAnalyzerEngine.ps1
. $PSScriptRoot\..\DataCollection\OrganizationInformation\Add-JobOrganizationInformation.ps1
. $PSScriptRoot\..\DataCollection\ServerInformation\Add-JobHardwareInformation.ps1
. $PSScriptRoot\..\DataCollection\ServerInformation\Add-JobOperatingSystemInformation.ps1
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Add-JobExchangeInformationCmdlet.ps1
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Add-JobExchangeInformationLocal.ps1
. $PSScriptRoot\..\..\..\Shared\JobManagement\Wait-JobQueue.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptBlock\RemoteSBLoggingFunctions.ps1

<#
    TODO:
        Write-Progress bar to be included
        Include Write-Warning in the debug logging
        Improve logic for determining what name to use FQDN or name.

    DevTestingScenario described here:
        LegacyOption: Run HealthChecker in Synchronous mode
        MainScenario: Is the mode that we believe is going to be the best performing option

            Scenario1:
                Data Collection Jobs are started with Sync Job (doesn't start till we wait for it)
                ExchCmdlets Jobs are all done per server in its own job
                Wait for all data collection jobs to be done before next step
                Analyzer is done with Async (starts once it is added to the queue)
                Write out the results on the main PS session
            Scenario2:
                Data Collection Jobs are started with Async Job (starts once added to the queue)
                ExchCmdlets Jobs are run in the main PowerShell session
                Wait for all data collection jobs to be done before next step
                Analyzer is done with Async 9starts once it is added to the queue)
                Write out the results on the main PS session
            Scenario3:
                Data Collection Jobs are started with Async Job (starts once added to the queue)
                ExchCmdlets Jobs are broken up to determine how to best handle
                Wait for all data collection jobs to be done before next step
                Analyzer is done with Async (starts once it is added to the queue)
                Write out the results on the main PS session
#>
function Get-HealthCheckerDataCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerNames
    )
    begin {

        function TestComputerName {
            [CmdletBinding()]
            [OutputType([bool])]
            param(
                [string]$ComputerName
            )
            try {
                Write-Verbose "Testing $ComputerName"

                # If local computer, we should just assume that it should work.
                if ($ComputerName -eq $env:COMPUTERNAME) {
                    Write-Verbose "Local computer, returning true"
                    return $true
                }

                Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-Date } -ErrorAction Stop | Out-Null
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName)
                $reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion") | Out-Null
                Write-Verbose "Returning true back"
                return $true
            } catch {
                Write-Verbose "Failed to run against $ComputerName"
                Invoke-CatchActions
            }
            return $false
        }

        if ($DevTestingScenario -eq "MainScenario") {
            # Set to the current main scenario that appears to work the best.
            $DevTestingScenario = "Scenario1"
        }

        Write-Verbose "DevTestingScenario is set to $DevTestingScenario"
        $hardwareRunType = $osRunType = $exchLocalRunType = $orgRunType = "StartNow"
        $exchCmdletRunType = "QueueOptimize"
        $getExchangeServerList = @{}
    }
    process {
        # Loop through all the server names provided to make sure they are an Exchange server, and to get the FQDN for them.
        $mainStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        foreach ($serverName in $ServerNames) {
            try {
                $getExchangeServer = Get-ExchangeServer $serverName -ErrorAction Stop
                # test the name to know what we are going to use for the Invoke-Command logic.
                $serverKeyName = $getExchangeServer.FQDN
                if (-not (TestComputerName $getExchangeServer.FQDN)) {
                    if (-not (TestComputerName $getExchangeServer.Name)) {
                        Write-Warning "Unable to connect to server $serverName. Please run locally"
                        continue
                    }
                    $serverKeyName = $getExchangeServer.Name
                }

                $getExchangeServerList.Add($serverKeyName, $getExchangeServer)
            } catch {
                Write-Warning "Unable to find server: $serverName"
                Invoke-CatchActions
            }
        }
        Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to get the Exchange Server and determine what names we can use."

        # Set the script variable for the name of the computer that we want to connect to for EMS
        $Script:PrimaryRemoteShellConnectionPoint = (Get-PSSession | Where-Object { $_.Availability -eq "Available" -and $_.State -eq "Opened" } | Select-Object -First 1).ComputerName
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $orgKey = "Invoke-JobOrganizationInformation"
        $hardwareKey = "Invoke-JobHardwareInformation"
        $osKey = "Invoke-JobOperatingSystemInformation"
        $exchCmdletKey = "Invoke-JobExchangeInformationCmdlet"
        $exchLocalKey = "Invoke-JobExchangeInformationLocal"
        $generationTime = Get-Date
        $exchCmdletServerJobData = @{}

        if ($DevTestingScenario -eq "LegacyOption") {
            # TODO
        } else {
            # Add all the jobs to the queue that we need.
            Add-JobOrganizationInformation -RunType $orgRunType

            foreach ($serverName in $getExchangeServerList.Keys) {
                Add-JobHardwareInformation -ComputerName $serverName -RunType $hardwareRunType
                Add-JobOperatingSystemInformation -ComputerName $serverName -RunType $osRunType
                Add-JobExchangeInformationLocal -ComputerName $serverName -GetExchangeServer ($getExchangeServerList[$serverName]) -RunType $exchLocalRunType
            }

            $exchCmdletJobResults = $getExchangeServerList.Keys | Add-JobExchangeInformationCmdlet -RunType $exchCmdletRunType -JobKeyMatchingToServer ([ref]$exchCmdletServerJobData)
            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to complete the Add-JobExchangeInformationCmdlet $exchCmdletRunType" -Verbose
            # TODO: Create proper Receive Job Action to handle the errors that we see in the logging location as well.
            # AND/OR improve the error logging inside remote
            Wait-JobQueue -ProcessReceiveJobAction ${Function:Invoke-RemotePipelineLoggingLocal}
            $jobResults = Get-JobQueueResult
        }

        Write-Verbose "Job Queue and Get Results time taken $($stopWatch.Elapsed.TotalSeconds) seconds" -Verbose
        Clear-JobQueue

        $healthCheckerData = New-Object System.Collections.Generic.List[object]
        $waitAsyncList = New-Object System.Collections.Generic.List[string]
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        foreach ($serverName in $getExchangeServerList.Keys) {

            if ($exchCmdletRunType -eq "Legacy") {
                if ($null -eq $exchCmdletJobResults) {
                    throw "Exchange Cmdlet Job Results NULL from Legacy Option"
                }
                $exchCmdletResults = $exchCmdletJobResults["$exchCmdletKey-$serverName"]
            } elseif ($exchCmdletRunType -eq "QueueOptimize") {
                $exchCmdletResults = $jobResults[$exchCmdletServerJobData[$serverName]] | Where-Object { $_.ServerObjectId -eq $serverName }
            } else {
                $exchCmdletResults = $jobResults["$exchCmdletKey-$serverName"]
            }
            $exchLocalResults = $jobResults["$exchLocalKey-$serverName"]

            $hcObject = [PSCustomObject]@{
                GenerationTime          = $generationTime
                ServerName              = $serverName
                HardwareInformation     = $jobResults["$hardwareKey-$serverName"]
                OSInformation           = $jobResults["$osKey-$serverName"]
                OrganizationInformation = $jobResults[$orgKey]
                ExchangeInformation     = [PSCustomObject]@{
                    EdgeTransportResourceThrottling          = $exchCmdletResults.EdgeTransportResourceThrottling
                    ExchangeServicesNotRunning               = $exchCmdletResults.ExchangeServicesNotRunning
                    GetExchangeServer                        = $exchCmdletResults.GetExchangeServer
                    GetMailboxServer                         = $exchCmdletResults.GetMailboxServer
                    GetServerMonitoringOverride              = $exchCmdletResults.GetServerMonitoringOverride
                    GetTransportService                      = $exchCmdletResults.GetTransportService
                    GetReceiveConnector                      = $exchCmdletResults.GetReceiveConnector
                    ServerMaintenance                        = $exchCmdletResults.ServerMaintenance
                    SettingOverrides                         = $exchCmdletResults.SettingOverrides
                    VirtualDirectories                       = $exchCmdletResults.VirtualDirectories
                    ExchangeCertificateInformation           = $exchCmdletResults.ExchangeCertificateInformation
                    ComputerMembership                       = [PSCustomObject]@{
                        ADGroupMembership = $exchCmdletResults.ComputerMembership.ADGroupMembership
                        LocalGroupMember  = $exchLocalResults.ComputerMembership.LocalGroupMember
                    }
                    AES256CBCInformation                     = $exchLocalResults.AES256CBCInformation
                    ApplicationConfigFileStatus              = $exchLocalResults.ApplicationConfigFileStatus
                    ApplicationPools                         = $exchLocalResults.ApplicationPools
                    BuildInformation                         = $exchLocalResults.BuildInformation
                    DependentServices                        = $exchLocalResults.DependentServices
                    ExchangeEmergencyMitigationServiceResult = $exchLocalResults.ExchangeEmergencyMitigationServiceResult
                    ExchangeFeatureFlightingServiceResult    = $exchLocalResults.ExchangeFeatureFlightingServiceResult
                    ExtendedProtectionConfig                 = $exchLocalResults.ExtendedProtectionConfig
                    FileContentInformation                   = $exchLocalResults.FileContentInformation
                    FIPFSUpdateIssue                         = $exchLocalResults.FIPFSUpdateIssue
                    IanaTimeZoneMappingsRaw                  = $exchLocalResults.IanaTimeZoneMappingsRaw
                    IISSettings                              = $exchLocalResults.IISSettings
                    RegistryValues                           = $exchLocalResults.RegistryValues
                }
            }

            if ($true) {
                # Write-Debug "Before asyncJob" -Debug
                Add-AsyncJobAnalyzerEngine -HealthServerObject $hcObject -RunType "StartNow"
                $waitAsyncList.Add("Invoke-JobAnalyzerEngine-$($hcObject.ServerName)")
            } else {
                $stopWatch2 = [System.Diagnostics.Stopwatch]::StartNew()
                $analyzedResults = Invoke-AnalyzerEngine -HealthServerObject $hcObject
                Write-Verbose "After analyzer as $($stopWatch2.Elapsed.TotalSeconds) seconds" -Verbose
                Write-ResultsToScreen -ResultsToWrite $analyzedResults.DisplayResults
                Write-Verbose "Took $($stopWatch2.Elapsed.TotalSeconds) seconds for analyzer and results" -Verbose
                $healthCheckerData.Add($hcObject)
            }
        }
        Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to start and queue the analyzer results" -Verbose

        if ($true) {
            Wait-JobQueue -ProcessReceiveJobAction ${Function:Invoke-RemotePipelineLoggingLocal}
            $jobResults = Get-JobQueueResult
            Write-Verbose "All servers to complete analyzed results $($stopWatch.Elapsed.TotalSeconds) seconds" -Verbose
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            foreach ($key in $jobResults.Keys) {
                $analyzedResults = $jobResults[$key].HCAnalyzedResults
                $serverName = $analyzedResults.HealthCheckerExchangeServer.ServerName
                Invoke-SetOutputInstanceLocation -Server $serverName -FileName "HealthChecker" -IncludeServerName $true
                try {
                    $analyzedResults | Export-Clixml -Path $Script:OutXmlFullPath -Encoding UTF8 -Depth 2 -ErrorAction Stop -Force
                } catch {
                    Write-Verbose "Failed to Export-Clixml. Inner Exception: $_"
                    Write-Verbose "Converting HealthCheckerExchangeServer to json."
                    $outputXml = [PSCustomObject]@{
                        HealthCheckerExchangeServer = $null
                        HtmlServerValues            = $analyzedResults.HtmlServerValues
                        DisplayResults              = $analyzedResults.DisplayResults
                    }
                    try {
                        $jsonHealthChecker = $analyzedResults.HealthCheckerExchangeServer | ConvertTo-Json -Depth 6 -ErrorAction Stop
                        $outputXml.HealthCheckerExchangeServer = $jsonHealthChecker | ConvertFrom-Json -ErrorAction Stop
                        $outputXml | Export-Clixml -Path $Script:OutXmlFullPath -Encoding UTF8 -Depth 2 -ErrorAction Stop -Force
                        Write-Verbose "Successfully export out the data after the convert"
                    } catch {
                        Write-Red "Failed to Export-Clixml. Unable to export the data."
                    }
                }
                Write-HostLog "Exchange Health Checker version $Script:BuildVersion"
                Write-ResultsToScreen -ResultsToWrite $analyzedResults.DisplayResults
                Write-Grey "Output file written to $($Script:OutputFullPath)"
                Write-Grey "Exported Data Object Written to $($Script:OutXmlFullPath)"
            }
        }

        Write-Verbose "Writing out the screen took total $($stopWatch.Elapsed.TotalSeconds) seconds"
        Write-Verbose "Total time in script data collection took $($mainStopWatch.Elapsed.TotalSeconds) seconds"
    }
}
