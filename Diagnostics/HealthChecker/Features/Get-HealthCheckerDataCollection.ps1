# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Needs to be on top to avoid the function to be encapsulated
. $PSScriptRoot\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

. $PSScriptRoot\Get-HealthCheckerDataObject.ps1
. $PSScriptRoot\..\DataCollection\OrganizationInformation\Add-JobOrganizationInformation.ps1
. $PSScriptRoot\..\DataCollection\OrganizationInformation\Invoke-JobOrganizationInformation.ps1
. $PSScriptRoot\..\DataCollection\ServerInformation\Add-JobHardwareInformation.ps1
. $PSScriptRoot\..\DataCollection\ServerInformation\Add-JobOperatingSystemInformation.ps1
. $PSScriptRoot\..\DataCollection\ServerInformation\Invoke-JobHardwareInformation.ps1
. $PSScriptRoot\..\DataCollection\ServerInformation\Invoke-JobOperatingSystemInformation.ps1
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Add-JobExchangeInformationCmdlet.ps1
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Add-JobExchangeInformationLocal.ps1
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Invoke-JobExchangeInformationCmdlet.ps1
. $PSScriptRoot\..\DataCollection\ExchangeInformation\Invoke-JobExchangeInformationLocal.ps1
. $PSScriptRoot\..\..\..\Shared\JobManagementFunctions\Wait-JobQueue.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptBlockFunctions\RemoteSBLoggingFunctions.ps1

<#
    TODO:
        Write-Progress bar to be included
        Include Write-Warning in the debug logging
        Improve logic for determining what name to use FQDN or name.
#>
function Get-HealthCheckerDataCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerNames
    )
    begin {
        $exchCmdletRunType = $orgRunType = "QueueJob"
        $getExchangeServerList = @{}
        $Script:defaultOptimizedServerToJobSize = $DevTestingDefaultOptimizedServerToJobSize

        if (([System.Math]::Ceiling($ServerNames.Count / $defaultOptimizedServerToJobSize )) -eq 1) {
            $orgRunType = $exchCmdletRunType = "CurrentSession"
        }

        if ($ForceLegacy) {

            if ($ServerNames.Count -gt 1) {
                throw "ForceLegacy option is only available to run against the Exchange Server Locally"
            }

            if ($ServerNames.Split(".") -ne $env:COMPUTERNAME) {
                throw "ForceLegacy option is only available to run against the Exchange Server Locally. Please run on the server $ServerNames"
            }

            Write-Verbose "Force Legacy has been applied."
            $orgRunType = $exchCmdletRunType = "CurrentSession"
        }
    }
    process {
        # Loop through all the server names provided to make sure they are an Exchange server, and to get the FQDN for them.
        if (-not $ForceLegacy) {
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $stopWatchGetExchange = New-Object System.Diagnostics.Stopwatch
            $getExchangeServerListToTestFQDN = @{}
            foreach ($serverName in $ServerNames) {
                try {
                    $stopWatchGetExchange.Start()
                    $getExchangeServer = Get-ExchangeServer $serverName -ErrorAction Stop
                    $stopWatchGetExchange.Stop()
                    $getExchangeServerListToTestFQDN.Add($getExchangeServer.FQDN, $getExchangeServer)
                } catch {
                    Write-Warning "Unable to find server: $serverName"
                    Invoke-CatchActions
                }
            }

            # Now test out the results.
            $errorCount = $Error.Count
            $startTime = [DateTime]::Now
            [array]$invokeCommandResults = Invoke-Command -ComputerName @($getExchangeServerListToTestFQDN.Keys) -ScriptBlock { Get-Date } -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $_ | Add-Member -Name ReturnTime -MemberType NoteProperty -Value ([DateTime]::Now)
                    $_ | Add-Member -Name ExecuteStartTime -MemberType NoteProperty -Value $startTime
                    $_
                }
            Write-Verbose "Took $(([DateTime]::Now) - $startTime) to execute the Invoke-Command test for FQDN"

            if ($invokeCommandResults.Count -ne $getExchangeServerListToTestFQDN.Count) {
                Write-Verbose "Not all servers passed the FQDN test, this could be the result of a server being down, unable to connect via FQDN, or Invoke-Command doesn't work."
                # Remove all the ones from the list that passed
                foreach ($passed in $invokeCommandResults) {
                    $getExchangeServerList.Add($passed.PSComputerName, $getExchangeServerListToTestFQDN[$passed.PSComputerName])
                    $getExchangeServerListToTestFQDN.Remove($passed.PSComputerName)
                }
                Write-Verbose "Successfully was able to get the following servers for FQDN: $([string]::Join(", ", @($getExchangeServerList.Keys)))"
                Write-Verbose "Failed to get from the following servers for FQDN: $([string]::Join(", ", @($getExchangeServerListToTestFQDN.Keys)))"
                # Now we need to go through what is left to see if we can get to it by server name vs FQDN
                $startTime = [DateTime]::Now
                [array]$invokeCommandResults = Invoke-Command -ComputerName @($getExchangeServerListToTestFQDN.Values.Name) -ScriptBlock { Get-Date } -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $_ | Add-Member -Name ReturnTime -MemberType NoteProperty -Value ([DateTime]::Now)
                        $_ | Add-Member -Name ExecuteStartTime -MemberType NoteProperty -Value $startTime
                        $_
                    }
                Write-Verbose "Took $(([DateTime]::Now) - $startTime) to execute the Invoke-Command test for server name"

                foreach ($passed in $invokeCommandResults) {
                    $key = $getExchangeServerListToTestFQDN.Values | Where-Object { $_.Name -eq $passed }
                    $getExchangeServerList.Add($passed.PSComputerName, $getExchangeServerListToTestFQDN[$key.FQDN])
                    $getExchangeServerListToTestFQDN.Remove($key.FQDN)
                }
                Write-Verbose "Successfully was able to get the following servers for server name: $([string]::Join(", ", @($invokeCommandResults.PSComputerName)))"
                Write-Verbose "Failed to get from the following servers for server name: $([string]::Join(", ", @($getExchangeServerListToTestFQDN.Keys)))"

                if ($getExchangeServerListToTestFQDN.Count -gt 0) {
                    Write-Warning "Failed to connect to the following servers: $([string]::Join(", ", @($getExchangeServerListToTestFQDN.Keys))). Please run locally."
                }
            } else {
                Write-Verbose "All Servers Passed FQDN test"
                $getExchangeServerList = $getExchangeServerListToTestFQDN
            }

            Invoke-ErrorCatchActionLoopFromIndex $errorCount
            Write-Verbose "Took $($stopWatchGetExchange.Elapsed.TotalSeconds) seconds to just run Get-ExchangeServer."
            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to get the Exchange Server and determine what names we can use."
        }

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

        if ($ForceLegacy) {
            try {
                $getExchangeServer = Get-ExchangeServer ($ServerNames[0]) -ErrorAction Stop
                $getExchangeServerList.Add($getExchangeServer.Name, $getExchangeServer)
            } catch {
                Write-Error "Unable to find Exchange Server $ServerNames" -ErrorAction Stop
            }

            $jobResults = @{}
            $exchCmdletJobResults = @{}
            $orgCmdletJobResults = Invoke-JobOrganizationInformation
            $exchCmdletValue = Invoke-JobExchangeInformationCmdlet -ServerName $getExchangeServer.Name
            $exchCmdletJobResults.Add("$exchCmdletKey-$($getExchangeServer.Name)", $exchCmdletValue)
            $hardwareValue = Invoke-JobHardwareInformation
            $jobResults.Add("$hardwareKey-$($getExchangeServer.Name)", $hardwareValue)
            $osValue = Invoke-JobOperatingSystemInformation
            $jobResults.Add("$osKey-$($getExchangeServer.Name)", $osValue)
            $exchLocalValue = Invoke-JobExchangeInformationLocal -GetExchangeServer $getExchangeServer
            $jobResults.Add("$exchLocalKey-$($getExchangeServer.Name)", $exchLocalValue)
        } else {
            # Add all the jobs to the queue that we need.
            if ($orgRunType -eq "QueueJob") {
                Add-JobOrganizationInformation
            }

            foreach ($serverName in $getExchangeServerList.Keys) {
                Add-JobHardwareInformation -ComputerName $serverName
                Add-JobOperatingSystemInformation -ComputerName $serverName
                Add-JobExchangeInformationLocal -ComputerName $serverName -GetExchangeServer ($getExchangeServerList[$serverName])
            }

            if ($exchCmdletRunType -eq "CurrentSession") {
                $exchCmdletJobResults = @{}
                foreach ($serverName in $getExchangeServerList.Keys) {
                    $data = Invoke-JobExchangeInformationCmdlet -ServerName $serverName
                    $exchCmdletJobResults.Add("$exchCmdletKey-$serverName", $data)
                }
            } else {
                $getExchangeServerList.Keys | Add-JobExchangeInformationCmdlet -JobKeyMatchingToServer ([ref]$exchCmdletServerJobData)
            }

            if ($orgRunType -eq "CurrentSession") {
                $orgCmdletJobResults = Invoke-JobOrganizationInformation
            }

            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to complete the Add-JobExchangeInformationCmdlet $exchCmdletRunType"
            # TODO: Create proper Receive Job Action to handle the errors that we see in the logging location as well.
            # AND/OR improve the error logging inside remote
            Wait-JobQueue -ProcessReceiveJobAction ${Function:Invoke-RemotePipelineLoggingLocal}
            $jobResults = Get-JobQueueResult
            Write-Verbose "Job Queue and Get Results time taken $($stopWatch.Elapsed.TotalSeconds) seconds"
            Clear-JobQueue
        }

        $healthCheckerData = New-Object System.Collections.Generic.List[object]
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        foreach ($serverName in $getExchangeServerList.Keys) {

            if ($orgRunType -eq "CurrentSession" -or $null -ne $orgCmdletJobResults) {
                if ($null -eq $orgCmdletJobResults) {
                    throw "Organization Cmdlet Job Results NULL from CurrentSession Option"
                }
                $organizationInformation = $orgCmdletJobResults
            } else {
                $organizationInformation = $jobResults[$orgKey]
            }

            if ($exchCmdletRunType -eq "CurrentSession" -or $null -ne $exchCmdletJobResults) {
                if ($null -eq $exchCmdletJobResults) {
                    throw "Exchange Cmdlet Job Results NULL from CurrentSession Option"
                }
                $exchCmdletResults = $exchCmdletJobResults["$exchCmdletKey-$serverName"]
            } elseif ($exchCmdletRunType -eq "QueueJob") {
                $exchCmdletResults = $jobResults[$exchCmdletServerJobData[$serverName]] | Where-Object { $_.ServerObjectId -eq $serverName }
            } else {
                $exchCmdletResults = $jobResults["$exchCmdletKey-$serverName"]
            }
            $exchLocalResults = $jobResults["$exchLocalKey-$serverName"]

            $params = @{
                OrganizationInformationResult = $organizationInformation
                ExchangeCmdletResult          = $exchCmdletResults
                ExchangeLocalResult           = $exchLocalResults
                HardwareInformationResult     = $jobResults["$hardwareKey-$serverName"]
                OSInformationResult           = $jobResults["$osKey-$serverName"]
                GenerationTime                = $generationTime
            }
            $healthCheckerData.Add((Get-HealthCheckerDataObject @params))
        }
        Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to create the Health Checker object list"
        return $healthCheckerData
    }
}
