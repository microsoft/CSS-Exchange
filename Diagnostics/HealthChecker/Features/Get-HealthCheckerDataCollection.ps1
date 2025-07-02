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
. $PSScriptRoot\..\..\..\Shared\ScriptDebugFunctions.ps1

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

        $progressDataCollectionParams = @{
            Activity = "Setting up jobs to queue for data collection"
            ParentId = 0
            Id       = 1
            Status   = [string]::Empty
        }
    }
    process {
        # Loop through all the server names provided to make sure they are an Exchange server, and to get the FQDN for them.
        if (-not $ForceLegacy) {
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $stopWatchGetExchange = New-Object System.Diagnostics.Stopwatch
            $getExchangeServerListToTestFQDN = @{}
            $getExchServerCount = 1
            foreach ($serverName in $ServerNames) {
                try {
                    $progressDataCollectionParams.Status = "Running Get-ExchangeServer for passed server names $getExchServerCount / $($ServerNames.Count)"
                    $getExchServerCount++
                    Write-Progress @progressDataCollectionParams
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
            $progressDataCollectionParams.Status = "Verifying Invoke-Command works against the servers for FQDN"
            Write-Progress @progressDataCollectionParams
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
                $progressDataCollectionParams.Status = "$($getExchangeServerListToTestFQDN.Count) failed to be reached by FQDN testing out Name instead"
                Write-Progress @progressDataCollectionParams
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
        Add-DebugObject -ObjectKeyName "GetExchangeServerList" -ObjectValueEntry $getExchangeServerList

        if ($ForceLegacy) {
            try {
                $getExchangeServer = Get-ExchangeServer ($ServerNames[0]) -ErrorAction Stop
                $getExchangeServerList.Add($getExchangeServer.Name, $getExchangeServer)
            } catch {
                Write-Error "Unable to find Exchange Server $ServerNames" -ErrorAction Stop
            }

            $jobResults = @{}
            $exchCmdletJobResults = @{}
            $progressDataCollectionParams.Activity = "Legacy Data Collection Locally Only"
            $progressDataCollectionParams.Status = "Getting Organization Information"
            Write-Progress @progressDataCollectionParams
            $orgCmdletJobResults = Invoke-JobOrganizationInformation
            $progressDataCollectionParams.Status = "Getting Exchange Cmdlet Information"
            Write-Progress @progressDataCollectionParams
            $exchCmdletValue = Invoke-JobExchangeInformationCmdlet -ServerName $getExchangeServer.Name
            $exchCmdletJobResults.Add("$exchCmdletKey-$($getExchangeServer.Name)", $exchCmdletValue)
            $progressDataCollectionParams.Status = "Getting Hardware Information"
            Write-Progress @progressDataCollectionParams
            $hardwareValue = Invoke-JobHardwareInformation
            $jobResults.Add("$hardwareKey-$($getExchangeServer.Name)", $hardwareValue)
            $progressDataCollectionParams.Status = "Getting Operating System Information"
            Write-Progress @progressDataCollectionParams
            $osValue = Invoke-JobOperatingSystemInformation
            $jobResults.Add("$osKey-$($getExchangeServer.Name)", $osValue)
            $progressDataCollectionParams.Status = "Getting Exchange Local Information"
            Write-Progress @progressDataCollectionParams
            $exchLocalValue = Invoke-JobExchangeInformationLocal -GetExchangeServer $getExchangeServer
            $jobResults.Add("$exchLocalKey-$($getExchangeServer.Name)", $exchLocalValue)
        } else {
            # Add all the jobs to the queue that we need.
            if ($orgRunType -eq "QueueJob") {
                $progressDataCollectionParams.Status = "Adding Job Organization Information to Queue"
                Write-Progress @progressDataCollectionParams
                Add-JobOrganizationInformation
            }

            foreach ($serverName in $getExchangeServerList.Keys) {
                $progressDataCollectionParams.Status = "Adding Local Server Data Collection Jobs for $serverName"
                Write-Progress @progressDataCollectionParams
                Add-JobHardwareInformation -ComputerName $serverName
                Add-JobOperatingSystemInformation -ComputerName $serverName
                Add-JobExchangeInformationLocal -ComputerName $serverName -GetExchangeServer ($getExchangeServerList[$serverName])
            }

            if ($exchCmdletRunType -eq "CurrentSession") {
                $exchCmdletJobResults = @{}
                foreach ($serverName in $getExchangeServerList.Keys) {
                    $progressDataCollectionParams.Status = "Getting Exchange Cmdlet Information in current PowerShell session for Server $serverName"
                    Write-Progress @progressDataCollectionParams
                    $data = Invoke-JobExchangeInformationCmdlet -ServerName $serverName
                    $exchCmdletJobResults.Add("$exchCmdletKey-$serverName", $data)
                }
            } else {
                $progressDataCollectionParams.Status = "Adding Jobs for all the Exchange Server Cmdlet information to the queue"
                Write-Progress @progressDataCollectionParams
                $getExchangeServerList.Keys | Add-JobExchangeInformationCmdlet -JobKeyMatchingToServer ([ref]$exchCmdletServerJobData)
            }

            if ($orgRunType -eq "CurrentSession") {
                $progressDataCollectionParams.Status = "Collecting Organization Information in current PowerShell session"
                Write-Progress @progressDataCollectionParams
                $orgCmdletJobResults = Invoke-JobOrganizationInformation
            }

            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to complete the Add-JobExchangeInformationCmdlet $exchCmdletRunType"
            # TODO: Create proper Receive Job Action to handle the errors that we see in the logging location as well.
            # AND/OR improve the error logging inside remote
            Wait-JobQueue -ProcessReceiveJobAction ${Function:Invoke-RemotePipelineLoggingLocal}
            $jobResults = Get-JobQueueResult
            Write-Verbose "Job Queue and Get Results time taken $($stopWatch.Elapsed.TotalSeconds) seconds"
            Write-Verbose "Saving out the JobQueue prior to clearing it."
            Add-DebugObject -ObjectKeyName "GetJobQueue-AfterDataCollection" -ObjectValueEntry ((Get-JobQueue).Clone())
            Clear-JobQueue
        }

        $healthCheckerData = New-Object System.Collections.Generic.List[object]
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $createObjectCounter = 1

        foreach ($serverName in $getExchangeServerList.Keys) {
            $progressDataCollectionParams.Status = "Organizing Data Structures for Servers. $createObjectCounter / $($getExchangeServerList.Count)"
            $createObjectCounter++
            Write-Progress @progressDataCollectionParams

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
            $dataObject = Get-HealthCheckerDataObject @params
            Add-DebugObject -ObjectKeyName "Get-HealthCheckerDataObject" -ObjectValueEntry $dataObject
            $healthCheckerData.Add($dataObject)
        }
        Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to create the Health Checker object list"
        Write-Progress @progressDataCollectionParams -Completed
        return $healthCheckerData
    }
}
