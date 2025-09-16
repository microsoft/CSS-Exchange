# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
. $PSScriptRoot\..\Helpers\HiddenJobUnhandledErrorFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\JobManagementFunctions\Wait-JobQueue.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptBlockFunctions\RemoteSBLoggingFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptDebugFunctions.ps1

<#
.DESCRIPTION
    This is the function that you call to collect information for the Exchange Servers.
    It is responsible to setup and determine if we need to do jobs for particular actions or if we need to execute the code
    within the main PowerShell session.
    It will wait for all the jobs to have been completed, then create the proper data structure for the Health Checker analyzer to process.
    Then it will return a list of those object back to the caller.
#>
function Get-HealthCheckerDataCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ServerNames
    )
    begin {
        # By default, we want to queue the job so we set the run type to "QueueJob"
        $exchCmdletRunType = $orgRunType = "QueueJob"
        $getExchangeServerList = @{}
        # This is the default value that we want to batch the servers into for Exchange Cmdlet data collection
        # We can speed up the process of large server data collection by spinning up jobs vs having a bunch of servers
        # trying to process on a single main thread for this process. However, we need to be careful as connecting EMS takes some time.
        $Script:defaultOptimizedServerToJobSize = 8

        # If there isn't enough Exchange Servers to justify spinning up a job with EMS, we can do this quicker inside the main PowerShell thread here.
        # Therefore, we will set this to CurrentSession.
        if (([System.Math]::Ceiling($ServerNames.Count / $defaultOptimizedServerToJobSize )) -eq 1) {
            $orgRunType = $exchCmdletRunType = "CurrentSession"
        }

        # If the local server that is running the script is Windows Server 2012/R2, we can't use multi-threading, it must be legacy.
        $windows2016OrGreater = [environment]::OSVersion.Version -ge "10.0.0.0"

        if (-not $windows2016OrGreater) {
            if ($ServerNames.Count -eq 1) {
                Write-Verbose "Switching to ForceLegacy to run the script locally on Windows Server 2012/R2"
                $Script:ForceLegacy = $true
            } else {
                Write-Warning "Unable to run the script against multiple servers from a Windows Server 2012 or Windows Server 2012 R2. Please run from a different computer or run locally on the Exchange Server."
                throw "Unsupported OS Version"
            }
        }

        # ForceLegacy is for when we can't use jobs. Since we can't use jobs for some reason, we must only do this locally.
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
            # For each of the Exchange Servers, we want to test to see if Invoke-Command will work against them. If it doesn't we don't want those servers within our list to process.
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
                Write-Verbose "Successfully was able to get the following servers for FQDN: $([string]::Join(", ", [array]$getExchangeServerList.Keys))"
                Write-Verbose "Failed to get from the following servers for FQDN: $([string]::Join(", ", [array]$getExchangeServerListToTestFQDN.Keys))"
                # Now we need to go through what is left to see if we can get to it by server name vs FQDN
                # We have seen that in some environments, they aren't able to reach the server by the FQDN, which appears to be a bad network design.
                # However, we want to try to get the computer information by the server name instead.
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

                if ($invokeCommandResults.Count -gt 0) {
                    foreach ($passed in $invokeCommandResults) {
                        $key = $getExchangeServerListToTestFQDN.Values | Where-Object { $_.Name -eq $passed.PSComputerName }
                        $getExchangeServerList.Add($passed.PSComputerName, $getExchangeServerListToTestFQDN[$key.FQDN])
                        $getExchangeServerListToTestFQDN.Remove($key.FQDN)
                    }
                    Write-Verbose "Successfully was able to get the following servers for server name: $([string]::Join(", ", [array]$invokeCommandResults.PSComputerName))"
                }

                Write-Verbose "Failed to get from the following servers for server name: $([string]::Join(", ", [array]$getExchangeServerListToTestFQDN.Keys))"

                if ($getExchangeServerListToTestFQDN.Count -gt 0) {
                    Write-Warning "Failed to connect to the following servers: $([string]::Join(", ", [array]$getExchangeServerListToTestFQDN.Keys)). Please run locally."
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
            # When we are in a Forced Legacy mode, we just need walk through each step manually and set the excepted variables
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
            # We want to add Organization Information to the queue right away, because loading EMS takes a while and we want that job to start
            # right away, plus we are limited to the number jobs we will start locally on the server.
            # If we want to collect the data within the session for EMS information, we will do this last.
            if ($orgRunType -eq "QueueJob") {
                $progressDataCollectionParams.Status = "Adding Job Organization Information to Queue"
                Write-Progress @progressDataCollectionParams
                Add-JobOrganizationInformation
            }

            # Add each of the servers local jobs that need to be executed on the server that we want to collect data from.
            # Not all of it needs to be executed locally, but we have adjust the script to handle it this way and to avoid a lot of back and forward
            # communication between the script executing server and the server we are collecting data from. This way we just send an entire script block,
            # then in return, we just the a data object of the results we want.
            foreach ($serverName in $getExchangeServerList.Keys) {
                $progressDataCollectionParams.Status = "Adding Local Server Data Collection Jobs for $serverName"
                Write-Progress @progressDataCollectionParams
                Add-JobHardwareInformation -ComputerName $serverName
                Add-JobOperatingSystemInformation -ComputerName $serverName
                Add-JobExchangeInformationLocal -ComputerName $serverName -GetExchangeServer ($getExchangeServerList[$serverName])
            }

            # If we are on the current session, execute the main code of the Invoke data collection job here.
            if ($exchCmdletRunType -eq "CurrentSession") {
                $exchCmdletJobResults = @{}
                foreach ($serverName in $getExchangeServerList.Keys) {
                    $progressDataCollectionParams.Status = "Getting Exchange Cmdlet Information in current PowerShell session for Server $serverName"
                    Write-Progress @progressDataCollectionParams
                    $data = Invoke-JobExchangeInformationCmdlet -ServerName $serverName
                    # We need to set it to the hash table so we can grab this information later.
                    $exchCmdletJobResults.Add("$exchCmdletKey-$serverName", $data)
                }
            } else {
                # We want to queue up the job and start processing it right away.
                $progressDataCollectionParams.Status = "Adding Jobs for all the Exchange Server Cmdlet information to the queue"
                Write-Progress @progressDataCollectionParams
                $getExchangeServerList.Keys | Add-JobExchangeInformationCmdlet -JobKeyMatchingToServer ([ref]$exchCmdletServerJobData)
            }

            # We have determined that we need to collect the information in the local session as it would be faster, so lets now collect the data
            if ($orgRunType -eq "CurrentSession") {
                $progressDataCollectionParams.Status = "Collecting Organization Information in current PowerShell session"
                Write-Progress @progressDataCollectionParams
                $orgCmdletJobResults = Invoke-JobOrganizationInformation
            }

            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to complete the Add-JobExchangeInformationCmdlet $exchCmdletRunType"
            # This function will Wait until the jobs have been completed. It is possible to get stuck here.
            Wait-JobQueue -ProcessReceiveJobAction ${Function:Invoke-RemotePipelineLoggingLocal}
            # This will return the true results from what was set within all the jobs we have created.
            $jobResults = Get-JobQueueResult
            Write-Verbose "Job Queue and Get Results time taken $($stopWatch.Elapsed.TotalSeconds) seconds"
            # We want to see if the Jobs had any hidden errors that wasn't handled, let's bubble those up to become aware of them.
            $jobResults.Values | Where-Object { $null -ne $_ } | Invoke-HiddenJobUnhandledErrors
            Write-Verbose "Saving out the JobQueue prior to clearing it."
            Add-DebugObject -ObjectKeyName "GetJobQueue-AfterDataCollection" -ObjectValueEntry ((Get-JobQueue).Clone())
            # We want to clear the queue so we don't reuse the data again the next time we call Get-JobQueueResults
            Clear-JobQueue
        }

        $healthCheckerData = New-Object System.Collections.Generic.List[object]
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $createObjectCounter = 1

        # Now that we have all the data results stored in variables from all the jobs that were executed, we need to sort out the information.
        foreach ($serverName in $getExchangeServerList.Keys) {
            $progressDataCollectionParams.Status = "Organizing Data Structures for Servers. $createObjectCounter / $($getExchangeServerList.Count)"
            $createObjectCounter++
            Write-Progress @progressDataCollectionParams

            # We need to go through and properly set/determine where we stored the information. If it is in the jobResults variable or a different local variable.
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

            # it is possible that not all jobs completed properly. So before we try to create the object, lets make sure we have everything we need.
            if ($null -eq $organizationInformation -or
                $null -eq $exchCmdletResults -or
                $null -eq $exchLocalResults -or
                $null -eq $jobResults["$hardwareKey-$serverName"] -or
                $null -eq $jobResults["$osKey-$serverName"]) {
                Write-Verbose ("Didn't get all the information. OrgInfo: $($null -eq $organizationInformation) ExchCmdlet: $($null -eq $exchCmdletResults)" +
                    " ExchLocal: $($null -eq $exchLocalResults) Hardware: $($null -eq $jobResults["$hardwareKey-$serverName"]) OSInfo: $($null -eq $jobResults["$osKey-$serverName"])")
                Write-Warning "Failed to get all the required information for server $serverName to properly review the data. Try to collect the data locally."
                continue
            }

            # Create the standard data object to be analyzed then add it to the return object list.
            $dataObject = Get-HealthCheckerDataObject @params
            Add-DebugObject -ObjectKeyName "Get-HealthCheckerDataObject" -ObjectValueEntry $dataObject
            $healthCheckerData.Add($dataObject)
        }
        Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to create the Health Checker object list"
        Write-Progress @progressDataCollectionParams -Completed
        return $healthCheckerData
    }
}
