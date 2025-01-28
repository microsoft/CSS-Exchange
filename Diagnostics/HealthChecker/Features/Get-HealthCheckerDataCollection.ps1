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
