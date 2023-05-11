# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

<#
    This collects the current state of the Search Processes on the server
    It flags if there is a possible issue by a few different checks.
        - Services Running
        - Services are set to Automatic
        - All 6 processes are up and running and have been for at least 1 hour.
            -> This is to detect possible crashes that might be occurring.
        - Are there 3rd party modules loaded into the process. This can have negative impact to the service.
#>
function Get-SearchProcessState {
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )
    begin {

        function GetSearchProcessStateScriptBlock {

            $admin = "AdminNode1"
            $content = "ContentEngineNode1"
            $index = "IndexNode1"
            $interaction = "InteractionEngineNode1"
            $node = "noderunner"

            $getSearchServices = Get-Service | Where-Object {
                $_.Name -eq "HostControllerService" -or
                $_.Name -eq "MSExchangeFastSearch"
            } | ForEach-Object {
                # Going to include value for non-english OSs
                [PSCustomObject]@{
                    Name           = $_.Name
                    StatusValue    = $_.Status.Value__ # 4 = Running
                    StartTypeValue = $_.StartType.Value__ # 2 = Automatic
                    Status         = $_.Status.ToString()
                    StartType      = $_.StartType.ToString()
                }
            }

            #This is to get the command line information and know which node runner is which
            $nodeRunner = Get-CimInstance Win32_Process -Filter "name = 'noderunner.exe'"
            $searchProcesses = Get-Process | Where-Object {
                $_.Name -eq "noderunner" -or
                $_.Name -eq "hostcontrollerservice" -or
                $_.Name -eq "Microsoft.Exchange.Search.Service"
            }

            $returnProcesses = New-Object 'System.Collections.Generic.List[object]'
            # Foreach of the processes collect some minor information
            foreach ($process in $searchProcesses) {
                # Only return 3 party modules, as that should be the only thing we care about.
                $thirdPartyModule = New-Object 'System.Collections.Generic.List[object]'
                $process.Modules | Where-Object {
                    $_.Company -notlike "*Microsoft*" -and
                    $_.ModuleName -ne "ManagedBlingSigned.dll"
                } | ForEach-Object {
                    $thirdPartyModule.Add([PSCustomObject]@{
                            ModuleName = $_.ModuleName
                            Company    = $_.Company
                            FileName   = $_.FileName
                        })
                }

                # Need to know which node runners are having an issue.
                # To known this, we need to look at the command line of the process
                $processFriendlyDisplayName = $process.Name

                if ($processFriendlyDisplayName -eq $node) {
                    $cmdLine = ($nodeRunner | Where-Object { $_.ProcessId -eq $process.Id }).CommandLine

                    if ($cmdLine -like "*$admin*") {
                        $processFriendlyDisplayName = "$node - $admin"
                    } elseif ($cmdLine -like "*$content*") {
                        $processFriendlyDisplayName = "$node - $content"
                    } elseif ($cmdLine -like "*$index*") {
                        $processFriendlyDisplayName = "$node - $index"
                    } elseif ($cmdLine -like "*$interaction*") {
                        $processFriendlyDisplayName = "$node - $interaction"
                    }
                }

                $returnProcesses.Add([PSCustomObject]@{
                        Name              = $processFriendlyDisplayName
                        PID               = $process.Id
                        StartTime         = $process.StartTime
                        ThirdPartyModules = $thirdPartyModule
                    })
            }

            return [PSCustomObject]@{
                Services    = $getSearchServices
                Processes   = $returnProcesses
                CurrentTime = [DateTime]::Now
            }
        }

        $requiredProcessNames = @("hostcontrollerservice",
            "microsoft.exchange.search.service",
            "noderunner - AdminNode1",
            "noderunner - ContentEngineNode1",
            "noderunner - IndexNode1",
            "noderunner - InteractionEngineNode1")

        $latestProcessStartTime = [DateTime]::MinValue
        $processesNotRunning = New-Object 'System.Collections.Generic.List[string]'
        $servicesNotCorrect = New-Object 'System.Collections.Generic.List[object]'
        $processesRunningForOneHour = $true
        $thirdPartyModuleFound = $false
    }
    process {

        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = ${Function:GetSearchProcessStateScriptBlock}
        }

        $processInformation = Invoke-ScriptBlockHandler @params

        # Now that we have all the correct data, process it for the following:
        # Services are running and automatic
        # all 6 required processes are running

        foreach ($requiredProcessName in $requiredProcessNames) {
            $check = $processInformation.Processes | Where-Object { $_.Name -eq $requiredProcessName }

            if ($null -eq $check) { $processesNotRunning.Add($requiredProcessName) }
        }

        foreach ($service in $processInformation.Services) {
            if ($service.StatusValue -ne 4 -or
                $service.StartTypeValue -ne 2) {
                $servicesNotCorrect.Add([PSCustomObject]@{
                        Name      = $service.Name
                        Status    = $service.Status
                        StartType = $service.StartType
                    })
            }
        }

        foreach ($process in $processInformation.Processes) {

            if ($process.StartTime -gt ($processInformation.CurrentTime.AddHours(-1))) {
                $processesRunningForOneHour = $false
            }

            if ($process.StartTime -gt $latestProcessStartTime) {
                $latestProcessStartTime = $process.StartTime
            }

            if ($process.ThirdPartyModules.Count -gt 0) {
                $thirdPartyModuleFound = $true
            }
        }
    }
    end {
        return [PSCustomObject]@{
            ServerName              = $ComputerName
            ProcessInformation      = $processInformation
            ServicesConfigCorrectly = $servicesNotCorrect.Count -eq 0
            ServicesNotCorrect      = $servicesNotCorrect
            AllProcessesRunning     = $processesNotRunning.Count -eq 0
            ProcessesNotRunning     = $processesNotRunning
            RunForAnHour            = $processesRunningForOneHour
            ThirdPartyModuleFound   = $thirdPartyModuleFound
            LatestProcessStartTime  = $latestProcessStartTime
        }
    }
}
