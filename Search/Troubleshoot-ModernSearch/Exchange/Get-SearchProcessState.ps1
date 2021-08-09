# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-SearchProcessState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'Cmdlet required')]
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )
    begin {

        Function Get-DefaultSettings {
            return [PSCustomObject]@{
                PID               = 0
                ThirdPartyModules = (New-Object 'System.Collections.Generic.List[object]')
                StartTime         = [DateTime]::MinValue
            }
        }
        $adminNodeName = "noderunner - AdminNode1"
        $contentNodeName = "noderunner - ContentEngineNode1"
        $indexNodeName = "noderunner - IndexNode1"
        $interactionNodeName = "noderunner - InteractionEngineNode1"

        $searchProcessState = @{}

        $searchProcessState.Add($adminNodeName, (Get-DefaultSettings))
        $searchProcessState.Add($contentNodeName, (Get-DefaultSettings))
        $searchProcessState.Add($indexNodeName, (Get-DefaultSettings))
        $searchProcessState.Add($interactionNodeName, (Get-DefaultSettings))
        $searchProcessState.Add("hostcontrollerservice", (Get-DefaultSettings))
        $searchProcessState.Add("microsoft.exchange.search.service", (Get-DefaultSettings))

        $serverSearchProcessState = [PSCustomObject]@{
            ServerName             = $ComputerName
            ServicesCheckPass      = $true
            ProcessesCheckPass     = $true
            ProcessResults         = $searchProcessState
            LatestProcessStartTime = [DateTime]::MinValue
            ProcessesNotStarted    = (New-Object 'System.Collections.Generic.List[string]')
        }
    }
    process {

        $searchServices = Get-Service -ComputerName $ComputerName |
            Where-Object {
                $_.Name -eq "HostControllerService" -or
                $_.Name -eq "MSExchangeFastSearch"
            }

        $searchServices |
            ForEach-Object {

                if ($_.StartType -ne "Automatic") {
                    Write-Warning "Service: '$($_.Name)' doesn't have the start up type set to Automatic. Currently: '$($_.StartType)'. This can cause problems."
                    $serverSearchProcessState.ServicesCheckPass = $false
                }

                if ($_.Status -ne "Running") {
                    Write-Error "Service: '$($_.Name)' is currently not running. Currently: '$($_.Status)'. This will cause problems."
                    $serverSearchProcessState.ServicesCheckPass = $false
                }
            }
        #This is to get the command line information and know which node runner is which
        $nodeRunner = Get-WmiObject Win32_Process -Filter "name = 'noderunner.exe'" -ComputerName $ComputerName
        $searchProcesses = Get-Process -ComputerName $ComputerName |
            Where-Object {
                $_.Name -eq "noderunner" -or
                $_.Name -eq "hostcontrollerservice" -or
                $_.Name -eq "Microsoft.Exchange.Search.Service"
            }

        foreach ($process in $searchProcesses) {
            $thirdPartyModule = New-Object 'System.Collections.Generic.List[object]'
            $process.Modules |
                ForEach-Object {

                    if ($_.Company -notlike "*Microsoft*" -and
                        $_.ModuleName -ne "ManagedBlingSigned.dll") {
                        $thirdPartyModule.Add($_)
                    }
                }
            $processName = $process.name.ToLower()

            if ($processName -eq "noderunner") {

                $win32 = $nodeRunner |
                    Where-Object { $_.ProcessId -eq $process.Id }

                if ($win32.CommandLine -like "*AdminNode1*") {
                    $processName = $adminNodeName
                } elseif ($win32.CommandLine -like "*ContentEngineNode1*") {
                    $processName = $contentNodeName
                } elseif ($win32.CommandLine -like "*IndexNode1*") {
                    $processName = $indexNodeName
                } elseif ($win32.CommandLine -like "*InteractionEngineNode1*") {
                    $processName = "$processName - InteractionEngineNode1"
                }
            }

            if ($process.StartTime -gt $serverSearchProcessState.LatestProcessStartTime) {
                $serverSearchProcessState.LatestProcessStartTime = $process.StartTime
            }

            if ($process.StartTime -gt ([DateTime]::Now.AddHours(-1))) {
                $serverSearchProcessState.ProcessesCheckPass = $false
            }

            $searchProcessState[$processName].PID = $process.Id
            $searchProcessState[$processName].StartTime = $process.StartTime
            $searchProcessState[$processName].ThirdPartyModules = $thirdPartyModule
        }

        foreach ($key in $serverSearchProcessState.ProcessResults.Keys) {

            if ($serverSearchProcessState.ProcessResults[$key].StartTime -eq [DateTime]::MinValue) {
                $serverSearchProcessState.ProcessesNotStarted.Add($key)
                $serverSearchProcessState.ProcessesCheckPass = $false
            }
        }
    }
    end {
        return $serverSearchProcessState
    }
}
