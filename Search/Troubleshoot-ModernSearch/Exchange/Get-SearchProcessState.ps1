# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Get-ExchangeProcessModuleAllowList.ps1
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
            param(
                [string[]]$ModuleAllowList,
                [string[]]$CompanyNameAllowList,
                [string[]]$DefenderModuleNames
            )

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

            # AMSI provider detection is the same as in Test-ExchAVExclusions.ps1.
            # Unlike Test-ExchAVExclusions.ps1, only the registered provider DLL is accepted.
            # Other modules loaded by the provider (like MPCLIENT.DLL) are expected in w3wp, not in the search processes.
            # cSpell:ignore MPCLIENT CLSID
            $amsiProviderModuleNames = New-Object 'System.Collections.Generic.List[string]'
            $amsiProviderErrors = New-Object 'System.Collections.Generic.List[string]'
            $amsiProvidersPath = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"

            $amsiProvidersPathExists = Test-Path -Path $amsiProvidersPath -ErrorAction SilentlyContinue -ErrorVariable providersPathError

            foreach ($providersPathErrorRecord in $providersPathError) {
                $amsiProviderErrors.Add("Failed to check $amsiProvidersPath. Error: $($providersPathErrorRecord.Exception.Message)")
            }

            if ($amsiProvidersPathExists) {
                $providerKeys = Get-ChildItem -Path $amsiProvidersPath -ErrorAction SilentlyContinue -ErrorVariable providerKeysError

                foreach ($providerKeyError in $providerKeysError) {
                    $amsiProviderErrors.Add("Failed to read $amsiProvidersPath. Error: $($providerKeyError.Exception.Message)")
                }

                foreach ($providerKey in $providerKeys) {
                    if ($providerKey.PSChildName -match '[0-9A-Fa-f\-]{36}') {
                        $inProcServerPath = "HKLM:\SOFTWARE\Classes\CLSID\{$($Matches[0])}\InprocServer32"
                        $providerDll = (Get-ItemProperty -Path $inProcServerPath -ErrorAction SilentlyContinue -ErrorVariable providerDllError).'(default)'

                        if ([string]::IsNullOrEmpty($providerDll)) {
                            $amsiProviderErrors.Add("Failed to get the AMSI provider DLL from $inProcServerPath. Error: $($providerDllError.Exception.Message)")
                        } else {
                            $amsiProviderModuleNames.Add(($providerDll.Trim('"') -split '\\')[-1])
                        }
                    }
                }
            }

            $returnProcesses = New-Object 'System.Collections.Generic.List[object]'
            # Foreach of the processes collect some minor information
            foreach ($process in $searchProcesses) {
                # Only return 3 party modules, as that should be the only thing we care about.
                $thirdPartyModule = New-Object 'System.Collections.Generic.List[object]'
                $amsiModule = New-Object 'System.Collections.Generic.List[object]'
                $modulesReadError = $null

                try {
                    $processModules = $process.Modules
                } catch {
                    $processModules = $null
                    $modulesReadError = $_.Exception.Message
                }

                # A running process always has loaded modules. Nothing returned means that the module list couldn't be read.
                if ($null -eq $processModules -or
                    @($processModules).Count -eq 0) {
                    $processModules = @()

                    if ($null -eq $modulesReadError) {
                        $modulesReadError = "No modules were returned for the process."
                    }
                }

                $hasAmsiDll = $null -ne ($processModules | Where-Object { $_.ModuleName -eq "amsi.dll" })

                foreach ($module in $processModules) {
                    $isAmsiProvider = $hasAmsiDll -and $module.ModuleName -in $amsiProviderModuleNames
                    # Windows Defender modules aren't expected even though they are Microsoft modules
                    # NGen native images (*.ni.dll) are allowed when their IL assembly is allowed
                    $isUnexpectedModule = (($module.Company -notlike "*Microsoft*" -and
                            $module.Company -notin $CompanyNameAllowList) -or
                        $module.FileName -like "*Windows Defender*" -or
                        $module.ModuleName -in $DefenderModuleNames) -and
                    ($module.ModuleName -replace "\.ni\.dll$", ".dll") -notin $ModuleAllowList

                    if (-not $isAmsiProvider -and
                        -not $isUnexpectedModule) {
                        continue
                    }

                    $moduleInformation = [PSCustomObject]@{
                        ModuleName  = $module.ModuleName
                        Company     = $module.Company
                        FileVersion = $module.FileVersion
                        FileName    = $module.FileName
                    }

                    if ($isAmsiProvider) {
                        $amsiModule.Add($moduleInformation)
                    } else {
                        $thirdPartyModule.Add($moduleInformation)
                    }
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
                        AmsiModules       = $amsiModule
                        ModulesReadError  = $modulesReadError
                    })
            }

            return [PSCustomObject]@{
                Services                = $getSearchServices
                Processes               = $returnProcesses
                AmsiProviderModuleNames = $amsiProviderModuleNames
                AmsiProviderErrors      = $amsiProviderErrors
                CurrentTime             = [DateTime]::Now
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
        $modulesReadFailed = $false
    }
    process {

        $allowList = Get-ExchangeProcessModuleAllowList
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = ${Function:GetSearchProcessStateScriptBlock}
            ArgumentList = @($allowList.ModuleNames, $allowList.CompanyNames, $allowList.AmsiKnownModuleNames)
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

            if ($null -ne $process.ModulesReadError) {
                $modulesReadFailed = $true
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
            ModulesReadFailed       = $modulesReadFailed
            LatestProcessStartTime  = $latestProcessStartTime
        }
    }
}
