# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
function Invoke-AnalyzerIISInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [int]$Order
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = (Get-DisplayResultsGroupingKey -Name "Exchange IIS Information"  -DisplayOrder $Order)
    }

    if ($exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::Edge) {
        Write-Verbose "No IIS information to review on an Edge Server"
        return
    }

    ########################
    # IIS Web Sites
    ########################

    Write-Verbose "Working on IIS Web Sites"
    $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]
    $iisWebSites = $exchangeInformation.IISSettings.IISWebSite | Sort-Object ID
    $bindingsPropertyName = "Protocol - Bindings - Certificate"

    foreach ($webSite in $iisWebSites) {
        $protocolLength = 0
        $bindingInformationLength = 0

        $webSite.Bindings.Protocol |
            ForEach-Object { if ($protocolLength -lt $_.Length) { $protocolLength = $_.Length } }
        $webSite.Bindings.bindingInformation |
            ForEach-Object { if ($bindingInformationLength -lt $_.Length) { $bindingInformationLength = $_.Length } }

        $value = @($webSite.Bindings | ForEach-Object {
                $certHash = $(if ($null -ne $_.certificateHash) { $_.certificateHash } else { "NULL" })
                $pSpace = [string]::Empty
                $biSpace = [string]::Empty
                1..(($protocolLength - $_.Protocol.Length) + 1) | ForEach-Object { $pSpace += " " }
                1..(($bindingInformationLength - $_.bindingInformation.Length) + 1 ) | ForEach-Object { $biSpace += " " }
                return "$($_.Protocol)$($pSpace)- $($_.bindingInformation)$($biSpace)- $certHash"
            })

        $outputObjectDisplayValue.Add([PSCustomObject]@{
                Name                  = $webSite.Name
                State                 = $webSite.State
                $bindingsPropertyName = $value
            })
    }

    #Used for Web App Pools as well
    $sbStarted = { param($o, $p) if ($p -eq "State") { if ($o."$p" -eq "Started") { "Green" } else { "Red" } } }

    $params = $baseParams + @{
        OutColumns       = ([PSCustomObject]@{
                DisplayObject      = $outputObjectDisplayValue
                ColorizerFunctions = @($sbStarted)
                IndentSpaces       = 8
            })
        AddHtmlDetailRow = $false
    }
    Add-AnalyzedResultInformation @params

    ########################
    # IIS Web App Pools
    ########################

    Write-Verbose "Working on Exchange Web App GC Mode"

    $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]

    foreach ($webAppKey in $exchangeInformation.ApplicationPools.Keys) {

        $appPool = $exchangeInformation.ApplicationPools[$webAppKey]
        $appRestarts = $appPool.AppSettings.add.recycling.periodicRestart
        $appRestartSet = ($appRestarts.PrivateMemory -ne "0" -or
            $appRestarts.Memory -ne "0" -or
            $appRestarts.Requests -ne "0" -or
            $null -ne $appRestarts.Schedule -or
            ($appRestarts.Time -ne "00:00:00" -and
                ($webAppKey -ne "MSExchangeOWAAppPool" -and
            $webAppKey -ne "MSExchangeECPAppPool")))

        $outputObjectDisplayValue.Add(([PSCustomObject]@{
                    AppPoolName         = $webAppKey
                    State               = $appPool.AppSettings.state
                    GCServerEnabled     = $appPool.GCServerEnabled
                    RestartConditionSet = $appRestartSet
                })
        )
    }

    $sbRestart = { param($o, $p) if ($p -eq "RestartConditionSet") { if ($o."$p") { "Red" } else { "Green" } } }
    $params = $baseParams + @{
        OutColumns       = ([PSCustomObject]@{
                DisplayObject      = $outputObjectDisplayValue
                ColorizerFunctions = @($sbStarted, $sbRestart)
                IndentSpaces       = 8
            })
        AddHtmlDetailRow = $false
    }
    Add-AnalyzedResultInformation @params

    $periodicStartAppPools = $outputObjectDisplayValue | Where-Object { $_.RestartConditionSet -eq $true }

    if ($null -ne $periodicStartAppPools) {

        $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]

        foreach ($appPool in $periodicStartAppPools) {
            $periodicRestart = $exchangeInformation.ApplicationPools[$appPool.AppPoolName].AppSettings.add.recycling.periodicRestart
            $schedule = $periodicRestart.Schedule

            if ([string]::IsNullOrEmpty($schedule)) {
                $schedule = "null"
            }

            $outputObjectDisplayValue.Add(([PSCustomObject]@{
                        AppPoolName   = $appPool.AppPoolName
                        PrivateMemory = $periodicRestart.PrivateMemory
                        Memory        = $periodicRestart.Memory
                        Requests      = $periodicRestart.Requests
                        Schedule      = $schedule
                        Time          = $periodicRestart.Time
                    }))
        }

        $sbColorizer = {
            param($o, $p)
            switch ($p) {
                { $_ -in "PrivateMemory", "Memory", "Requests" } {
                    if ($o."$p" -eq "0") { "Green" } else { "Red" }
                }
                "Time" {
                    if ($o."$p" -eq "00:00:00") { "Green" } else { "Red" }
                }
                "Schedule" {
                    if ($o."$p" -eq "null") { "Green" } else { "Red" }
                }
            }
        }

        $params = $baseParams + @{
            OutColumns       = ([PSCustomObject]@{
                    DisplayObject      = $outputObjectDisplayValue
                    ColorizerFunctions = @($sbColorizer)
                    IndentSpaces       = 8
                })
            AddHtmlDetailRow = $false
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Details          = "Error: The above app pools currently have the periodic restarts set. This restart will cause disruption to end users."
            DisplayWriteType = "Red"
            AddHtmlDetailRow = $false
        }
        Add-AnalyzedResultInformation @params
    }
}
