# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
Function Invoke-AnalyzerWebAppPools {
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
    $keyWebApps = Get-DisplayResultsGroupingKey -Name "Exchange Web App Pools"  -DisplayOrder $Order
    $exchangeInformation = $HealthServerObject.ExchangeInformation

    if ($exchangeInformation.BuildInformation.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge) {
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

        $sbStarted = { param($o, $p) if ($p -eq "State") { if ($o."$p" -eq "Started") { "Green" } else { "Red" } } }
        $sbRestart = { param($o, $p) if ($p -eq "RestartConditionSet") { if ($o."$p") { "Red" } else { "Green" } } }
        $AnalyzeResults | Add-AnalyzedResultInformation -OutColumns ([PSCustomObject]@{
                DisplayObject      = $outputObjectDisplayValue
                ColorizerFunctions = @($sbStarted, $sbRestart)
                IndentSpaces       = 8
            }) `
            -DisplayGroupingKey $keyWebApps `
            -AddHtmlDetailRow $false

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

            $AnalyzeResults | Add-AnalyzedResultInformation -OutColumns ([PSCustomObject]@{
                    DisplayObject      = $outputObjectDisplayValue
                    ColorizerFunctions = @($sbColorizer)
                    IndentSpaces       = 8
                }) `
                -DisplayGroupingKey $keyWebApps `
                -AddHtmlDetailRow $false

            $AnalyzeResults | Add-AnalyzedResultInformation -Details "Error: The above app pools currently have the periodic restarts set. This restart will cause disruption to end users." `
                -DisplayGroupingKey $keyWebApps `
                -DisplayWriteType "Red" `
                -AddHtmlDetailRow $false
        }
    }
}
