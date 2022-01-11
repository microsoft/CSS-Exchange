# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Helpers\PerformanceCountersFunctions.ps1
Function Get-CASLoadBalancingReport {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $CASServers = @()

    if ($null -ne $CasServerList) {
        Write-Grey("Custom CAS server list is being used.  Only servers specified after the -CasServerList parameter will be used in the report.")
        foreach ($cas in $CasServerList) {
            $CASServers += (Get-ExchangeServer $cas)
        }
    } elseif ($SiteName -ne [string]::Empty) {
        Write-Grey("Site filtering ON.  Only Exchange 2013/2016 CAS servers in {0} will be used in the report." -f $SiteName)
        $CASServers = Get-ExchangeServer | Where-Object { `
            ($_.IsClientAccessServer -eq $true) -and `
            ($_.AdminDisplayVersion -Match "^Version 15") -and `
            ([System.Convert]::ToString($_.Site).Split("/")[-1] -eq $SiteName) }
    } else {
        Write-Grey("Site filtering OFF.  All Exchange 2013/2016 CAS servers will be used in the report.")
        $CASServers = Get-ExchangeServer | Where-Object { ($_.IsClientAccessServer -eq $true) -and ($_.AdminDisplayVersion -Match "^Version 15") }
    }

    if ($CASServers.Count -eq 0) {
        Write-Red("Error: No CAS servers found using the specified search criteria.")
        Exit
    }

    Function DisplayKeyMatching {
        param(
            [string]$CounterValue,
            [string]$DisplayValue
        )
        return [PSCustomObject]@{
            Counter = $CounterValue
            Display = $DisplayValue
        }
    }

    #Request stats from perfmon for all CAS
    $displayKeys = @{
        1 = DisplayKeyMatching "Default Web Site" "Load Distribution"
        2 = DisplayKeyMatching "_LM_W3SVC_1_ROOT_Autodiscover" "AutoDiscover"
        3 = DisplayKeyMatching "_LM_W3SVC_1_ROOT_EWS" "EWS"
        4 = DisplayKeyMatching "_LM_W3SVC_1_ROOT_mapi" "MapiHttp"
        5 = DisplayKeyMatching "_LM_W3SVC_1_ROOT_Microsoft-Server-ActiveSync" "EAS"
        6 = DisplayKeyMatching "_LM_W3SVC_1_ROOT_owa" "OWA"
        7 = DisplayKeyMatching "_LM_W3SVC_1_ROOT_Rpc" "RpcHttp"
    }
    $perServerStats = @{}
    $totalStats = @{}

    $currentErrors = $Error.Count
    $counterSamples = Get-LocalizedCounterSamples -MachineName $CASServers -Counter @(
        "\Web Service(*)\Current Connections",
        "\ASP.NET Apps v4.0.30319(*)\Requests Executing"
    ) `
        -CustomErrorAction "SilentlyContinue"


    if ($currentErrors -ne $Error.Count) {
        $i = 0
        while ($i -lt ($Error.Count - $currentErrors)) {
            Invoke-CatchActions -CopyThisError $Error[$i]
            $i++
        }

        Write-Verbose("Failed to get some counters")
    }

    foreach ($counterSample in $counterSamples) {
        $counterObject = Get-CounterFullNameToCounterObject -FullCounterName $counterSample.Path

        if (-not ($perServerStats.ContainsKey($counterObject.ServerName))) {
            $perServerStats.Add($counterObject.ServerName, @{})
        }

        if (-not ($perServerStats[$counterObject.ServerName].ContainsKey($counterObject.InstanceName))) {
            $perServerStats[$counterObject.ServerName].Add($counterObject.InstanceName, $counterSample.CookedValue)
        } else {
            Write-Verbose "This shouldn't occur...."
            $perServerStats[$counterObject.ServerName][$counterObject.InstanceName] += $counterSample.CookedValue
        }

        if (-not ($totalStats.ContainsKey($counterObject.InstanceName))) {
            $totalStats.Add($counterObject.InstanceName, 0)
        }

        $totalStats[$counterObject.InstanceName] += $counterSample.CookedValue
    }

    $keyOrders = $displayKeys.Keys | Sort-Object

    foreach ($key in $keyOrders) {
        $currentDisplayKey = $displayKeys[$key]
        $totalRequests = $totalStats[$currentDisplayKey.Counter]

        if ($totalRequests -le 0) { continue }

        Write-Grey ""
        Write-Grey "Current $($currentDisplayKey.Display) Per Server"
        Write-Grey "Total Requests: $totalRequests"

        foreach ($serverKey in $perServerStats.Keys) {
            if ($perServerStats.ContainsKey($serverKey)) {
                $serverValue = $perServerStats[$serverKey][$currentDisplayKey.Counter]
                Write-Grey "$serverKey : $serverValue Connections = $([math]::Round((([int]$serverValue / $totalRequests) * 100)))% Distribution"
            }
        }
    }
}
