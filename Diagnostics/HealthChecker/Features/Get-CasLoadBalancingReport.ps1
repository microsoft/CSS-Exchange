# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-CASLoadBalancingReport {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    #Connection and requests per server and client type values
    $CASConnectionStats = @{}
    $TotalCASConnectionCount = 0
    $AutoDStats = @{}
    $TotalAutoDRequests = 0
    $EWSStats = @{}
    $TotalEWSRequests = 0
    $MapiHttpStats = @{}
    $TotalMapiHttpRequests = 0
    $EASStats = @{}
    $TotalEASRequests = 0
    $OWAStats = @{}
    $TotalOWARequests = 0
    $RpcHttpStats = @{}
    $TotalRpcHttpRequests = 0
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

    #Request stats from perfmon for all CAS
    $PerformanceCounters = @()
    $PerformanceCounters += "\Web Service(Default Web Site)\Current Connections"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Autodiscover)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_EWS)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_mapi)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Microsoft-Server-ActiveSync)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_owa)\Requests Executing"
    $PerformanceCounters += "\ASP.NET Apps v4.0.30319(_LM_W3SVC_1_ROOT_Rpc)\Requests Executing"
    $currentErrors = $Error.Count
    $AllCounterResults = Get-Counter -ComputerName $CASServers -Counter $PerformanceCounters -ErrorAction SilentlyContinue

    if ($currentErrors -ne $Error.Count) {
        $i = 0
        while ($i -lt ($Error.Count - $currentErrors)) {
            Invoke-CatchActions -CopyThisError $Error[$i]
            $i++
        }

        Write-Verbose("Failed to get some counters")
    }

    foreach ($Result in $AllCounterResults.CounterSamples) {
        $CasName = ($Result.Path).Split("\\", [System.StringSplitOptions]::RemoveEmptyEntries)[0]
        $ResultCookedValue = $Result.CookedValue

        if ($Result.Path -like "*{0}*{1}" -f $CasName, $PerformanceCounters[0]) {
            #Total connections
            $CASConnectionStats.Add($CasName, $ResultCookedValue)
            $TotalCASConnectionCount += $ResultCookedValue
        } elseif ($Result.Path -like "*{0}*{1}" -f $CasName, $PerformanceCounters[1]) {
            #AutoD requests
            $AutoDStats.Add($CasName, $ResultCookedValue)
            $TotalAutoDRequests += $ResultCookedValue
        } elseif ($Result.Path -like "*{0}*{1}" -f $CasName, $PerformanceCounters[2]) {
            #EWS requests
            $EWSStats.Add($CasName, $ResultCookedValue)
            $TotalEWSRequests += $ResultCookedValue
        } elseif ($Result.Path -like "*{0}*{1}" -f $CasName, $PerformanceCounters[3]) {
            #MapiHttp requests
            $MapiHttpStats.Add($CasName, $ResultCookedValue)
            $TotalMapiHttpRequests += $ResultCookedValue
        } elseif ($Result.Path -like "*{0}*{1}" -f $CasName, $PerformanceCounters[4]) {
            #EAS requests
            $EASStats.Add($CasName, $ResultCookedValue)
            $TotalEASRequests += $ResultCookedValue
        } elseif ($Result.Path -like "*{0}*{1}" -f $CasName, $PerformanceCounters[5]) {
            #OWA requests
            $OWAStats.Add($CasName, $ResultCookedValue)
            $TotalOWARequests += $ResultCookedValue
        } elseif ($Result.Path -like "*{0}*{1}" -f $CasName, $PerformanceCounters[6]) {
            #RPCHTTP requests
            $RpcHttpStats.Add($CasName, $ResultCookedValue)
            $TotalRpcHttpRequests += $ResultCookedValue
        }
    }


    #Report the results for connection count
    Write-Grey("")
    Write-Grey("Connection Load Distribution Per Server")
    Write-Grey("Total Connections: {0}" -f $TotalCASConnectionCount)
    #Calculate percentage of connection load
    $CASConnectionStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
        Write-Grey($_.Key + ": " + $_.Value + " Connections = " + [math]::Round((([int]$_.Value / $TotalCASConnectionCount) * 100)) + "% Distribution")
    }

    #Same for each client type.  These are request numbers not connection numbers.
    #AutoD
    if ($TotalAutoDRequests -gt 0) {
        Write-Grey("")
        Write-Grey("Current AutoDiscover Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalAutoDRequests)
        $AutoDStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
            Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value / $TotalAutoDRequests) * 100)) + "% Distribution")
        }
    }

    #EWS
    if ($TotalEWSRequests -gt 0) {
        Write-Grey("")
        Write-Grey("Current EWS Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalEWSRequests)
        $EWSStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
            Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value / $TotalEWSRequests) * 100)) + "% Distribution")
        }
    }

    #MapiHttp
    if ($TotalMapiHttpRequests -gt 0) {
        Write-Grey("")
        Write-Grey("Current MapiHttp Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalMapiHttpRequests)
        $MapiHttpStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
            Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value / $TotalMapiHttpRequests) * 100)) + "% Distribution")
        }
    }

    #EAS
    if ($TotalEASRequests -gt 0) {
        Write-Grey("")
        Write-Grey("Current EAS Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalEASRequests)
        $EASStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
            Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value / $TotalEASRequests) * 100)) + "% Distribution")
        }
    }

    #OWA
    if ($TotalOWARequests -gt 0) {
        Write-Grey("")
        Write-Grey("Current OWA Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalOWARequests)
        $OWAStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
            Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value / $TotalOWARequests) * 100)) + "% Distribution")
        }
    }

    #RpcHttp
    if ($TotalRpcHttpRequests -gt 0) {
        Write-Grey("")
        Write-Grey("Current RpcHttp Requests Per Server")
        Write-Grey("Total Requests: {0}" -f $TotalRpcHttpRequests)
        $RpcHttpStats.GetEnumerator() | Sort-Object -Descending | ForEach-Object {
            Write-Grey($_.Key + ": " + $_.Value + " Requests = " + [math]::Round((([int]$_.Value / $TotalRpcHttpRequests) * 100)) + "% Distribution")
        }
    }
    Write-Grey("")
}
