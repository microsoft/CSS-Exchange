# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Helpers\PerformanceCountersFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionErrorLoop.ps1
function Get-LoadBalancingReport {
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $CASServers = @()
    $MBXServers = @()
    $getExchangeServer = Get-ExchangeServer | Select-Object Name, Site, IsClientAccessServer, IsMailboxServer, AdminDisplayVersion, FQDN

    if ($SiteName -ne [string]::Empty) {
        Write-Grey("Site filtering ON.  Only Exchange 2013+ CAS servers in {0} will be used in the report." -f $SiteName)
        $CASServers = $getExchangeServer | Where-Object {
            ($_.IsClientAccessServer -eq $true) -and
            ($_.AdminDisplayVersion -match "^Version 15") -and
            ([System.Convert]::ToString($_.Site).Split("/")[-1] -eq $SiteName) } | Select-Object Name, Site | Sort-Object Name
        Write-Grey("Site filtering ON.  Only Exchange 2013+ MBX servers in {0} will be used in the report." -f $SiteName)
        $MBXServers = $getExchangeServer | Where-Object {
                ($_.IsMailboxServer -eq $true) -and
                ($_.AdminDisplayVersion -match "^Version 15") -and
                ([System.Convert]::ToString($_.Site).Split("/")[-1] -eq $SiteName) } | Select-Object Name, Site | Sort-Object Name
    } else {
        if ( ($null -eq $ServerList) ) {
            Write-Grey("Filtering OFF.  All Exchange 2013+ servers will be used in the report.")
            $CASServers = $getExchangeServer | Where-Object { ($_.IsClientAccessServer -eq $true) -and ($_.AdminDisplayVersion -match "^Version 15") } | Select-Object Name, Site | Sort-Object Name
            $MBXServers = $getExchangeServer | Where-Object { ($_.IsMailboxServer -eq $true) -and ($_.AdminDisplayVersion -match "^Version 15") } | Select-Object Name, Site | Sort-Object Name
        } else {
            Write-Grey("Custom server list is being used. Only servers specified after the -ServerList parameter will be used in the report.")
            $CASServers = $getExchangeServer | Where-Object { ($_.IsClientAccessServer -eq $true) -and ( ($_.Name -in $ServerList) -or ($_.FQDN -in $ServerList) ) } | Select-Object Name, Site | Sort-Object Name
            $MBXServers = $getExchangeServer | Where-Object { ($_.IsMailboxServer -eq $true) -and ( ($_.Name -in $ServerList) -or ($_.FQDN -in $ServerList) ) } | Select-Object Name, Site | Sort-Object Name
        }
    }

    if ($CASServers.Count -eq 0) {
        Write-Red("Error: No CAS servers found using the specified search criteria.")
        exit
    }

    if ($MBXServers.Count -eq 0) {
        Write-Red("Error: No MBX servers found using the specified search criteria.")
        exit
    }

    foreach ($server in $ServerList) {
        if ($server -notin $CASServers.Name -and $server -notin $MBXServers.Name) {
            Write-Warning "$server was not found as an Exchange server."
        }
    }

    function DisplayKeyMatching {
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
        1  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_Total" "Load Distribution"
        2  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT" "root"
        3  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_API" "API"
        4  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_Autodiscover" "AutoDiscover"
        5  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_ecp" "ECP"
        6  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_EWS" "EWS"
        7  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_mapi" "MapiHttp"
        8  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_Microsoft-Server-ActiveSync" "EAS"
        9  = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_OAB" "OAB"
        10 = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_owa" "OWA"
        11 = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_owa_Calendar" "OWA-Calendar"
        12 = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_PowerShell" "PowerShell"
        13 = DisplayKeyMatching "_LM_W3SVC_DefaultSite_ROOT_Rpc" "RpcHttp"
    }

    #Request stats from perfmon for all MBX
    $displayKeysBackend = @{
        1  = DisplayKeyMatching "_LM_W3SVC_BackendSite_Total" "Load Distribution-BackEnd"
        2  = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_API" "API-BackEnd"
        3  = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_Autodiscover" "AutoDiscover-BackEnd"
        4  = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_ecp" "ECP-BackEnd"
        5  = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_EWS" "EWS-BackEnd"
        6  = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_mapi_emsmdb" "MapiHttp_emsmdb-BackEnd"
        7  = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_mapi_nspi" "MapiHttp_nspi-BackEnd"
        8  = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_Microsoft-Server-ActiveSync" "EAS-BackEnd"
        9  = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_owa" "OWA-BackEnd"
        10 = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_PowerShell" "PowerShell-BackEnd"
        11 = DisplayKeyMatching "_LM_W3SVC_BackendSite_ROOT_Rpc" "RpcHttp-BackEnd"
    }

    $perServerStats = [ordered]@{}
    $perServerBackendStats = [ordered]@{}
    $totalStats = [ordered]@{}
    $totalBackendStats = [ordered]@{}

    #TODO: Improve performance here #1770
    #This is very slow loop against Each Server to collect this information.
    #Should be able to improve the speed by running 1 or 2 script blocks against the servers.
    foreach ( $CASServer in $CASServers.Name) {
        $currentErrors = $Error.Count
        $DefaultIdSite = Invoke-Command -ComputerName $CASServer -ScriptBlock { (Get-Website "Default Web Site").Id }

        $params = @{
            MachineName       = $CASServer
            Counter           = "\ASP.NET Apps v4.0.30319(_lm_w3svc_$($DefaultIdSite)_*)\Requests Executing"
            CustomErrorAction = "SilentlyContinue"
        }

        $FECounters = Get-LocalizedCounterSamples @params
        Invoke-CatchActionErrorLoop $currentErrors ${Function:Invoke-CatchActions}

        if ($null -eq $FECounters -or
            $FECounters.Count -eq 0) {
            Write-Verbose "Didn't find any counters on the server that matched."
            continue
        }

        foreach ( $sample in $FECounters) {
            $sample.Path = $sample.Path.Replace("_$($DefaultIdSite)_", "_DefaultSite_")
            $sample.InstanceName = $sample.InstanceName.Replace("_$($DefaultIdSite)_", "_DefaultSite_")
        }

        $counterSamples += $FECounters
    }

    foreach ($counterSample in $counterSamples) {
        $counterObject = Get-CounterFullNameToCounterObject -FullCounterName $counterSample.Path

        if (-not ($perServerStats.Contains($counterObject.ServerName))) {
            $perServerStats.Add($counterObject.ServerName, @{})
        }
        if (-not ($perServerStats[$counterObject.ServerName].Contains($counterObject.InstanceName))) {
            $perServerStats[$counterObject.ServerName].Add($counterObject.InstanceName, $counterSample.CookedValue)
        } else {
            Write-Verbose "This shouldn't occur...."
            $perServerStats[$counterObject.ServerName][$counterObject.InstanceName] += $counterSample.CookedValue
        }
        if (-not ($totalStats.Contains($counterObject.InstanceName))) {
            $totalStats.Add($counterObject.InstanceName, 0)
        }
        $totalStats[$counterObject.InstanceName] += $counterSample.CookedValue
    }

    $totalStats.Add("_lm_w3svc_DefaultSite_total", ($totalStats.Values | Measure-Object -Sum).Sum)

    for ($i = 0; $i -lt $perServerStats.count; $i++) {
        $perServerStats[$i].Add("_lm_w3svc_DefaultSite_total", ($perServerStats[$i].Values | Measure-Object -Sum).Sum)
    }

    $keyOrders = $displayKeys.Keys | Sort-Object

    foreach ( $MBXServer in $MBXServers.Name) {
        $currentErrors = $Error.Count
        $BackendIdSite = Invoke-Command -ComputerName $MBXServer -ScriptBlock { (Get-Website "Exchange Back End").Id }

        $params = @{
            MachineName       = $MBXServer
            Counter           = "\ASP.NET Apps v4.0.30319(_lm_w3svc_$($BackendIdSite)_*)\Requests Executing"
            CustomErrorAction = "SilentlyContinue"
        }

        $BECounters = Get-LocalizedCounterSamples @params
        Invoke-CatchActionErrorLoop $currentErrors ${Function:Invoke-CatchActions}

        if ($null -eq $BECounters -or
            $BECounters.Count -eq 0) {
            Write-Verbose "Didn't find any counters on the server that matched."
            continue
        }

        foreach ( $sample in $BECounters) {
            $sample.Path = $sample.Path.Replace("_$($BackendIdSite)_", "_BackendSite_")
            $sample.InstanceName = $sample.InstanceName.Replace("_$($BackendIdSite)_", "_BackendSite_")
        }

        $counterBackendSamples += $BECounters
    }

    foreach ($counterSample in $counterBackendSamples) {
        $counterObject = Get-CounterFullNameToCounterObject -FullCounterName $counterSample.Path

        if (-not ($perServerBackendStats.Contains($counterObject.ServerName))) {
            $perServerBackendStats.Add($counterObject.ServerName, @{})
        }
        if (-not ($perServerBackendStats[$counterObject.ServerName].Contains($counterObject.InstanceName))) {
            $perServerBackendStats[$counterObject.ServerName].Add($counterObject.InstanceName, $counterSample.CookedValue)
        } else {
            Write-Verbose "This shouldn't occur...."
            $perServerBackendStats[$counterObject.ServerName][$counterObject.InstanceName] += $counterSample.CookedValue
        }
        if (-not ($totalBackendStats.Contains($counterObject.InstanceName))) {
            $totalBackendStats.Add($counterObject.InstanceName, 0)
        }
        $totalBackendStats[$counterObject.InstanceName] += $counterSample.CookedValue
    }

    $totalBackendStats.Add("_lm_w3svc_BackendSite_total", ($totalBackendStats.Values | Measure-Object -Sum).Sum)

    for ($i = 0; $i -lt $perServerBackendStats.count; $i++) {
        $perServerBackendStats[$i].Add("_lm_w3svc_BackendSite_total", ($perServerBackendStats[$i].Values | Measure-Object -Sum).Sum)
    }

    $keyOrdersBackend = $displayKeysBackend.Keys | Sort-Object

    $htmlHeader = "<html>
    <style>
    BODY{font-family: Arial; font-size: 8pt;}
    H1{font-size: 16px;}
    H2{font-size: 14px;}
    H3{font-size: 12px;}
    TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
    TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
    TD{border: 1px solid black; padding: 5px; }
    td.Green{background: #7FFF00;}
    td.Yellow{background: #FFE600;}
    td.Red{background: #FF0000; color: #ffffff;}
    td.Info{background: #85D4FF;}
    </style>
    <body>
    <h1 align=""center"">Exchange Health Checker v$($BuildVersion)</h1>
    <h1 align=""center"">Domain : $(($(Get-ADDomain).DNSRoot).toUpper())</h1>
    <h2 align=""center"">Load balancer run finished : $((Get-Date).ToString("yyyy-MM-dd HH:mm"))</h2><br>"

    [array]$htmlLoadDetails += "<table>
    <tr><th>Server</th>
    <th>Site</th>
    "
    #Load the key Headers
    $keyOrders | ForEach-Object {
        if ( $totalStats[$displayKeys[$_].counter] -gt 0) {
            $htmlLoadDetails += "$([System.Environment]::NewLine)<th><center>$($displayKeys[$_].Display) Requests</center></th>
            <th><center>$($displayKeys[$_].Display) %</center></th>"
        }
    }
    $htmlLoadDetails += "$([System.Environment]::NewLine)</tr>$([System.Environment]::NewLine)"

    foreach ($server in $CASServers) {
        $serverKey = $server.Name
        Write-Verbose "Working Server for HTML report $serverKey"
        $htmlLoadDetails += "<tr>
        <td>$($serverKey)</td>
        <td><center>$($server.Site)</center></td>"

        foreach ($key in $keyOrders) {
            if ( $totalStats[$displayKeys[$key].counter] -gt 0) {
                $currentDisplayKey = $displayKeys[$key]
                $totalRequests = $totalStats[$currentDisplayKey.Counter]

                if ($perServerStats.Contains($serverKey)) {
                    $serverValue = $perServerStats[$serverKey][$currentDisplayKey.Counter]
                    if ($null -eq $serverValue) { $serverValue = 0 }
                } else {
                    $serverValue = 0
                }
                if ($perServerStats.Contains($serverKey)) {
                    $serverValue = $perServerStats[$serverKey][$currentDisplayKey.Counter]
                    if ($null -eq $serverValue) { $serverValue = 0 }
                } else {
                    $serverValue = 0
                }
                if (($totalRequests -eq 0) -or
                ($null -eq $totalRequests)) {
                    $percentageLoad = 0
                } else {
                    $percentageLoad = [math]::Round((($serverValue / $totalRequests) * 100))
                    Write-Verbose "$($currentDisplayKey.Display) Server Value $serverValue Percentage usage $percentageLoad"

                    $htmlLoadDetails += "$([System.Environment]::NewLine)<td><center>$($serverValue)</center></td>
                    <td><center>$percentageLoad</center></td>"
                }
            }
        }
        $htmlLoadDetails += "$([System.Environment]::NewLine)</tr>"
    }

    # Totals
    $htmlLoadDetails += "$([System.Environment]::NewLine)<tr>
        <td><center>Totals</center></td>
        <td></td>"
    $keyOrders | ForEach-Object {
        if ( $totalStats[$displayKeys[$_].counter] -gt 0) {
            $htmlLoadDetails += "$([System.Environment]::NewLine)<td><center>$($totalStats[(($displayKeys[$_]).Counter)])</center></td>
            <td></td>"
        }
    }

    $htmlLoadDetails += "$([System.Environment]::NewLine)</table>"

    $htmlHeaderBackend = "<h2 align=""center"">BackEnd - Mailbox Role</h2><br>"

    [array]$htmlLoadDetailsBackend = "<table>
        <tr><th>Server</th>
        <th>Site</th>
        "
    #Load the key Headers
    $keyOrdersBackend | ForEach-Object {
        if ( $totalBackendStats[$displayKeysBackend[$_].counter] -gt 0) {
            $htmlLoadDetailsBackend += "$([System.Environment]::NewLine)<th><center>$($displayKeysBackend[$_].Display) Requests</center></th>
            <th><center>$($displayKeysBackend[$_].Display) %</center></th>"
        }
    }
    $htmlLoadDetailsBackend += "$([System.Environment]::NewLine)</tr>$([System.Environment]::NewLine)"

    foreach ($server in $MBXServers) {
        $serverKey = $server.Name
        Write-Verbose "Working Server for HTML report $serverKey"
        $htmlLoadDetailsBackend += "<tr>
            <td>$($serverKey)</td>
            <td><center>$($server.Site)</center></td>"

        foreach ($key in $keyOrdersBackend) {
            if ( $totalBackendStats[$displayKeysBackend[$key].counter] -gt 0) {
                $currentDisplayKey = $displayKeysBackend[$key]
                $totalRequests = $totalBackendStats[$currentDisplayKey.Counter]

                if ($perServerBackendStats.Contains($serverKey)) {
                    $serverValue = $perServerBackendStats[$serverKey][$currentDisplayKey.Counter]
                    if ($null -eq $serverValue) { $serverValue = 0 }
                } else {
                    $serverValue = 0
                }
                if ($perServerBackendStats.Contains($serverKey)) {
                    $serverValue = $perServerBackendStats[$serverKey][$currentDisplayKey.Counter]
                    if ($null -eq $serverValue) { $serverValue = 0 }
                } else {
                    $serverValue = 0
                }
                if (($totalRequests -eq 0) -or
                ($null -eq $totalRequests)) {
                    $percentageLoad = 0
                } else {
                    $percentageLoad = [math]::Round((($serverValue / $totalRequests) * 100))
                    Write-Verbose "$($currentDisplayKey.Display) Server Value $serverValue Percentage usage $percentageLoad"
                    $htmlLoadDetailsBackend += "$([System.Environment]::NewLine)<td><center>$($serverValue)</center></td>
                    <td><center>$percentageLoad</center></td>"
                }
            }
        }
        $htmlLoadDetailsBackend += "$([System.Environment]::NewLine)</tr>"
    }

    # Totals
    $htmlLoadDetailsBackend += "$([System.Environment]::NewLine)<tr>
            <td><center>Totals</center></td>
            <td></td>"
    $keyOrdersBackend | ForEach-Object {
        if ( $totalBackendStats[$displayKeysBackend[$_].counter] -gt 0) {
            $htmlLoadDetailsBackend += "$([System.Environment]::NewLine)<td><center>$($totalBackendStats[(($displayKeysBackend[$_]).Counter)])</center></td>
            <td></td>"
        }
    }
    $htmlLoadDetailsBackend += "$([System.Environment]::NewLine)</table>"

    $htmlReport = $htmlHeader + $htmlLoadDetails
    $htmlReport = $htmlReport + $htmlHeaderBackend + $htmlLoadDetailsBackend
    $htmlReport = $htmlReport + "</body></html>"

    $htmlFile = "$Script:OutputFilePath\HtmlLoadBalancerReport-$((Get-Date).ToString("yyyyMMddhhmmss")).html"
    $htmlReport | Out-File $htmlFile

    Write-Grey ""
    Write-Green "Client Access - FrontEnd information"
    foreach ($key in $keyOrders) {
        $currentDisplayKey = $displayKeys[$key]
        $totalRequests = $totalStats[$currentDisplayKey.Counter]

        if ($totalRequests -le 0) { continue }

        Write-Grey ""
        Write-Grey "Current $($currentDisplayKey.Display) Per Server"
        Write-Grey "Total Requests: $totalRequests"

        foreach ($serverKey in $perServerStats.Keys) {
            if ($perServerStats.Contains($serverKey)) {
                $serverValue = $perServerStats[$serverKey][$currentDisplayKey.Counter]
                Write-Grey "$serverKey : $serverValue Connections = $([math]::Round((([int]$serverValue / $totalRequests) * 100)))% Distribution"
            }
        }
    }

    Write-Grey ""
    Write-Green "Mailbox - BackEnd information"
    foreach ($key in $keyOrdersBackend) {
        $currentDisplayKey = $displayKeysBackend[$key]
        $totalRequests = $totalBackendStats[$currentDisplayKey.Counter]

        if ($totalRequests -le 0) { continue }

        Write-Grey ""
        Write-Grey "Current $($currentDisplayKey.Display) Per Server on Backend"
        Write-Grey "Total Requests: $totalRequests on Backend"

        foreach ($serverKey in $perServerBackendStats.Keys) {
            if ($perServerBackendStats.Contains($serverKey)) {
                $serverValue = $perServerBackendStats[$serverKey][$currentDisplayKey.Counter]
                Write-Grey "$serverKey : $serverValue Connections = $([math]::Round((([int]$serverValue / $totalRequests) * 100)))% Distribution on Backend"
            }
        }
    }
    Write-Grey ""
    Write-Grey "HTML File Report Written to $htmlFile"
}
