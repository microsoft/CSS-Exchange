# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Helpers\PerformanceCountersFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionErrorLoop.ps1
function Get-CASLoadBalancingReport {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $CASServers = @()

    if ($null -ne $CasServerList) {
        Write-Grey("Custom CAS server list is being used.  Only servers specified after the -CasServerList parameter will be used in the report.")
        $CASServers = Get-ExchangeServer | Where-Object { ($_.Name -in $CasServerList) -or ($_.FQDN -in $CasServerList) } | Sort-Object Name
    } elseif ($SiteName -ne [string]::Empty) {
        Write-Grey("Site filtering ON.  Only Exchange 2013/2016 CAS servers in {0} will be used in the report." -f $SiteName)
        $CASServers = Get-ExchangeServer | Where-Object {
            ($_.IsClientAccessServer -eq $true) -and
            ($_.AdminDisplayVersion -Match "^Version 15") -and
            ([System.Convert]::ToString($_.Site).Split("/")[-1] -eq $SiteName) } | Sort-Object Name
    } else {
        Write-Grey("Site filtering OFF.  All Exchange 2013/2016 CAS servers will be used in the report.")
        $CASServers = Get-ExchangeServer | Where-Object { ($_.IsClientAccessServer -eq $true) -and ($_.AdminDisplayVersion -Match "^Version 15") } | Sort-Object Name
    }

    if ($CASServers.Count -eq 0) {
        Write-Red("Error: No CAS servers found using the specified search criteria.")
        exit
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

    Invoke-CatchActionErrorLoop $currentErrors ${Function:Invoke-CatchActions}

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
        $htmlLoadDetails += "$([System.Environment]::NewLine)<th><center>$($displayKeys[$_].Display) Requests</center></th>
        <th><center>$($displayKeys[$_].Display) %</center></th>"
    }
    $htmlLoadDetails += "$([System.Environment]::NewLine)</tr>$([System.Environment]::NewLine)"

    foreach ($server in $CASServers) {
        $serverKey = $server.Name.ToString()
        Write-Verbose "Working Server for HTML report $serverKey"
        $htmlLoadDetails += "<tr>
        <td>$($serverKey)</td>
        <td><center>$($server.Site)</center></td>"

        foreach ($key in $keyOrders) {
            $currentDisplayKey = $displayKeys[$key]
            $totalRequests = $totalStats[$currentDisplayKey.Counter]

            if ($perServerStats.ContainsKey($serverKey)) {
                $serverValue = $perServerStats[$serverKey][$currentDisplayKey.Counter]
                if ($null -eq $serverValue) { $serverValue = 0 }
            } else {
                $serverValue = 0
            }
            $percentageLoad = [math]::Round((($serverValue / $totalRequests) * 100))
            Write-Verbose "$($currentDisplayKey.Display) Server Value $serverValue Percentage usage $percentageLoad"

            $htmlLoadDetails += "$([System.Environment]::NewLine)<td><center>$($serverValue)</center></td>
            <td><center>$percentageLoad</center></td>"
        }
        $htmlLoadDetails += "$([System.Environment]::NewLine)</tr>"
    }

    # Totals
    $htmlLoadDetails += "$([System.Environment]::NewLine)<tr>
        <td><center>Totals</center></td>
        <td></td>"
    $keyOrders | ForEach-Object {
        $htmlLoadDetails += "$([System.Environment]::NewLine)<td><center>$($totalStats[(($displayKeys[$_]).Counter)])</center></td>
        <td></td>"
    }

    $htmlLoadDetails += "$([System.Environment]::NewLine)</table></p>"
    $htmlReport = $htmlHeader + $htmlLoadDetails + "</body></html>"
    $htmlFile = "$Script:OutputFilePath\HtmlLoadBalancerReport.html"
    $htmlReport | Out-File $htmlFile

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

    Write-Grey "HTML File Report Written to $htmlFile"
}
