# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This function is used to collect the required information needed to determine if a server is ready for IP Filtering mitigation
function Get-IPFilteringPrerequisitesCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ExchangeServers
    )
    begin {
        $results = New-Object 'System.Collections.Generic.List[object]'
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    } process {
        foreach ($server in $ExchangeServers) {
            Write-Verbose ("Performing prereq checks on server: {0}" -f $server.ToString())

            $computerResult = Invoke-ScriptBlockHandler -ComputerName $server.ToString() -ScriptBlock { return $env:COMPUTERNAME }
            $serverConnected = $null -ne $computerResult

            if ($serverConnected) {
                Write-Verbose ("Server {0} appears to up and reachable" -f $server.ToString())
            } else {
                Write-Verbose ("Server {0} doesn't appear to be online." -f $server.ToString())
            }

            $results.Add([PSCustomObject]@{
                    ComputerName = $server.ToString()
                    ServerOnline = $serverConnected
                })
        }
    } end {
        return $results
    }
}
