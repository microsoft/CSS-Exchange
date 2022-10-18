# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-RequiresServerFqdn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $tempServerName = ($Server).Split(".")

    if ($tempServerName[0] -eq $env:COMPUTERNAME) {
        Write-Verbose "Executed against the local machine. No need to pass '-ComputerName' parameter."
        return
    } else {
        try {
            $ServerFQDN = (Get-ExchangeServer $Server -ErrorAction Stop).FQDN
        } catch {
            Invoke-CatchActions
            Write-Verbose "Unable to query Fqdn via 'Get-ExchangeServer'"
        }
    }

    try {
        Invoke-Command -ComputerName $Server -ScriptBlock { Get-Date | Out-Null } -ErrorAction Stop
        Write-Verbose "Connected successfully using: $($Server)."
    } catch {
        Invoke-CatchActions
        if ($tempServerName.Count -gt 1) {
            $Server = $tempServerName[0]
        } else {
            $Server = $ServerFQDN
        }

        try {
            Invoke-Command -ComputerName $Server -ScriptBlock { Get-Date | Out-Null } -ErrorAction Stop
            Write-Verbose "Fallback to: $($Server) Connection was successfully established."
        } catch {
            Write-Red("Failed to run against: {0}. Please try to run the script locally on: {0} for results. " -f $Server)
            exit
        }
    }
}
