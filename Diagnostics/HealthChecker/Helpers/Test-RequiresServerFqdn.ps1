# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-RequiresServerFqdn {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $tempServerName = ($Script:Server).Split(".")

    if ($tempServerName[0] -eq $env:COMPUTERNAME) {
        Write-Verbose "Executed against the local machine. No need to pass '-ComputerName' parameter."
        return
    } else {
        try {
            $Script:ServerFQDN = (Get-ExchangeServer $Script:Server -ErrorAction Stop).FQDN
        } catch {
            Invoke-CatchActions
            Write-Verbose "Unable to query Fqdn via 'Get-ExchangeServer'"
        }
    }

    try {
        Invoke-Command -ComputerName $Script:Server -ScriptBlock { Get-Date | Out-Null } -ErrorAction Stop
        Write-Verbose "Connected successfully using: $($Script:Server)."
    } catch {
        Invoke-CatchActions
        if ($tempServerName.Count -gt 1) {
            $Script:Server = $tempServerName[0]
        } else {
            $Script:Server = $Script:ServerFQDN
        }

        try {
            Invoke-Command -ComputerName $Script:Server -ScriptBlock { Get-Date | Out-Null } -ErrorAction Stop
            Write-Verbose "Fallback to: $($Script:Server) Connection was successfully established."
        } catch {
            Write-Red("Failed to run against: {0}. Please try to run the script locally on: {0} for results. " -f $Script:Server)
            exit
        }
    }
}
