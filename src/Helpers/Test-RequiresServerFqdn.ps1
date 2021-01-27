Function Test-RequiresServerFqdn {

    Write-VerboseOutput("Calling: Test-RequiresServerFqdn")
    $tempServerName = ($Script:Server).Split(".")

    if ($tempServerName[0] -eq $env:COMPUTERNAME) {
        Write-VerboseOutput("Executed against the local machine. No need to pass '-ComputerName' parameter.")
        return
    } else {
        try {
            $Script:ServerFQDN = (Get-ExchangeServer $Script:Server -ErrorAction Stop).FQDN
        } catch {
            Invoke-CatchActions
            Write-VerboseOutput("Unable to query Fqdn via 'Get-ExchangeServer'")
        }
    }

    try {
        Invoke-Command -ComputerName $Script:Server -ScriptBlock { Get-Date | Out-Null } -ErrorAction Stop
        Write-VerboseOutput("Connected successfully using: {0}." -f $Script:Server)
    } catch {
        Invoke-CatchActions
        if ($tempServerName.Count -gt 1) {
            $Script:Server = $tempServerName[0]
        } else {
            $Script:Server = $Script:ServerFQDN
        }

        try {
            Invoke-Command -ComputerName $Script:Server -ScriptBlock { Get-Date | Out-Null } -ErrorAction Stop
            Write-VerboseOutput("Fallback to: {0} Connection was successfully established." -f $Script:Server)
        } catch {
            Write-Red("Failed to run against: {0}. Please try to run the script locally on: {0} for results. " -f $Script:Server)
            exit
        }
    }
}