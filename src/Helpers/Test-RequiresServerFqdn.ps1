Function Test-RequiresServerFqdn {

    Write-VerboseOutput("Calling: Test-RequiresServerFqdn")

    try {
        $Script:ServerFQDN = (Get-ExchangeServer $Script:Server).FQDN
        Invoke-Command -ComputerName $Script:Server -ScriptBlock { Get-Date | Out-Null } -ErrorAction Stop
        Write-VerboseOutput("Connected successfully using NetBIOS name.")
    } catch {
        Invoke-CatchActions
        Write-VerboseOutput("Failed to connect to {0} using NetBIOS name. Fallback to Fqdn: {1}" -f $Script:Server, $Script:ServerFQDN)
        $Script:Server = $Script:ServerFQDN
    }
}