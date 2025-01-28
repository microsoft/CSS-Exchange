# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-DefaultConnectExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExchangeServerName
    )
    process {
        $currentWarningPreference = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ExchangeServerName/powershell" -Authentication Kerberos) | Out-Null

        try {
            Get-EventLogLevel -ErrorAction Stop | Out-Null
            Write-Verbose "Successfully loaded Exchange Shell"
        } catch {
            throw "Failed to load Exchange Management Shell against server $ExchangeServerName."
        }
        $WarningPreference = $currentWarningPreference
    }
}
