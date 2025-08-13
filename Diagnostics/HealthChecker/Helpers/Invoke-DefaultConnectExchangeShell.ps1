# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    This function will try to connect to the Exchange Server with Remote Exchange Management Shell.
    This will only execute if we determined that we are within a job or with a Force switch, otherwise, we should already have EMS loaded
#>
function Invoke-DefaultConnectExchangeShell {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [string]$ExchangeServerName,

        [bool]$Force = $false
    )
    process {

        if ($PSSenderInfo -or $Force) {

            if ([string]::IsNullOrEmpty($ExchangeServerName) -and $PSSenderInfo) {
                # $PrimaryRemoteShellConnectionPoint must be set in the primary session.
                # With Start-Job, this always requires any Using variable to be set, even if we aren't going to be using it.
                $ExchangeServerName = $Using:PrimaryRemoteShellConnectionPoint
            }

            # Track how long we spent trying to connect to Exchange, as this can be time consuming.
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            # We want to hide any warnings or verbose information this process causes.
            # Our overrides will still work when we are set like this however.
            $currentWarningPreference = $WarningPreference
            $currentVerbosePreference = $VerbosePreference
            $VerbosePreference = 'SilentlyContinue'
            $WarningPreference = 'SilentlyContinue'
            Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ExchangeServerName/powershell" -Authentication Kerberos) | Out-Null

            try {
                Get-EventLogLevel -ErrorAction Stop | Out-Null
                Write-Verbose "Successfully loaded Exchange Shell. Took $($stopWatch.Elapsed.TotalSeconds) seconds to complete."
            } catch {
                throw "Failed to load Exchange Management Shell against server $ExchangeServerName. Inner Exception $_"
            }
            $WarningPreference = $currentWarningPreference
            $VerbosePreference = $currentVerbosePreference
        }
    }
}
