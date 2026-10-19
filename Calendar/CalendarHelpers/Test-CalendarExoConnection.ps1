# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Validates that the current PowerShell session is connected to Exchange Online.

.DESCRIPTION
    Confirms that Get-Mailbox is available, and when Get-ConnectionInformation is available (ExchangeOnlineManagement 3.x),
    confirms that an active Exchange Online connection exists and reports its endpoint host.
    An active connection to an unrecognized endpoint produces a warning instead of a failure, because sovereign cloud
    and test environments use different hosts. Messages are written to the console; the caller decides whether to stop.

.OUTPUTS
    System.Boolean. $true when the session can be used for Exchange Online diagnostics.
#>
function Test-CalendarExoConnection {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $connectHint = "Run 'Import-Module ExchangeOnlineManagement' and 'Connect-ExchangeOnline', then rerun the script."

    if ($null -eq (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue)) {
        Write-Host -ForegroundColor Red "Get-Mailbox cmdlet not found. Validate that you are running this script from a PowerShell session connected to Exchange Online."
        Write-Host -ForegroundColor Yellow $connectHint
        return $false
    }

    $endpointHost = $null
    if ($null -ne (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
        $activeConnections = $null
        try {
            $activeConnections = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq "Connected" })
        } catch {
            Write-Verbose "Get-ConnectionInformation failed: $($_.Exception.Message)"
        }

        if (($null -ne $activeConnections) -and ($activeConnections.Count -eq 0)) {
            Write-Host -ForegroundColor Red "Get-Mailbox is available, but there is no active Exchange Online connection in this session."
            Write-Host -ForegroundColor Yellow $connectHint
            return $false
        }

        $knownHostSuffixes = @("office365.com", "office.com", "outlook.com", "office365.us", "outlook.cn")
        foreach ($connection in @($activeConnections)) {
            $connectionUri = $null
            if ([System.Uri]::TryCreate([string]$connection.ConnectionUri, [System.UriKind]::Absolute, [ref]$connectionUri)) {
                $connectionHost = $connectionUri.Host.ToLowerInvariant()
                if ($null -eq $endpointHost) {
                    $endpointHost = $connectionHost
                }
                foreach ($suffix in $knownHostSuffixes) {
                    if (($connectionHost -eq $suffix) -or $connectionHost.EndsWith(".$suffix")) {
                        $endpointHost = $connectionHost
                        Write-Host -ForegroundColor Green "Validated connection to Exchange Online ($endpointHost)."
                        return $true
                    }
                }
            }
        }

        if ($null -ne $endpointHost) {
            Write-Warning "The active connection endpoint '$endpointHost' is not a recognized Exchange Online endpoint. Verify that this session is connected to Exchange Online."
            return $true
        }
    }

    Write-Host -ForegroundColor Green "Validated connection to Exchange Online."
    return $true
}
