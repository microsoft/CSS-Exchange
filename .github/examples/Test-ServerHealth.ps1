# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-ServerHealth {
    <#
    .SYNOPSIS
        Example function that demonstrates testing Exchange-specific cmdlets with mocking.

    .DESCRIPTION
        Shows how to:
        - Mock Exchange cmdlets (Get-ExchangeServer, etc.)
        - Handle Exchange API responses
        - Test pagination-like scenarios
        - Mock date/time for consistent results

    .PARAMETER Identity
        The Exchange server identity.

    .EXAMPLE
        Test-ServerHealth -Identity "EX01"

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
    )

    $ErrorActionPreference = "Stop"

    try {
        # These would be real Exchange cmdlets in production
        $server = Get-ExchangeServer -Identity $Identity -ErrorAction Stop

        if ($null -eq $server) {
            throw "Exchange server not found: $Identity"
        }

        # Check certificate health
        $cert = Get-ExchangeCertificate -Server $server.Name -ErrorAction Stop

        if ($null -eq $cert -or $cert.Count -eq 0) {
            throw "No certificates found for server: $($server.Name)"
        }

        $daysUntilExpire = ($cert[0].NotAfter - (Get-Date)).Days

        if ($daysUntilExpire -lt 30) {
            $certStatus = "Critical"
        } elseif ($daysUntilExpire -lt 90) {
            $certStatus = "Warning"
        } else {
            $certStatus = "Healthy"
        }

        $certHealth = @{
            ServerName        = $server.Name
            CertificateStatus = $certStatus
            DaysUntilExpire   = $daysUntilExpire
            LastChecked       = (Get-Date)
        }

        return [PSCustomObject]$certHealth
    } catch {
        # Use Write-Verbose for logging in catch blocks, not Write-Error.
        # With $ErrorActionPreference = "Stop", Write-Error becomes terminating
        # and overwrites the original exception. Use throw to let the caller handle it.
        Write-Verbose "Health check failed for $Identity : $_"
        throw
    }
}
