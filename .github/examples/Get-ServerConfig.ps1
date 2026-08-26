# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ServerConfig {
    <#
    .SYNOPSIS
        Example helper function that retrieves server configuration.

    .DESCRIPTION
        This is a minimal example function for demonstrating test patterns.
        It includes parameter validation, error handling, and structured output.

    .PARAMETER ServerName
        The name of the server to query.

    .PARAMETER Timeout
        Query timeout in seconds.

    .EXAMPLE
        Get-ServerConfig -ServerName "SERVER01"

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ServerName,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$Timeout = 30
    )

    $ErrorActionPreference = "Stop"
    Write-Verbose "Starting Get-ServerConfig for server: $ServerName with timeout: $Timeout seconds"

    try {
        # Simulate server query with timeout
        if ($ServerName -eq "INVALID") {
            throw "Server not found: $ServerName"
        }

        # Return structured output
        return [PSCustomObject]@{
            ServerName        = $ServerName
            IsOnline          = $true
            ConfigVersion     = "1.0"
            LastUpdated       = (Get-Date)
            ProcessorCount    = 4
            AvailableMemoryGB = 16
        }
    } catch {
        # Use Write-Verbose for logging in catch blocks, not Write-Error.
        # With $ErrorActionPreference = "Stop", Write-Error becomes terminating
        # and overwrites the original exception. Use throw to let the caller handle it.
        Write-Verbose "Failed to retrieve config for $ServerName : $_"
        throw
    }
}
