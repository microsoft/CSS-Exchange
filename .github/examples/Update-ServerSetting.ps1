# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Example script')]
param()

function Update-ServerSetting {
    <#
    .SYNOPSIS
        Example of a state-changing function with validation and error handling.

    .DESCRIPTION
        Demonstrates:
        - Parameter validation
        - State change operations
        - Error scenarios
        - Logging/output

    .PARAMETER ConfigKey
        Configuration key to update.

    .PARAMETER ConfigValue
        New value for the configuration.

    .EXAMPLE
        Update-ServerSetting -ConfigKey "MaxMemory" -ConfigValue "32GB"

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigKey,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigValue
    )

    $ErrorActionPreference = "Stop"
    $validKeys = @("MaxMemory", "MaxCPU", "HealthCheckInterval", "LogRetention")

    try {
        # Validate configuration key
        if ($validKeys -notcontains $ConfigKey) {
            throw "Invalid configuration key: $ConfigKey. Valid keys: $($validKeys -join ', ')"
        }

        # Simulate updating configuration
        Write-Verbose "Updating $ConfigKey to $ConfigValue"

        # Simulate validation of value format
        if ($ConfigKey -eq "MaxMemory" -and -not ($ConfigValue -match "^\d+GB$")) {
            throw "Invalid memory format. Expected format: <number>GB (e.g., 32GB)"
        }

        # Return success status
        return [PSCustomObject]@{
            ConfigKey = $ConfigKey
            OldValue  = "previous"
            NewValue  = $ConfigValue
            Updated   = $true
            Timestamp = (Get-Date)
        }
    } catch {
        # Use Write-Verbose for logging in catch blocks, not Write-Error.
        # With $ErrorActionPreference = "Stop", Write-Error becomes terminating
        # and overwrites the original exception. Use throw to let the caller handle it.
        Write-Verbose "Failed to update configuration: $_"
        throw
    }
}
