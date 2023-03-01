# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns True if we are running inside Exchange Management Shell, and False otherwise.
#>
function Confirm-ExchangeManagementShell {
    $cmd = Get-Command "Get-EventLogLevel" -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        return $false
    }

    $level = Get-EventLogLevel | Select-Object -First 1
    if (($level.GetType().Name -eq "EventCategoryObject") -or
        (($level.GetType().Name -eq "PSObject") -and
            ($null -ne $level.SerializationData))) {
        return $true
    }

    return $false
}
