# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Stop-Logman {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I like Stop Logman')]
    param(
        [Parameter(Mandatory = $true)][string]$LogmanName,
        [Parameter(Mandatory = $true)][string]$ServerName
    )
    Write-ScriptHost -WriteString ("Stopping Data Collection {0} on server {1}" -f $LogmanName, $ServerName)
    logman stop -s $ServerName $LogmanName
}
