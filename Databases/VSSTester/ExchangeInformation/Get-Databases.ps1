# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-Databases {
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ServerName
    )

    Write-Host "$(Get-Date) Getting databases on server: $ServerName"
    [array]$databases = Get-MailboxDatabase -server $ServerName -status
    $databases | Format-Table Name, Mounted, Server -AutoSize | Out-Host
    return $databases
}
