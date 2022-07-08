# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExchangeInstallDirectory {
    [CmdletBinding()]
    param()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $installDirectory = [string]::Empty
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup') {
        Write-Verbose "Detected v14"
        $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath
    } elseif (Test-Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup') {
        Write-Verbose "Detected v15"
        $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup).MsiInstallPath
    } else {
        Write-Host "Something went wrong trying to find Exchange Install path on this server: $env:COMPUTERNAME"
    }

    Write-Verbose "Returning: $installDirectory"

    return $installDirectory
}
