# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeInformation.ps1
. $PSScriptRoot\..\ServerInformation\Get-HardwareInformation.ps1
. $PSScriptRoot\..\ServerInformation\Get-OperatingSystemInformation.ps1
. $PSScriptRoot\..\ServerInformation\Get-DotNetDllFileVersions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-NETFrameworkVersion.ps1
function Get-HealthCheckerExchangeServer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )

    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $hardwareInformation = Get-HardwareInformation -Server $ServerName
        $osInformation = Get-OperatingSystemInformation -Server $ServerName
        $exchangeInformation = Get-ExchangeInformation -Server $ServerName
    } end {
        Write-Verbose "Finished building health Exchange Server Object for server: $ServerName"
        return [PSCustomObject]@{
            ServerName              = $ServerName
            HardwareInformation     = $hardwareInformation
            OSInformation           = $osInformation
            ExchangeInformation     = $exchangeInformation
            HealthCheckerVersion    = $BuildVersion
            OrganizationInformation = $null
            GenerationTime          = [DateTime]::Now
        }
    }
}
