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
        [string]$ServerInstance
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    [HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj = New-Object -TypeName HealthChecker.HealthCheckerExchangeServer
    $HealthExSvrObj.ServerName = $ServerInstance
    $HealthExSvrObj.HardwareInformation = Get-HardwareInformation -Server $ServerInstance
    $HealthExSvrObj.OSInformation = Get-OperatingSystemInformation -Server $ServerInstance
    $HealthExSvrObj.ExchangeInformation = Get-ExchangeInformation -Server $ServerInstance -OSMajorVersion $HealthExSvrObj.OSInformation.BuildInformation.MajorVersion

    if ($HealthExSvrObj.ExchangeInformation.BuildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
        $netFrameworkVersion = Get-NETFrameworkVersion -MachineName $ServerInstance -CatchActionFunction ${Function:Invoke-CatchActions}
        $HealthExSvrObj.OSInformation.NETFramework.FriendlyName = $netFrameworkVersion.FriendlyName
        $HealthExSvrObj.OSInformation.NETFramework.RegistryValue = $netFrameworkVersion.RegistryValue
        $HealthExSvrObj.OSInformation.NETFramework.NetMajorVersion = $netFrameworkVersion.MinimumValue
        $HealthExSvrObj.OSInformation.NETFramework.FileInformation = Get-DotNetDllFileVersions -ComputerName $ServerInstance -FileNames @("System.Data.dll", "System.Configuration.dll") -CatchActionFunction ${Function:Invoke-CatchActions}

        if ($netFrameworkVersion.MinimumValue -eq $HealthExSvrObj.ExchangeInformation.NETFramework.MaxSupportedVersion) {
            $HealthExSvrObj.ExchangeInformation.NETFramework.OnRecommendedVersion = $true
        }
    }
    $HealthExSvrObj.HealthCheckerVersion = $BuildVersion
    $HealthExSvrObj.GenerationTime = [datetime]::Now
    Write-Verbose "Finished building health Exchange Server Object for server: $ServerInstance"
    return $HealthExSvrObj
}
