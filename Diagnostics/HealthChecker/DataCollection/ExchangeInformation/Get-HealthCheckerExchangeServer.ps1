# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeInformation.ps1
. $PSScriptRoot\..\ServerInformation\Get-HardwareInformation.ps1
. $PSScriptRoot\..\ServerInformation\Get-OperatingSystemInformation.ps1
. $PSScriptRoot\..\ServerInformation\Get-DotNetDllFileVersions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-NETFrameworkVersion.ps1
Function Get-HealthCheckerExchangeServer {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    [HealthChecker.HealthCheckerExchangeServer]$HealthExSvrObj = New-Object -TypeName HealthChecker.HealthCheckerExchangeServer
    $HealthExSvrObj.ServerName = $Script:Server
    $HealthExSvrObj.HardwareInformation = Get-HardwareInformation
    $HealthExSvrObj.OSInformation = Get-OperatingSystemInformation
    $HealthExSvrObj.ExchangeInformation = Get-ExchangeInformation -OSMajorVersion $HealthExSvrObj.OSInformation.BuildInformation.MajorVersion

    if ($HealthExSvrObj.ExchangeInformation.BuildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
        $netFrameworkVersion = Get-NETFrameworkVersion -MachineName $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}
        $HealthExSvrObj.OSInformation.NETFramework.FriendlyName = $netFrameworkVersion.FriendlyName
        $HealthExSvrObj.OSInformation.NETFramework.RegistryValue = $netFrameworkVersion.RegistryValue
        $HealthExSvrObj.OSInformation.NETFramework.NetMajorVersion = $netFrameworkVersion.MinimumValue
        $HealthExSvrObj.OSInformation.NETFramework.FileInformation = Get-DotNetDllFileVersions -ComputerName $Script:Server -FileNames @("System.Data.dll", "System.Configuration.dll") -CatchActionFunction ${Function:Invoke-CatchActions}

        if ($netFrameworkVersion.MinimumValue -eq $HealthExSvrObj.ExchangeInformation.NETFramework.MaxSupportedVersion) {
            $HealthExSvrObj.ExchangeInformation.NETFramework.OnRecommendedVersion = $true
        }
    }
    $HealthExSvrObj.HealthCheckerVersion = $BuildVersion
    $HealthExSvrObj.GenerationTime = [datetime]::Now
    Write-Verbose "Finished building health Exchange Server Object for server: $Script:Server"
    return $HealthExSvrObj
}
