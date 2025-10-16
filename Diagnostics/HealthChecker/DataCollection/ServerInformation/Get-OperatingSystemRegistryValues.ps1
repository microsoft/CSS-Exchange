# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-OperatingSystemRegistryValues {
    [CmdletBinding()]
    param(
        [string]$MachineName,
        [ScriptBlock]$CatchActionFunction
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $suppressEpValue = $null
    $ubrValue = $null
    $lanManValue = $null
    $ipv6ComponentsValue = $null
    $tcpKeepAliveValue = $null
    $rpcMinValue = $null
    $credGuardValue = $null
    $lmValue = $null
    $renegoServerValue = $null
    $renegoClientValue = $null
    $productNameValue = $null
    $releaseIdValue = $null
    $currentBuildValue = $null

    $baseParams = @{
        MachineName         = $MachineName
        CatchActionFunction = $CatchActionFunction
    }

    $lanManParams = $baseParams + @{
        SubKey   = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        GetValue = "DisableCompression"
    }

    $ubrParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        GetValue = "UBR"
    }

    $ipv6ComponentsParams = $baseParams + @{
        SubKey    = "SYSTEM\CurrentControlSet\Services\TcpIp6\Parameters"
        GetValue  = "DisabledComponents"
        ValueType = "DWord"
    }

    $tcpKeepAliveParams = $baseParams + @{
        SubKey   = "SYSTEM\CurrentControlSet\Services\TcpIp\Parameters"
        GetValue = "KeepAliveTime"
    }

    $rpcMinParams = $baseParams + @{
        SubKey   = "Software\Policies\Microsoft\Windows NT\RPC\"
        GetValue = "MinimumConnectionTimeout"
    }

    $renegoClientsParams = $baseParams + @{
        SubKey    = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
        GetValue  = "AllowInsecureRenegoClients"
        ValueType = "DWord"
    }

    $renegoServersParams = $baseParams + @{
        SubKey    = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
        GetValue  = "AllowInsecureRenegoServers"
        ValueType = "DWord"
    }

    $credGuardParams = $baseParams + @{
        SubKey   = "SYSTEM\CurrentControlSet\Control\LSA"
        GetValue = "LsaCfgFlags"
    }

    $suppressEpParams = $baseParams + @{
        SubKey   = "SYSTEM\CurrentControlSet\Control\LSA"
        GetValue = "SuppressExtendedProtection"
    }

    $lmCompParams = $baseParams + @{
        SubKey    = "SYSTEM\CurrentControlSet\Control\Lsa"
        GetValue  = "LmCompatibilityLevel"
        ValueType = "DWord"
    }

    $productNameParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        GetValue = "ProductName"
    }

    $releaseIdParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        GetValue = "ReleaseID"
    }

    $currentBuildParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        GetValue = "CurrentBuild"
    }

    Get-RemoteRegistryValue @lmCompParams | Invoke-RemotePipelineHandler -Result ([ref]$lmValue)
    Get-RemoteRegistryValue @suppressEpParams | Invoke-RemotePipelineHandler -Result ([ref]$suppressEpValue)
    Get-RemoteRegistryValue @ubrParams | Invoke-RemotePipelineHandler -Result ([ref]$ubrValue)
    Get-RemoteRegistryValue @lanManParams | Invoke-RemotePipelineHandler -Result ([ref]$lanManValue)
    Get-RemoteRegistryValue @ipv6ComponentsParams | Invoke-RemotePipelineHandler -Result ([ref]$ipv6ComponentsValue)
    Get-RemoteRegistryValue @tcpKeepAliveParams | Invoke-RemotePipelineHandler -Result ([ref]$tcpKeepAliveValue)
    Get-RemoteRegistryValue @rpcMinParams | Invoke-RemotePipelineHandler -Result ([ref]$rpcMinValue)
    Get-RemoteRegistryValue @credGuardParams | Invoke-RemotePipelineHandler -Result ([ref]$credGuardValue)
    Get-RemoteRegistryValue @renegoServersParams | Invoke-RemotePipelineHandler -Result ([ref]$renegoServerValue)
    Get-RemoteRegistryValue @renegoClientsParams | Invoke-RemotePipelineHandler -Result ([ref]$renegoClientValue)
    Get-RemoteRegistryValue @productNameParams | Invoke-RemotePipelineHandler -Result ([ref]$productNameValue)
    Get-RemoteRegistryValue @releaseIdParams | Invoke-RemotePipelineHandler -Result ([ref]$releaseIdValue)
    Get-RemoteRegistryValue @currentBuildParams | Invoke-RemotePipelineHandler -Result ([ref]$currentBuildValue)

    if ($null -eq $lmValue) { $lmValue = 3 }
    if ($null -eq $renegoServerValue) { $renegoServerValue = "NULL" }
    if ($null -eq $renegoClientValue) { $renegoClientValue = "NULL" }

    return [PSCustomObject]@{
        SuppressExtendedProtection      = [int]$suppressEpValue
        LmCompatibilityLevel            = $lmValue
        CurrentVersionUbr               = [int]$ubrValue
        LanManServerDisabledCompression = [int]$lanManValue
        IPv6DisabledComponents          = [int]$ipv6ComponentsValue
        TCPKeepAlive                    = [int]$tcpKeepAliveValue
        RpcMinConnectionTimeout         = [int]$rpcMinValue
        AllowInsecureRenegoServers      = $renegoServerValue
        AllowInsecureRenegoClients      = $renegoClientValue
        CredentialGuard                 = [int]$credGuardValue
        ProductName                     = $productNameValue
        ReleaseId                       = $releaseIdValue
        CurrentBuild                    = $currentBuildValue
    }
}
