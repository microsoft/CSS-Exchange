# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
function Get-OperatingSystemRegistryValues {
    [CmdletBinding()]
    param(
        [string]$MachineName,
        [scriptblock]$CatchActionFunction
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

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
        SubKey    = "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        GetValue  = "DisabledComponents"
        ValueType = "DWord"
    }

    $tcpKeepAliveParams = $baseParams + @{
        SubKey   = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
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

    $lmCompParams = $baseParams + @{
        SubKey    = "SYSTEM\CurrentControlSet\Control\Lsa"
        GetValue  = "LmCompatibilityLevel"
        ValueType = "DWord"
    }
    $lmValue = Get-RemoteRegistryValue @lmCompParams

    if ($null -eq $lmValue) { $lmValue = 3 }

    return [PSCustomObject]@{
        LmCompatibilityLevel            = $lmValue
        CurrentVersionUbr               = [int](Get-RemoteRegistryValue @ubrParams)
        LanManServerDisabledCompression = [int](Get-RemoteRegistryValue @lanManParams)
        IPv6DisabledComponents          = [int](Get-RemoteRegistryValue @ipv6ComponentsParams)
        TCPKeepAlive                    = [int](Get-RemoteRegistryValue @tcpKeepAliveParams)
        RpcMinConnectionTimeout         = [int](Get-RemoteRegistryValue @rpcMinParams)
        AllowInsecureRenegoServers      = [int](Get-RemoteRegistryValue @renegoServersParams)
        AllowInsecureRenegoClients      = [int](Get-RemoteRegistryValue @renegoClientsParams)
    }
}
