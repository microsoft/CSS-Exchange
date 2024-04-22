# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
function Get-OperatingSystemRegistryValues {
    [CmdletBinding()]
    param(
        [string]$MachineName,
        [ScriptBlock]$CatchActionFunction
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
    $renegoClientValue = Get-RemoteRegistryValue @renegoClientsParams

    if ($null -eq $renegoClientValue) { $renegoClientValue = "NULL" }

    $renegoServersParams = $baseParams + @{
        SubKey    = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
        GetValue  = "AllowInsecureRenegoServers"
        ValueType = "DWord"
    }
    $renegoServerValue = Get-RemoteRegistryValue @renegoServersParams

    if ($null -eq $renegoServerValue) { $renegoServerValue = "NULL" }

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
    $lmValue = Get-RemoteRegistryValue @lmCompParams

    if ($null -eq $lmValue) { $lmValue = 3 }

    return [PSCustomObject]@{
        SuppressExtendedProtection      = [int](Get-RemoteRegistryValue @suppressEpParams)
        LmCompatibilityLevel            = $lmValue
        CurrentVersionUbr               = [int](Get-RemoteRegistryValue @ubrParams)
        LanManServerDisabledCompression = [int](Get-RemoteRegistryValue @lanManParams)
        IPv6DisabledComponents          = [int](Get-RemoteRegistryValue @ipv6ComponentsParams)
        TCPKeepAlive                    = [int](Get-RemoteRegistryValue @tcpKeepAliveParams)
        RpcMinConnectionTimeout         = [int](Get-RemoteRegistryValue @rpcMinParams)
        AllowInsecureRenegoServers      = $renegoServerValue
        AllowInsecureRenegoClients      = $renegoClientValue
        CredentialGuard                 = [int](Get-RemoteRegistryValue @credGuardParams)
    }
}
