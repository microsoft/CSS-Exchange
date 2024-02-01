﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
function Get-HttpProxySetting {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    function GetWinHttpSettings {
        param(
            [Parameter(Mandatory = $true)][string]$RegistryLocation
        )
        $connections = Get-ItemProperty -Path $RegistryLocation
        $byteLength = 4
        $proxyStartLocation = 16
        $proxyLength = 0
        $proxyAddress = [string]::Empty
        $byPassList = [string]::Empty

        if (($null -ne $connections) -and
            ($Connections | Get-Member).Name -contains "WinHttpSettings") {
            try {
                $bytes = $Connections.WinHttpSettings
                $proxyLength = [System.BitConverter]::ToInt32($bytes, $proxyStartLocation - $byteLength)

                if ($proxyLength -gt 0) {
                    $proxyAddress = [System.Text.Encoding]::UTF8.GetString($bytes, $proxyStartLocation, $proxyLength)
                    $byPassListLength = [System.BitConverter]::ToInt32($bytes, $proxyStartLocation + $proxyLength)

                    if ($byPassListLength -gt 0) {
                        $byPassList = [System.Text.Encoding]::UTF8.GetString($bytes, $byteLength + $proxyStartLocation + $proxyLength, $byPassListLength)
                    }
                }
            } catch {
                Write-Verbose "Failed to properly get HTTP Proxy information. Inner Exception: $_"
            }
        }

        return [PSCustomObject]@{
            ProxyAddress = $(if ($proxyAddress -eq [string]::Empty) { "None" } else { $proxyAddress })
            ByPassList   = $byPassList
        }
    }

    $httpProxy32 = Invoke-ScriptBlockHandler -ComputerName $Server `
        -ScriptBlock ${Function:GetWinHttpSettings} `
        -ArgumentList "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" `
        -ScriptBlockDescription "Getting 32 Http Proxy Value" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    $httpProxy64 = Invoke-ScriptBlockHandler -ComputerName $Server `
        -ScriptBlock ${Function:GetWinHttpSettings} `
        -ArgumentList "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" `
        -ScriptBlockDescription "Getting 64 Http Proxy Value" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    $httpProxy = [PSCustomObject]@{
        ProxyAddress         = $(if ($httpProxy32.ProxyAddress -ne "None") { $httpProxy32.ProxyAddress } else { $httpProxy64.ProxyAddress })
        ByPassList           = $(if ($httpProxy32.ByPassList -ne [string]::Empty) { $httpProxy32.ByPassList } else { $httpProxy64.ByPassList })
        HttpProxyDifference  = $httpProxy32.ProxyAddress -ne $httpProxy64.ProxyAddress
        HttpByPassDifference = $httpProxy32.ByPassList -ne $httpProxy64.ByPassList
        HttpProxy32          = $httpProxy32
        HttpProxy64          = $httpProxy64
    }

    Write-Verbose "Http Proxy 32: $($httpProxy32.ProxyAddress)"
    Write-Verbose "Http By Pass List 32: $($httpProxy32.ByPassList)"
    Write-Verbose "Http Proxy 64: $($httpProxy64.ProxyAddress)"
    Write-Verbose "Http By Pass List 64: $($httpProxy64.ByPassList)"
    Write-Verbose "Proxy Address: $($httpProxy.ProxyAddress)"
    Write-Verbose "By Pass List: $($httpProxy.ByPassList)"
    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $httpProxy
}
