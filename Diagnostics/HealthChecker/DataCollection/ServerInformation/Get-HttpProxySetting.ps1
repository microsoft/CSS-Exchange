# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
Function Get-HttpProxySetting {

    $httpProxy32 = [String]::Empty
    $httpProxy64 = [String]::Empty
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    Function Get-WinHttpSettings {
        param(
            [Parameter(Mandatory = $true)][string]$RegistryLocation
        )
        $connections = Get-ItemProperty -Path $RegistryLocation
        $Proxy = [string]::Empty
        if (($null -ne $connections) -and
            ($Connections | Get-Member).Name -contains "WinHttpSettings") {
            foreach ($Byte in $Connections.WinHttpSettings) {
                if ($Byte -ge 48) {
                    $Proxy += [CHAR]$Byte
                }
            }
        }
        return $(if ($Proxy -eq [string]::Empty) { "<None>" } else { $Proxy })
    }

    $httpProxy32 = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-WinHttpSettings} -ArgumentList "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ScriptBlockDescription "Getting 32 Http Proxy Value" -CatchActionFunction ${Function:Invoke-CatchActions}
    $httpProxy64 = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-WinHttpSettings} -ArgumentList "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ScriptBlockDescription "Getting 64 Http Proxy Value" -CatchActionFunction ${Function:Invoke-CatchActions}

    Write-Verbose "Http Proxy 32: $httpProxy32"
    Write-Verbose "Http Proxy 64: $httpProxy64"
    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"

    if ($httpProxy32 -ne "<None>") {
        return $httpProxy32
    } else {
        return $httpProxy64
    }
}
