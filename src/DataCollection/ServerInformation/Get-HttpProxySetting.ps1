Function Get-HttpProxySetting {

    $httpProxy32 = [String]::Empty
    $httpProxy64 = [String]::Empty
    Write-VerboseOutput("Calling: Get-HttpProxySetting")

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

    Write-VerboseOutput("Http Proxy 32: {0}" -f $httpProxy32)
    Write-VerboseOutput("Http Proxy 64: {0}" -f $httpProxy64)
    Write-VerboseOutput("Exiting: Get-HttpProxySetting")

    if ($httpProxy32 -ne "<None>") {
        return $httpProxy32
    } else {
        return $httpProxy64
    }
}