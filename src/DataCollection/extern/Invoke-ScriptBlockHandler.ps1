#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Common/Invoke-ScriptBlockHandler/Invoke-ScriptBlockHandler.ps1
#v21.01.08.2133
Function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $false)][string]$ScriptBlockDescription,
        [Parameter(Mandatory = $false)][object]$ArgumentList,
        [Parameter(Mandatory = $false)][bool]$IncludeNoProxyServerOption,
        [Parameter(Mandatory = $false)][scriptblock]$CatchActionFunction
    )
    #Function Version #v21.01.08.2133

    Write-VerboseWriter("Calling: Invoke-ScriptBlockHandler")
    if (![string]::IsNullOrEmpty($ScriptBlockDescription)) {
        Write-VerboseWriter($ScriptBlockDescription)
    }
    try {
        if ($ComputerName -ne $env:COMPUTERNAME) {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock  = $ScriptBlock
                ErrorAction  = "Stop"
            }

            if ($IncludeNoProxyServerOption) {
                Write-VerboseWriter("Including SessionOption")
                $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
            }

            if ($null -ne $ArgumentList) {
                $params.Add("ArgumentList", $ArgumentList)
                Write-VerboseWriter("Running Invoke-Command with argument list.")
            } else {
                Write-VerboseWriter("Running Invoke-Command without argument list.")
            }

            $invokeReturn = Invoke-Command @params
            return $invokeReturn
        } else {
            if ($null -ne $ArgumentList) {
                Write-VerboseWriter("Running Script Block locally with argument list.")
                $localReturn = & $ScriptBlock $ArgumentList
            } else {
                Write-VerboseWriter("Running Script Block locally without argument list.")
                $localReturn = & $ScriptBlock
            }
            return $localReturn
        }
    } catch {
        Write-VerboseWriter("Failed to Invoke-ScriptBlockHandler")
        if ($null -ne $CatchActionFunction) {
            & $CatchActionFunction
        }
    }
}
