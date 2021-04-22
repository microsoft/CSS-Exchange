Function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [string]$ScriptBlockDescription,
        [object]$ArgumentList,
        [bool]$IncludeNoProxyServerOption,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: Invoke-ScriptBlockHandler"
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose "Description: $ScriptBlockDescription"
        }

        try {

            if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {

                $params = @{
                    ComputerName = $ComputerName
                    ScriptBlock  = $ScriptBlock
                    ErrorAction  = "Stop"
                }

                if ($IncludeNoProxyServerOption) {
                    Write-Verbose "Including SessionOption"
                    $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
                }

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Invoke-Command with argument list"
                    $params.Add("ArgumentList", $ArgumentList)
                } else {
                    Write-Verbose "Running Invoke-Command without argument list"
                }

                return Invoke-Command @params
            } else {

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Script Block Locally with argument list"
                    $localReturn = & $ScriptBlock $ArgumentList
                } else {
                    Write-Verbose "Running Script Block Locally without argument list"
                    $localReturn = & $ScriptBlock
                }

                return $localReturn
            }
        } catch {
            Write-Verbose "Failed to run Invoke-ScriptBlockHandler"

            if ($null -ne $CatchActionFunction) {
                & $CatchActionFunction
            }
        }
    }
    end {
        Write-Verbose "Exiting: Invoke-ScriptBlockHandler"
    }
}