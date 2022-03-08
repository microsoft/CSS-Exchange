# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-ScriptBlockInjection.ps1
. $PSScriptRoot\Invoke-CatchActionError.ps1

# Common method used to handle Invoke-Command within a script.
# Avoids using Invoke-Command when running locally on a server.
# Adds ability to use Write-Verbose and Write-Debug properly within the remote Script Block
# You can also easily inject other script blocks into the main remote script block.
# Common use to inject is for an override of Write-Verbose if there is a custom override of this function
Function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,

        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,

        [string]
        $ScriptBlockDescription,

        [object]
        $ArgumentList,

        [bool]
        $IncludeNoProxyServerOption,

        [scriptblock[]]
        $IncludeScriptBlock,

        [string[]]
        $IncludeUsingParameter,

        [scriptblock]
        $CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $returnValue = $null
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose "Description: $ScriptBlockDescription"
        }

        try {

            if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {

                $adjustedScriptBlock = Add-ScriptBlockInjection -PrimaryScriptBlock $ScriptBlock `
                    -IncludeUsingParameter $IncludeUsingParameter `
                    -IncludeScriptBlock $IncludeScriptBlock `
                    -CatchActionFunction $CatchActionFunction

                $ScriptBlock = [scriptblock]::Create($adjustedScriptBlock)
                Write-Verbose "Created the new script block"

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

                $returnValue = Invoke-Command @params
            } else {

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Script Block Locally with argument list"
                    $returnValue = & $ScriptBlock $ArgumentList
                } else {
                    Write-Verbose "Running Script Block Locally without argument list"
                    $returnValue = & $ScriptBlock
                }
            }
        } catch {
            Write-Debug "Caught error in $($MyInvocation.MyCommand)"
            Write-Verbose "Failed to run $($MyInvocation.MyCommand)"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return $returnValue
    }
}
