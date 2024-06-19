# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1
function Get-ExchangeDiagnosticInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$Process,

        [Parameter(Mandatory = $true)]
        [string]$Component,

        [string]$Argument,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    process {
        try {
            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $params = @{
                Process     = $Process
                Component   = $Component
                Server      = $Server
                ErrorAction = "Stop"
            }

            if (-not ([string]::IsNullOrEmpty($Argument))) {
                $params.Add("Argument", $Argument)
            }

            return (Get-ExchangeDiagnosticInfo @params)
        } catch {
            Write-Verbose "Failed to execute $($MyInvocation.MyCommand). Inner Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
}
