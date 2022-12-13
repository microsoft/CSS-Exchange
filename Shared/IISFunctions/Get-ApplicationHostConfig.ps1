# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-ScriptBlockHandler.ps1

function Get-ApplicationHostConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [scriptblock]$CatchActionFunction
    )

    $params = @{
        ComputerName           = $ComputerName
        ScriptBlockDescription = "Getting applicationHost.config"
        ScriptBlock            = { Get-Content "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config" }
        CatchActionFunction    = $CatchActionFunction
    }

    return Invoke-ScriptBlockHandler @params
}
