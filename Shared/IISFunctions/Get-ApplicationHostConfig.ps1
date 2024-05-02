# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-ScriptBlockHandler.ps1

function Get-ApplicationHostConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [ScriptBlock]$CatchActionFunction
    )

    $params = @{
        ComputerName           = $ComputerName
        ScriptBlockDescription = "Getting applicationHost.config"
        ScriptBlock            = { (Get-Content "$($env:WINDIR)\System32\inetSrv\config\applicationHost.config" -Raw -Encoding UTF8).Trim() }
        CatchActionFunction    = $CatchActionFunction
    }

    return Invoke-ScriptBlockHandler @params
}
