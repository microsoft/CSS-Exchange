# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-ScriptBlockHandler.ps1

function Get-ApplicationHostConfig {
    [CmdletBinding()]
    [OutputType([System.Xml.XmlNode])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [scriptblock]$CatchActionFunction
    )
    function LoadApplicationHostConfig {
        param()
        $appHostConfig = New-Object -TypeName Xml
        $appHostConfigPath = "$($env:WINDIR)\System32\inetsrv\config\applicationHost.config"
        $appHostConfig.Load($appHostConfigPath)
        return $appHostConfig
    }

    $params = @{
        ComputerName           = $ComputerName
        ScriptBlockDescription = "Getting applicationHost.config"
        ScriptBlock            = ${Function:LoadApplicationHostConfig}
        CatchActionFunction    = $CatchActionFunction
    }

    return Invoke-ScriptBlockHandler @params
}
