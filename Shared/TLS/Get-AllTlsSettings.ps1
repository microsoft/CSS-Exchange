# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1
. $PSScriptRoot\Get-AllTlsSettingsFromRegistry.ps1
. $PSScriptRoot\Get-TlsCipherSuiteInformation.ps1

# Gets all related TLS Settings, from registry or other factors
function Get-AllTlsSettings {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $registry = $null
        $securityProtocol = $null
        $tlsCipherSuite = $null
    }
    process {

        Get-AllTlsSettingsFromRegistry -MachineName $MachineName -CatchActionFunction $CatchActionFunction |
            Invoke-RemotePipelineHandler -Result ([ref]$registry)
        Get-TlsCipherSuiteInformation -MachineName $MachineName -CatchActionFunction $CatchActionFunction |
            Invoke-RemotePipelineHandler -Result ([ref]$tlsCipherSuite)

        if ($PSSenderInfo) {
            $securityProtocol = ([System.Net.ServicePointManager]::SecurityProtocol).ToString()
        } else {
            $securityProtocol = (Invoke-ScriptBlockHandler -ComputerName $MachineName -ScriptBlock { ([System.Net.ServicePointManager]::SecurityProtocol).ToString() } -CatchActionFunction $CatchActionFunction)
        }

        return [PSCustomObject]@{
            Registry         = $registry
            SecurityProtocol = $securityProtocol
            TlsCipherSuite   = $tlsCipherSuite
        }
    }
}
