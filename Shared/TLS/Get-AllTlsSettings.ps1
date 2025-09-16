# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

<#
.DESCRIPTION
    This function gets all TLS related information from the local server.
    This includes the registry information for TLS, CipherSuites, and SecurityProtocol currently active.
.NOTES
    You MUST execute this code on the server you want to collect information for. This can be done remotely via Invoke-Command/Invoke-ScriptBlockHandler.
#>
function Get-AllTlsSettings {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        # Place into the function so the build process can handle this.
        . $PSScriptRoot\Get-AllTlsSettingsFromRegistry.ps1
        . $PSScriptRoot\Get-TlsCipherSuiteInformation.ps1

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $registry = $null
        $securityProtocol = ([System.Net.ServicePointManager]::SecurityProtocol).ToString()
        $tlsCipherSuite = $null
    }
    process {

        Get-AllTlsSettingsFromRegistry -CatchActionFunction $CatchActionFunction |
            Invoke-RemotePipelineHandler -Result ([ref]$registry)
        Get-TlsCipherSuiteInformation -CatchActionFunction $CatchActionFunction |
            Invoke-RemotePipelineHandler -Result ([ref]$tlsCipherSuite)

        return [PSCustomObject]@{
            Registry         = $registry
            SecurityProtocol = $securityProtocol
            TlsCipherSuite   = $tlsCipherSuite
        }
    }
}
