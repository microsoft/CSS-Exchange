# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeProtocolContainer.ps1
. $PSScriptRoot\..\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-ExchangeWebSitesFromAd {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param (
        [string]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        function GetExchangeWebSiteFromCn {
            param (
                [string]$Site
            )

            if ($null -ne $Site) {
                $index = $Site.IndexOf("(") + 1
                if ($index -ne 0) {
                    return ($Site.Substring($index, ($Site.LastIndexOf(")") - $index)))
                }
            }
        }

        $processedExchangeWebSites = New-Object 'System.Collections.Generic.List[array]'
    }
    process {
        $protocolContainer = $null
        Get-ExchangeProtocolContainer -ComputerName $ComputerName | Invoke-RemotePipelineHandler -Result ([ref]$protocolContainer)
        if ($null -ne $protocolContainer) {
            $httpProtocol = $protocolContainer.Children | Where-Object {
                ($_.name -eq "HTTP")
            }

            foreach ($cn in $httpProtocol.Children.cn) {
                $processedExchangeWebSites.Add((GetExchangeWebSiteFromCn $cn))
            }
        }
    }
    end {
        return ($processedExchangeWebSites | Select-Object -Unique)
    }
}
