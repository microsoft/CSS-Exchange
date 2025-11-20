# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-HttpProxySetting.ps1
. $PSScriptRoot\..\..\Helpers\PerformanceCountersFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-AllNicInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-NetworkingInformation {
    [CmdletBinding()]
    param(
        [string]$Server = $env:COMPUTERNAME
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $ipv6DisabledOnNICs = $false
        $httpProxy = $null
        $packetsReceivedDiscarded = $null
        $networkAdapters = @()
    } process {
        Get-HttpProxySetting | Invoke-RemotePipelineHandler -Result ([ref]$httpProxy)
        Get-LocalizedCounterSamples -MachineName $Server -Counter "\Network Interface(*)\Packets Received Discarded" |
            Invoke-RemotePipelineHandler -Result ([ref]$packetsReceivedDiscarded)
        Get-AllNicInformation -CatchActionFunction ${Function:Invoke-CatchActions} | Invoke-RemotePipelineHandler -Result ([ref]$networkAdapters)

        foreach ($adapter in $networkAdapters.Adapters) {
            if (-not ($adapter.IPv6Enabled)) {
                $ipv6DisabledOnNICs = $true
                break
            }
        }
    } end {
        return [PSCustomObject]@{
            HttpProxy                = $httpProxy
            PacketsReceivedDiscarded = $packetsReceivedDiscarded
            NetworkAdapters          = $networkAdapters
            IPv6DisabledOnNICs       = $ipv6DisabledOnNICs
        }
    }
}
