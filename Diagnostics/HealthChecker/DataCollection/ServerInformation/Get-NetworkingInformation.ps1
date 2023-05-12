# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-HttpProxySetting.ps1
. $PSScriptRoot\..\..\Helpers\PerformanceCountersFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-AllNicInformation.ps1

function Get-NetworkingInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $ipv6DisabledOnNICs = $false
    } process {
        $httpProxy = Get-HttpProxySetting -Server $Server
        $packetsReceivedDiscarded = (Get-LocalizedCounterSamples -MachineName $Server -Counter "\Network Interface(*)\Packets Received Discarded")
        $networkAdapters = @(Get-AllNicInformation -ComputerName $Server -CatchActionFunction ${Function:Invoke-CatchActions} -ComputerFQDN $ServerFQDN)

        foreach ($adapter in $networkAdapters) {
            if (-not ($adapter.IPv6Enabled)) {
                $ipv6DisabledOnNICs = $true
                break
            }
        }
    } end {
        return [PSCustomObject]@{
            HttpProxy                = $httpProxy
            PacketsReceivedDiscarded = $packetsReceivedDiscarded
            NetworkAdapters          = [array]$networkAdapters
            IPv6DisabledOnNICs       = $ipv6DisabledOnNICs
        }
    }
}
