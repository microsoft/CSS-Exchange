# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
Function Get-ExchangeRegistryValues {
    [CmdletBinding()]
    param(
        [string]$MachineName,
        [scriptblock]$CatchActionFunction
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $ctsParams = @{
        MachineName         = $MachineName
        SubKey              = "SOFTWARE\Microsoft\ExchangeServer\v15\Search\SystemParameters"
        GetValue            = "CtsProcessorAffinityPercentage"
        CatchActionFunction = $CatchActionFunction
    }

    $fipsParams = @{
        MachineName         = $MachineName
        SubKey              = "SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
        GetValue            = "Enabled"
        CatchActionFunction = $CatchActionFunction
    }

    return [PSCustomObject]@{
        CtsProcessorAffinityPercentage = [int](Get-RemoteRegistryValue @ctsParams)
        FipsAlgorithmPolicyEnabled     = [int](Get-RemoteRegistryValue @fipsParams)
    }
}
