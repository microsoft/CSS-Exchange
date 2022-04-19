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

    $blockReplParams = @{
        MachineName         = $MachineName
        SubKey              = "SOFTWARE\Microsoft\ExchangeServer\v15\Replay\Parameters"
        GetValue            = "DisableGranularReplication"
        CatchActionFunction = $CatchActionFunction
    }

    $disableAsyncParams = @{
        MachineName         = $MachineName
        SubKey              = "SOFTWARE\Microsoft\ExchangeServer\v15"
        GetValue            = "DisableAsyncNotification"
        CatchActionFunction = $CatchActionFunction
    }

    return [PSCustomObject]@{
        CtsProcessorAffinityPercentage = [int](Get-RemoteRegistryValue @ctsParams)
        FipsAlgorithmPolicyEnabled     = [int](Get-RemoteRegistryValue @fipsParams)
        DisableGranularReplication     = [int](Get-RemoteRegistryValue @blockReplParams)
        DisableAsyncNotification       = [int](Get-RemoteRegistryValue @disableAsyncParams)
    }
}
