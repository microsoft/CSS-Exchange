# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-ExchangeRegistryValues {
    [CmdletBinding()]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [ScriptBlock]$CatchActionFunction
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $baseParams = @{
        MachineName         = $MachineName
        CatchActionFunction = $CatchActionFunction
    }

    $ctsParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\ExchangeServer\v15\Search\SystemParameters"
        GetValue = "CtsProcessorAffinityPercentage"
    }

    $fipsParams = $baseParams + @{
        SubKey   = "SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
        GetValue = "Enabled"
    }

    $blockReplParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\ExchangeServer\v15\Replay\Parameters"
        GetValue = "DisableGranularReplication"
    }

    $disableAsyncParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\ExchangeServer\v15"
        GetValue = "DisableAsyncNotification"
    }

    $serializedDataSigningParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics"
        GetValue = "EnableSerializationDataSigning"
    }

    $installDirectoryParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\ExchangeServer\v15\Setup"
        GetValue = "MsiInstallPath"
    }

    $baseTypeCheckForDeserializationParams = $baseParams + @{
        SubKey   = "SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics"
        GetValue = "DisableBaseTypeCheckForDeserialization"
    }

    $disablePreservationParams = $baseParams + @{
        SubKey    = "SOFTWARE\Microsoft\ExchangeServer\v15\Setup"
        GetValue  = "DisablePreservation"
        ValueType = "String"
    }

    $fipFsDatabasePathParams = $baseParams + @{
        SubKey    = "SOFTWARE\Microsoft\ExchangeServer\v15\FIP-FS"
        GetValue  = "DatabasePath"
        ValueType = "String"
    }

    $eccCertificateSupportParams = $baseParams + @{
        SubKey    = "SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics"
        GetValue  = "EnableEccCertificateSupport"
        ValueType = "String"
    }

    $disableBaseTypeCheckForDeserializationValue = $null
    $ctsProcessorAffinityPercentageValue = $null
    $fipsAlgorithmPolicyEnabledValue = $null
    $disableGranularReplicationValue = $null
    $disableAsyncNotificationValue = $null
    $serializedDataSigningValue = $null
    $msiInstallPathValue = $null
    $disablePreservationValue = $null
    $fipFsDatabasePathValue = $null
    $enableEccCertificateSupportValue = $null

    Get-RemoteRegistryValue @baseTypeCheckForDeserializationParams | Invoke-RemotePipelineHandler -Result ([ref]$disableBaseTypeCheckForDeserializationValue)
    Get-RemoteRegistryValue @ctsParams | Invoke-RemotePipelineHandler -Result ([ref]$ctsProcessorAffinityPercentageValue)
    Get-RemoteRegistryValue @fipsParams | Invoke-RemotePipelineHandler -Result ([ref]$fipsAlgorithmPolicyEnabledValue)
    Get-RemoteRegistryValue @blockReplParams | Invoke-RemotePipelineHandler -Result ([ref]$disableGranularReplicationValue)
    Get-RemoteRegistryValue @disableAsyncParams | Invoke-RemotePipelineHandler -Result ([ref]$disableAsyncNotificationValue)
    Get-RemoteRegistryValue @serializedDataSigningParams | Invoke-RemotePipelineHandler -Result ([ref]$serializedDataSigningValue)
    Get-RemoteRegistryValue @installDirectoryParams | Invoke-RemotePipelineHandler -Result ([ref]$msiInstallPathValue)
    Get-RemoteRegistryValue @disablePreservationParams | Invoke-RemotePipelineHandler -Result ([ref]$disablePreservationValue)
    Get-RemoteRegistryValue @fipFsDatabasePathParams | Invoke-RemotePipelineHandler -Result ([ref]$fipFsDatabasePathValue)
    Get-RemoteRegistryValue @eccCertificateSupportParams | Invoke-RemotePipelineHandler -Result ([ref]$enableEccCertificateSupportValue)

    return [PSCustomObject]@{
        DisableBaseTypeCheckForDeserialization = [int]$disableBaseTypeCheckForDeserializationValue
        CtsProcessorAffinityPercentage         = [int]$ctsProcessorAffinityPercentageValue
        FipsAlgorithmPolicyEnabled             = [int]$fipsAlgorithmPolicyEnabledValue
        DisableGranularReplication             = [int]$disableGranularReplicationValue
        DisableAsyncNotification               = [int]$disableAsyncNotificationValue
        SerializedDataSigning                  = [int]$serializedDataSigningValue
        MsiInstallPath                         = [string]$msiInstallPathValue
        DisablePreservation                    = [string]$disablePreservationValue
        FipFsDatabasePath                      = [string]$fipFsDatabasePathValue
        EnableEccCertificateSupport            = [string]$enableEccCertificateSupportValue
    }
}
