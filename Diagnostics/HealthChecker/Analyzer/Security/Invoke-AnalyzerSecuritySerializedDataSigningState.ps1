# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\Get-FilteredSettingOverrideInformation.ps1
. $PSScriptRoot\..\..\Helpers\CompareExchangeBuildLevel.ps1
function Invoke-AnalyzerSecuritySerializedDataSigningState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $exchangeBuild = $exchangeInformation.BuildInformation.VersionInformation.BuildVersion
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    <#
        SerializedDataSigning was introduced with the January 2023 Exchange Server Security Update
        By now, it is disabled by default and must be enabled like this:
        - Exchange 2016/2019 > Feature must be enabled via New-SettingOverride
        - Exchange 2013 > Feature must be enabled via EnableSerializationDataSigning registry value

        Note:
        If the registry value is set on E16/E19, it will be ignored.
        Same goes for the SettingOverride set on E15 - it will be ignored and the feature remains off until the registry value is set.
    #>

    if ((Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName "Jan23SU") -and
        ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false)) {
        Write-Verbose "SerializedDataSigning is available on this Exchange role / version build combination"
        $serializedDataSigningWriteType = "Yellow"

        if ($exchangeBuild -ge "15.1.0.0") {
            Write-Verbose "Checking SettingOverride for SerializedDataSigning configuration state"

            $params = @{
                ExchangeSettingOverride = $exchangeInformation.SettingOverrides
                GetSettingOverride      = $HealthServerObject.OrganizationInformation.GetSettingOverride
                FilterServer            = $HealthServerObject.ServerName
                FilterServerVersion     = $exchangeBuild
                FilterComponentName     = "Data"
                FilterSectionName       = "EnableSerializationDataSigning"
                FilterParameterName     = "Enabled"
            }

            [array]$serializedDataSigningSettingOverride = Get-FilteredSettingOverrideInformation @params

            if ($null -eq $serializedDataSigningSettingOverride) {
                Write-Verbose "SerializedDataSigning is not configured via SettingOverride and is considered disabled"
                $serializedDataSigningState = $false
            } elseif ($serializedDataSigningSettingOverride.Count -eq 1) {
                $stateValue = $serializedDataSigningSettingOverride.ParameterValue
                if ($stateValue -eq "False") {
                    Write-Verbose "SerializedDataSigning is explicitly disabled"
                    $serializedDataSigningState = $false
                    $additionalSerializedDataSigningDisplayValue = "SerializedDataSigning is explicitly disabled"
                } elseif ($stateValue -eq "True") {
                    Write-Verbose "SerializedDataSigning is enabled for the server"
                    $serializedDataSigningState = $true
                    $serializedDataSigningWriteType = "Green"
                } else {
                    Write-Verbose "Unknown value provided"
                    $serializedDataSigningState = "Unknown"
                    $serializedDataSigningWriteType = "Red"
                    $additionalSerializedDataSigningDisplayValue = "SerializedDataSigning is unknown"
                }
            } else {
                Write-Verbose "Multi overrides detected"
                $serializedDataSigningState = "Unknown"
                $serializedDataSigningWriteType = "Red"
                $additionalSerializedDataSigningDisplayValue = "SerializedDataSigning is unknown - Multi Setting Overrides Applied: $([string]::Join(", ", $serializedDataSigningSettingOverride.Name))"
            }
        } else {
            Write-Verbose "Checking Registry Value for SerializedDataSigning configuration state"
            if ($exchangeInformation.RegistryValues.SerializedDataSigning -eq 1) {
                Write-Verbose "SerializedDataSigning enabled via Registry Value"
                $serializedDataSigningState = $true
                $serializedDataSigningWriteType = "Green"
            } else {
                Write-Verbose "SerializedDataSigning not configured or explicitly disabled via Registry Value"
                $serializedDataSigningState = $false
            }
        }

        $params = $baseParams + @{
            Name             = "SerializedDataSigning Enabled"
            Details          = $serializedDataSigningState
            DisplayWriteType = $serializedDataSigningWriteType
        }
        Add-AnalyzedResultInformation @params

        # Always display if not true
        if (-not ($serializedDataSigningState -eq $true)) {
            $addLine = "This may pose a security risk to your servers`r`n`t`tMore Information: https://aka.ms/HC-SerializedDataSigning"

            if ($null -ne $additionalSerializedDataSigningDisplayValue) {
                $details = "$additionalSerializedDataSigningDisplayValue`r`n`t`t$addLine"
            } else {
                $details = $addLine
            }

            $params = $baseParams + @{
                Details                = $details
                DisplayWriteType       = $serializedDataSigningWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }
    } else {
        Write-Verbose "SerializedDataSigning isn't available because we are on role: $($exchangeInformation.BuildInformation.ServerRole) build: $exchangeBuild"
    }
}
