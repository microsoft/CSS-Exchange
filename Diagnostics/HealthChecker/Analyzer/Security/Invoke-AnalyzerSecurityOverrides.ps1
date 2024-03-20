# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\Get-FilteredSettingOverrideInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
function Invoke-AnalyzerSecurityOverrides {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    <#
        This function is used to analyze overrides which are enabled via SettingOverride or Registry Value
    #>

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $exchangeBuild = $exchangeInformation.BuildInformation.VersionInformation.BuildVersion
    $strictModeDisabledLocationsList = New-Object System.Collections.Generic.List[string]
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    if ($exchangeBuild -ge "15.1.0.0") {
        Write-Verbose "Checking SettingOverride for Strict Mode configuration state"
        $params = @{
            ExchangeSettingOverride = $exchangeInformation.SettingOverrides
            GetSettingOverride      = $HealthServerObject.OrganizationInformation.GetSettingOverride
            FilterServer            = $HealthServerObject.ServerName
            FilterServerVersion     = $exchangeBuild
            FilterComponentName     = "Data"
            FilterSectionName       = "DeserializationBinderSettings"
            FilterParameterName     = "LearningLocations"
        }

        [array]$deserializationBinderSettings = Get-FilteredSettingOverrideInformation @params

        if ($null -ne $deserializationBinderSettings) {
            foreach ($setting in $deserializationBinderSettings) {
                Write-Verbose "Strict Mode has been disabled via SettingOverride for $($setting.ParameterValue) location"
                $strictModeDisabledLocationsList.Add($setting.ParameterValue)
            }
        }

        $params = $baseParams + @{
            Name             = "Strict Mode disabled"
            Details          = $strictModeDisabledLocationsList.Count -gt 0
            DisplayWriteType = if ($strictModeDisabledLocationsList.Count -gt 0) { "Red" } else { "Green" }
        }
        Add-AnalyzedResultInformation @params

        foreach ($location in $strictModeDisabledLocationsList) {
            $params = $baseParams + @{
                Name                   = "Location"
                Details                = $location
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }
    }

    Write-Verbose "Checking Registry Value for BaseTypeCheckForDeserialization configuration state"
    $disableBaseTypeCheckForDeserializationSettingsState = $exchangeInformation.RegistryValues.DisableBaseTypeCheckForDeserialization -eq 1

    $params = $baseParams + @{
        Name             = "BaseTypeCheckForDeserialization disabled"
        Details          = $disableBaseTypeCheckForDeserializationSettingsState
        DisplayWriteType = if ($disableBaseTypeCheckForDeserializationSettingsState) { "Red" } else { "Green" }
    }
    Add-AnalyzedResultInformation @params

    if (($strictModeDisabledLocationsList.Count -gt 0) -or
        ($disableBaseTypeCheckForDeserializationSettingsState)) {
        $params = $baseParams + @{
            Details                = "These overrides should only be used in very limited failure scenarios" +
            "`n`t`tRollback instructions: https://aka.ms/HC-SettingOverrides"
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }
}
