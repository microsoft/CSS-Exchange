# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
. $PSScriptRoot\..\Get-FilteredSettingOverrideInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1

function Invoke-AnalyzerSecurityAMSIConfigState {
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
    $exchangeCU = $exchangeInformation.BuildInformation.CU
    $osInformation = $HealthServerObject.OSInformation
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    # AMSI integration is only available on Windows Server 2016 or higher and only on
    # Exchange Server 2016 CU21+ or Exchange Server 2019 CU10+.
    # AMSI is also not available on Edge Transport Servers (no http component available).
    if (($osInformation.BuildInformation.BuildVersion -ge [System.Version]"10.0.0.0") -and
        ((Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2016" -CU "CU21") -or
        (Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2019" -CU "CU10")) -and
        ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false)) {

        $params = @{
            ExchangeSettingOverride = $HealthServerObject.ExchangeInformation.SettingOverrides
            GetSettingOverride      = $HealthServerObject.OrganizationInformation.GetSettingOverride
            FilterServer            = $HealthServerObject.ServerName
            FilterServerVersion     = $exchangeInformation.BuildInformation.VersionInformation.BuildVersion
            FilterComponentName     = "Cafe"
            FilterSectionName       = "HttpRequestFiltering"
            FilterParameterName     = "Enabled"
        }

        # Only thing that is returned is Accepted values and unique
        [array]$amsiInformation = Get-FilteredSettingOverrideInformation @params

        $amsiWriteType = "Yellow"
        $amsiConfigurationWarning = "`r`n`t`tThis may pose a security risk to your servers`r`n`t`tMore Information: https://aka.ms/HC-AMSIExchange"
        $amsiConfigurationUnknown = "Exchange AMSI integration state is unknown"
        $additionalAMSIDisplayValue = $null

        if ($null -eq $amsiInformation) {
            # No results returned, no matches therefore good.
            $amsiWriteType = "Green"
            $amsiState = "True"
        } elseif ($amsiInformation -eq "Unknown") {
            $additionalAMSIDisplayValue = "Unable to query Exchange AMSI integration state"
        } elseif ($amsiInformation.Count -eq 1) {
            $amsiState = $amsiInformation.ParameterValue
            if ($amsiInformation.ParameterValue -eq "False") {
                $additionalAMSIDisplayValue = "Setting applies to the server" + $amsiConfigurationWarning
            } elseif ($amsiInformation.ParameterValue -eq "True") {
                $amsiWriteType = "Green"
            } else {
                $additionalAMSIDisplayValue = $amsiConfigurationUnknown + " - Setting Override Name: $($amsiInformation.Name)"
                $additionalAMSIDisplayValue += $amsiConfigurationWarning
            }
        } else {
            $amsiState = "Multiple overrides detected"
            $additionalAMSIDisplayValue = $amsiConfigurationUnknown + " - Multi Setting Overrides Applied: $([string]::Join(", ", $amsiInformation.Name))"
            $additionalAMSIDisplayValue += $amsiConfigurationWarning
        }

        $params = $baseParams + @{
            Name             = "AMSI Enabled"
            Details          = $amsiState
            DisplayWriteType = $amsiWriteType
        }
        Add-AnalyzedResultInformation @params

        if ($null -ne $additionalAMSIDisplayValue) {
            $params = $baseParams + @{
                Details                = $additionalAMSIDisplayValue
                DisplayWriteType       = $amsiWriteType
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }
    } else {
        Write-Verbose "AMSI integration is not available because we are on: $($exchangeInformation.BuildInformation.MajorVersion) $exchangeCU"
    }
}
