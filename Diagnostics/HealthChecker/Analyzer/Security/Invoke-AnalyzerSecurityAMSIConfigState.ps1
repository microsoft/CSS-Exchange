﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
. $PSScriptRoot\..\Get-FilteredSettingOverrideInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

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

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
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
    $isE16CU21Plus = $null
    $isE19CU10Plus = $null
    $isExSeRtmPlus = $null
    Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2016" -CU "CU21" |
        Invoke-RemotePipelineHandler -Result ([ref]$isE16CU21Plus)
    Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2019" -CU "CU10" |
        Invoke-RemotePipelineHandler -Result ([ref]$isE19CU10Plus)
    Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "ExchangeSE" -CU "RTM" |
        Invoke-RemotePipelineHandler -Result ([ref]$isExSeRtmPlus)

    if (($osInformation.BuildInformation.BuildVersion -ge [System.Version]"10.0.0.0") -and
        (($isE16CU21Plus) -or
        ($isE19CU10Plus) -or
        ($isExSeRtmPlus)) -and
        ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $false)) {

        $filterSettingOverrideParams = @{
            ExchangeSettingOverride = $HealthServerObject.ExchangeInformation.SettingOverrides
            GetSettingOverride      = $HealthServerObject.OrganizationInformation.GetSettingOverride
            FilterServer            = $HealthServerObject.ServerName
            FilterServerVersion     = $exchangeInformation.BuildInformation.VersionInformation.BuildVersion
            FilterComponentName     = "Cafe"
            FilterSectionName       = "HttpRequestFiltering"
            FilterParameterName     = "Enabled"
        }

        # Only thing that is returned is Accepted values and unique
        $amsiInformation = $null
        Get-FilteredSettingOverrideInformation @filterSettingOverrideParams | Invoke-RemotePipelineHandlerList -Result ([ref]$amsiInformation)
        $amsiWriteType = "Yellow"
        $amsiConfigurationWarning = "`r`n`t`tThis may pose a security risk to your servers"
        $amsiMoreInfo = "More Information: https://aka.ms/HC-AMSIExchange"
        $amsiMoreInformationDisplay = $false
        $amsiConfigurationUnknown = "Exchange AMSI integration state is unknown"
        $additionalAMSIDisplayValue = $null

        if ($amsiInformation.Count -eq 0) {
            # No results returned, no matches therefore good.
            $amsiWriteType = "Green"
            $amsiState = "True"
        } elseif ($amsiInformation -eq "Unknown") {
            $additionalAMSIDisplayValue = "Unable to query Exchange AMSI integration state"
        } elseif ($amsiInformation.Count -eq 1) {
            $amsiState = $amsiInformation.ParameterValue
            if ($amsiInformation.ParameterValue -eq "False") {
                $additionalAMSIDisplayValue = "Setting applies to the server" + $amsiConfigurationWarning + "`r`n`t`t" + $amsiMoreInfo
            } elseif ($amsiInformation.ParameterValue -eq "True") {
                $amsiWriteType = "Green"
            } else {
                $additionalAMSIDisplayValue = $amsiConfigurationUnknown + " - Setting Override Name: $($amsiInformation.Name)"
                $additionalAMSIDisplayValue += $amsiConfigurationWarning + "`r`n`t`t" + $amsiMoreInfo
            }
        } else {
            $amsiState = "Multiple overrides detected"
            $additionalAMSIDisplayValue = $amsiConfigurationUnknown + " - Multi Setting Overrides Applied: $([string]::Join(", ", [array]$amsiInformation.Name))"
            $additionalAMSIDisplayValue += $amsiConfigurationWarning + "`r`n`t`t" + $amsiMoreInfo
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

        <#
            AMSI Needs to be enabled in order for Request Body Scanning to work. If Aug25SU is installed, EnabledAll is set to true by default.
            - If request body scanning is enabled, but AMSI is disabled, call out this misconfiguration
            - If request body max size is enabled, if the HTTP request body size is over 1MB regardless if AMSI is enabled,
                it will be rejected.
            - If request body scanning is enabled and AMSI is enabled, then just show enabled.
        #>

        $isAug25SuOrGreater = Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName "Aug25SU"
        $amsiStateEnabled = "true" -eq $amsiState
        $filterSettingOverrideParams.FilterSectionName = "AmsiRequestBodyScanning"
        $filterSettingOverrideParams.FilterParameterName = @("EnabledAll", "EnabledApi", "EnabledAutoD", "EnabledEcp",
            "EnabledEws", "EnabledMapi", "EnabledEas", "EnabledOab", "EnabledOwa", "EnabledPowerShell", "EnabledOthers")
        [array]$amsiRequestBodyScanning = $null
        Get-FilteredSettingOverrideInformation @filterSettingOverrideParams | Invoke-RemotePipelineHandlerList -Result ([ref]$amsiRequestBodyScanning)
        $filterSettingOverrideParams.FilterSectionName = "BlockRequestBodyGreaterThanMaxScanSize"
        [array]$amsiBlockRequestBodyGreater = $null
        Get-FilteredSettingOverrideInformation @filterSettingOverrideParams | Invoke-RemotePipelineHandlerList -Result ([ref]$amsiBlockRequestBodyGreater)
        [array]$enabledAllValues = $amsiRequestBodyScanning | Where-Object { $_.ParameterName -eq "EnabledAll" }
        $defaultEnabledAll = $isAug25SuOrGreater -and ($null -eq ($enabledAllValues | Where-Object { $_.ParameterValue -eq "False" }))
        Write-Verbose "Enabled All Default Value Set to '$defaultEnabledAll'"
        $amsiRequestBodyScanningEnabled = $defaultEnabledAll -or ($amsiRequestBodyScanning.Count -gt 0 -and
            ($null -ne ($amsiRequestBodyScanning | Where-Object { $_.ParameterValue -eq "True" })))
        $amsiBlockRequestBodyEnabled = $amsiBlockRequestBodyGreater.Count -gt 0 -and
        ($null -ne ($amsiBlockRequestBodyGreater | Where-Object { $_.ParameterValue -eq "True" }))
        $requestBodyDisplayValue = $amsiStateEnabled -and $amsiRequestBodyScanningEnabled
        $requestBodyDisplayType = $requestBodySizeBlockDisplayType = "Grey"
        $requestBodySizeBlockDisplayValue = $false

        if ($amsiBlockRequestBodyEnabled) {
            $requestBodySizeBlockDisplayValue = "$true - WARNING: Requests over 1MB will be blocked."
            $requestBodySizeBlockDisplayType = "Yellow"
            $amsiMoreInformationDisplay = $true
        }

        if ($amsiStateEnabled -eq $false) {
            if ($amsiRequestBodyScanningEnabled) {
                $requestBodyDisplayValue = "$true - WARNING: AMSI not enabled"
                $requestBodyDisplayType = "Yellow"
                $amsiMoreInformationDisplay = $true
            }
            if ($amsiBlockRequestBodyEnabled) {
                $requestBodySizeBlockDisplayValue += " AMSI not enabled and this will still be triggered."
                $amsiMoreInformationDisplay = $true
            }
        }

        $params = $baseParams + @{
            Name             = "AMSI Request Body Scanning"
            Details          = $requestBodyDisplayValue
            DisplayWriteType = $requestBodyDisplayType
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Name             = "AMSI Request Body Size Block"
            Details          = $requestBodySizeBlockDisplayValue
            DisplayWriteType = $requestBodySizeBlockDisplayType
        }
        Add-AnalyzedResultInformation @params

        $isNov24SUOrGreater = $false
        Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName "Nov24SU" |
            Invoke-RemotePipelineHandler -Result ([ref]$isNov24SUOrGreater)
        if (($amsiRequestBodyScanningEnabled -or
                $amsiBlockRequestBodyEnabled) -and
            -not ($isNov24SUOrGreater)) {
            $params = $baseParams + @{
                Details                = "AMSI Body Scanning Option(s) enabled, but not applicable due to the version of Exchange. Must be on Nov24SU or greater to have this feature enabled."
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }

        if ($amsiMoreInformationDisplay) {
            $params = $baseParams + @{
                Details                = $amsiMoreInfo
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }
    } else {
        Write-Verbose "AMSI integration is not available because we are on: $($exchangeInformation.BuildInformation.MajorVersion) $exchangeCU"
    }
    Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($stopWatch.Elapsed.TotalSeconds) seconds"
}
