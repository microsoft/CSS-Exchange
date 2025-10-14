# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

<#
.DESCRIPTION
    This is a generic check for CVEs that are now being released behind an override.
    This is to make sure that the override is not set and that the code is applied to make the CVE not applicable.
.PARAMETER SettingOverrideInformation
    SettingOverrideParams
        ExchangeSettingOverride
        GetSettingOverride
        FilterServer
        FilterServerVersion
        FilterComponentName
        FilterSectionName
        FilterParameterName
    FilterParameterValueMatch
#>
function Invoke-AnalyzerSecurityCveAndOverrideCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$CurrentExchangeBuild,

        [Parameter(Mandatory = $true)]
        [object[]]$SettingOverrideInformation,

        [Parameter(Mandatory = $true)]
        [string]$SUName,

        [Parameter(Mandatory = $true)]
        [string]$CVEName,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $overrideDisabled = $false
        $isSuApplied = $null
        Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $CurrentExchangeBuild -SUName $SUName |
            Invoke-RemotePipelineHandler -Result ([ref]$isSuApplied)

        if ($isSuApplied) {
            foreach ($settingOverrideInfo in $SettingOverrideInformation) {
                [array]$settingOverrideResults = $null
                $params = $settingOverrideInfo.SettingOverrideParams
                Get-FilteredSettingOverrideInformation @params | Invoke-RemotePipelineHandlerList -Result ([ref]$settingOverrideResults)

                $overrideDisabled = $settingOverrideResults.Count -gt 0 -and
                ($null -ne ($settingOverrideResults | Where-Object { $_.ParameterValue -eq $settingOverrideInfo.FilterParameterValueMatch }))

                if ($overrideDisabled) {
                    break
                }
            }
        }

        if (-not $isSuApplied -or $overrideDisabled) {
            $params = @{
                AnalyzedInformation = $AnalyzeResults
                DisplayGroupingKey  = $DisplayGroupingKey
                Name                = "Security Vulnerability"
                Details             = ("{0}$(if($overrideDisabled){" - Disabled By Override"})`r`n`t`tSee: https://portal.msrc.microsoft.com/security-guidance/advisory/{0} for more information." -f $CVEName)
                DisplayWriteType    = "Red"
                DisplayTestingValue = $CVEName
            }
            Add-AnalyzedResultInformation @params
        }
    }
}
