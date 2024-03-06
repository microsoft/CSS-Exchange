# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-AnalyzerSecurityADV24199947.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2020-0796.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2020-1147.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2021-1730.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2021-34470.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2022-21978.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2023-36434.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCveAddressedBySerializedDataSigning.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-MarchSuSpecial.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityExtendedProtectionConfigState.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityIISModules.ps1
. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
function Invoke-AnalyzerSecurityCveCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    function TestVulnerabilitiesByBuildNumbersForDisplay {
        param(
            [Parameter(Mandatory = $true)][string]$ExchangeBuildRevision,
            [Parameter(Mandatory = $true)][array]$SecurityFixedBuilds,
            [Parameter(Mandatory = $true)][array]$CVENames
        )
        [int]$fileBuildPart = ($split = $ExchangeBuildRevision.Split("."))[0]
        [int]$filePrivatePart = $split[1]
        $Script:breakpointHit = $false

        foreach ($securityFixedBuild in $SecurityFixedBuilds) {
            [int]$securityFixedBuildPart = ($split = $securityFixedBuild.Split("."))[0]
            [int]$securityFixedPrivatePart = $split[1]

            if ($fileBuildPart -eq $securityFixedBuildPart) {
                $Script:breakpointHit = $true
            }

            if (($fileBuildPart -lt $securityFixedBuildPart) -or
                    ($fileBuildPart -eq $securityFixedBuildPart -and
                $filePrivatePart -lt $securityFixedPrivatePart)) {
                foreach ($cveName in $CVENames) {
                    $params = @{
                        AnalyzedInformation = $AnalyzeResults
                        DisplayGroupingKey  = $DisplayGroupingKey
                        Name                = "Security Vulnerability"
                        Details             = ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/security-guidance/advisory/{0} for more information." -f $cveName)
                        DisplayWriteType    = "Red"
                        DisplayTestingValue = $cveName
                        AddHtmlDetailRow    = $false
                    }
                    Add-AnalyzedResultInformation @params
                }
                break
            }

            if ($Script:breakpointHit) {
                break
            }
        }
    }

    function NewCveEntry {
        param(
            [string[]]$CVENames,
            [string[]]$ExchangeVersion
        )
        foreach ($cve in $CVENames) {
            [PSCustomObject]@{
                CVE     = $cve
                Version = $ExchangeVersion
            }
        }
    }

    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation

    [string]$buildRevision = ("{0}.{1}" -f $exchangeInformation.BuildInformation.ExchangeSetup.FileBuildPart, `
            $exchangeInformation.BuildInformation.ExchangeSetup.FilePrivatePart)
    $exchangeCU = $exchangeInformation.BuildInformation.CU
    Write-Verbose "Exchange Build Revision: $buildRevision"
    Write-Verbose "Exchange CU: $exchangeCU"
    # This dictionary is a list of how to crawl through the list and add all the vulnerabilities to display
    # only place CVEs here that are fix by code fix only. If special checks are required, we need to check for that manually.
    $ex131619 = @("Exchange2013", "Exchange2016", "Exchange2019")
    $ex2013 = "Exchange2013"
    $ex2016 = "Exchange2016"
    $ex2019 = "Exchange2019"
    $suNameDictionary = @{
        "Mar18SU" = ((NewCveEntry @("CVE-2018-0924", "CVE-2018-0940") @($ex2013, $ex2016)) + (NewCveEntry "CVE-2018-0941" $ex2016))
        "May18SU" = ((NewCveEntry @("CVE-2018-8151", "CVE-2018-8154", "CVE-2018-8159") @($ex2013, $ex2016)) + (NewCveEntry @("CVE-2018-8152", "CVE-2018-8153") $ex2016))
        "Aug18SU" = (@((NewCveEntry "CVE-2018-8302" @($ex2013, $ex2016))) + (NewCveEntry "CVE-2018-8374" $ex2016))
        "Oct18SU" = (NewCveEntry @("CVE-2018-8265", "CVE-2018-8448") @($ex2013, $ex2016))
        "Dec18SU" = (@(NewCveEntry "CVE-2018-8604" $ex2016))
        "Jan19SU" = (NewCveEntry @("CVE-2019-0586", "CVE-2019-0588") @($ex2013, $ex2016))
        "Feb19SU" = (NewCveEntry @("CVE-2019-0686", "CVE-2019-0724") $ex131619)
        "Apr19SU" = (NewCveEntry @("CVE-2019-0817", "CVE-2019-0858") $ex131619)
        "Jun19SU" = (@(NewCveEntry @("ADV190018") $ex131619))
        "Jul19SU" = ((NewCveEntry @("CVE-2019-1084", "CVE-2019-1137") $ex131619) + (NewCveEntry "CVE-2019-1136" @($ex2013, $ex2016)))
        "Sep19SU" = (NewCveEntry @("CVE-2019-1233", "CVE-2019-1266") @($ex2016, $ex2019))
        "Nov19SU" = (@(NewCveEntry "CVE-2019-1373" $ex131619))
        "Feb20SU" = (NewCveEntry @("CVE-2020-0688", "CVE-2020-0692") $ex131619)
        "Mar20SU" = (@(NewCveEntry "CVE-2020-0903" @($ex2016, $ex2019)))
        "Sep20SU" = (@(NewCveEntry "CVE-2020-16875" @($ex2016, $ex2019)))
        "Oct20SU" = (@(NewCveEntry "CVE-2020-16969" $ex131619))
        "Nov20SU" = (NewCveEntry @("CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085") $ex131619)
        "Dec20SU" = ((NewCveEntry @("CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17142", "CVE-2020-17143") $ex131619) + (NewCveEntry "CVE-2020-17141" @($ex2016, $ex2019)))
        "Feb21SU" = (@(NewCveEntry "CVE-2021-24085" @($ex2016, $ex2019)))
        "Mar21SU" = (NewCveEntry @("CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065", "CVE-2021-26412", "CVE-2021-27078", "CVE-2021-26854") $ex131619)
        "Apr21SU" = (NewCveEntry @("CVE-2021-28480", "CVE-2021-28481", "CVE-2021-28482", "CVE-2021-28483") $ex131619)
        "May21SU" = (NewCveEntry @("CVE-2021-31195", "CVE-2021-31198", "CVE-2021-31207", "CVE-2021-31209") $ex131619)
        "Jul21SU" = (NewCveEntry @("CVE-2021-31206", "CVE-2021-31196", "CVE-2021-33768") $ex131619)
        "Oct21SU" = (@((NewCveEntry "CVE-2021-26427" $ex131619)) + (NewCveEntry @("CVE-2021-41350", "CVE-2021-41348", "CVE-2021-34453") @($ex2016, $ex2019)))
        "Nov21SU" = ((NewCveEntry @("CVE-2021-42305", "CVE-2021-41349") $ex131619) + (NewCveEntry "CVE-2021-42321" @($ex2016, $ex2019)))
        "Jan22SU" = (NewCveEntry @("CVE-2022-21855", "CVE-2022-21846", "CVE-2022-21969") $ex131619)
        "Mar22SU" = (@((NewCveEntry "CVE-2022-23277" $ex131619)) + (NewCveEntry "CVE-2022-24463" @($ex2016, $ex2019)))
        "Aug22SU" = (@(NewCveEntry "CVE-2022-34692" @($ex2016, $ex2019)))
        "Nov22SU" = ((NewCveEntry @("CVE-2022-41040", "CVE-2022-41082", "CVE-2022-41079", "CVE-2022-41078", "CVE-2022-41080") $ex131619) + (NewCveEntry "CVE-2022-41123" @($ex2016, $ex2019)))
        "Jan23SU" = (@((NewCveEntry "CVE-2023-21762" $ex131619)) + (NewCveEntry @("CVE-2023-21745", "CVE-2023-21761", "CVE-2023-21763", "CVE-2023-21764") @($ex2016, $ex2019)))
        "Feb23SU" = (@(NewCveEntry @("CVE-2023-21529", "CVE-2023-21706", "CVE-2023-21707") $ex131619) + (NewCveEntry "CVE-2023-21710" @($ex2016, $ex2019)))
        "Mar23SU" = (@(NewCveEntry ("CVE-2023-21707") $ex131619))
        "Jun23SU" = (NewCveEntry @("CVE-2023-28310", "CVE-2023-32031") @($ex2016, $ex2019))
        "Aug23SU" = (NewCveEntry @("CVE-2023-38181", "CVE-2023-38182", "CVE-2023-38185", "CVE-2023-35368", "CVE-2023-35388", "CVE-2023-36777", "CVE-2023-36757", "CVE-2023-36756", "CVE-2023-36745", "CVE-2023-36744") @($ex2016, $ex2019))
        "Oct23SU" = (NewCveEntry @("CVE-2023-36778") @($ex2016, $ex2019))
        "Nov23SU" = (NewCveEntry @("CVE-2023-36050", "CVE-2023-36039", "CVE-2023-36035", "CVE-2023-36439") @($ex2016, $ex2019))
        "Mar24SU" = (NewCveEntry @("CVE-2024-26198") @($ex2016, $ex2019))
    }

    # Need to organize the list so oldest CVEs come out first.
    $monthOrder = @{
        "Jan" = 1
        "Feb" = 2
        "Mar" = 3
        "Apr" = 4
        "May" = 5
        "Jun" = 6
        "Jul" = 7
        "Aug" = 8
        "Sep" = 9
        "Oct" = 10
        "Nov" = 11
        "Dec" = 12
    }
    $unsortedKeys = @($suNameDictionary.Keys)
    $sortedKeys = New-Object System.Collections.Generic.List[string]

    foreach ($value in $unsortedKeys) {
        $month = $value.Substring(0, 3)
        $year = [int]$value.Substring(3, 2)
        $insertAt = 0
        while ($insertAt -lt $sortedKeys.Count) {

            $compareMonth = $sortedKeys[$insertAt].Substring(0, 3)
            $compareYear = [int]$sortedKeys[$insertAt].Substring(3, 2)
            # break to add at current spot in list
            if ($compareYear -gt $year) { break }
            elseif ( $compareYear -eq $year -and
                $monthOrder[$month] -lt $monthOrder[$compareMonth]) { break }

            $insertAt++
        }

        $sortedKeys.Insert($insertAt, $value)
    }

    foreach ($key in $sortedKeys) {
        if (-not (Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName $key)) {
            Write-Verbose "Tested that we aren't on SU $key or greater"
            $cveNames = ($suNameDictionary[$key] | Where-Object { $_.Version.Contains($exchangeInformation.BuildInformation.MajorVersion) }).CVE
            foreach ($cveName in $cveNames) {
                $params = @{
                    AnalyzedInformation = $AnalyzeResults
                    DisplayGroupingKey  = $DisplayGroupingKey
                    Name                = "Security Vulnerability"
                    Details             = ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/security-guidance/advisory/{0} for more information." -f $cveName)
                    DisplayWriteType    = "Red"
                    DisplayTestingValue = $cveName
                    AddHtmlDetailRow    = $false
                }
                Add-AnalyzedResultInformation @params
            }
        }
    }

    $securityObject = [PSCustomObject]@{
        BuildInformation    = $exchangeInformation.BuildInformation.VersionInformation
        MajorVersion        = $exchangeInformation.BuildInformation.MajorVersion
        IsEdgeServer        = $exchangeInformation.GetExchangeServer.IsEdgeServer
        ExchangeInformation = $exchangeInformation
        OsInformation       = $osInformation
        OrgInformation      = $HealthServerObject.OrganizationInformation
    }

    Invoke-AnalyzerSecurityIISModules -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2020-0796 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2020-1147 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2021-1730 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2021-34470 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2022-21978 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2023-36434 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCveAddressedBySerializedDataSigning -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-MarchSuSpecial -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityADV24199947 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    # Make sure that these stay as the last one to keep the output more readable
    Invoke-AnalyzerSecurityExtendedProtectionConfigState -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
}
