# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2020-0796.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2020-1147.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2021-1730.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-2021-34470.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityCve-MarchSuSpecial.ps1
. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
Function Invoke-AnalyzerSecurityCveCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    Function TestVulnerabilitiesByBuildNumbersForDisplay {
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
                    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Security Vulnerability" `
                        -Details ("{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/{0} for more information." -f $cveName) `
                        -DisplayGroupingKey $DisplayGroupingKey `
                        -DisplayTestingValue $cveName `
                        -DisplayWriteType "Red" `
                        -AddHtmlDetailRow $false
                }
                break
            }

            if ($Script:breakpointHit) {
                break
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

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) {

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU19) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1347.5", "1365.3" `
                -CVENames "CVE-2018-0924", "CVE-2018-0940"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU20) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1365.7", "1367.6" `
                -CVENames "CVE-2018-8151", "CVE-2018-8154", "CVE-2018-8159"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU21) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1367.9", "1395.7" `
                -CVENames "CVE-2018-8302"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1395.8" `
                -CVENames "CVE-2018-8265", "CVE-2018-8448"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1395.10" `
                -CVENames "CVE-2019-0586", "CVE-2019-0588"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU22) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1473.3" `
                -CVENames "CVE-2019-0686", "CVE-2019-0724"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1473.4" `
                -CVENames "CVE-2019-0817", "CVE-2019-0858"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1473.5" `
                -CVENames "ADV190018"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU23) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.3" `
                -CVENames "CVE-2019-1084", "CVE-2019-1136", "CVE-2019-1137"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.4" `
                -CVENames "CVE-2019-1373"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.6" `
                -CVENames "CVE-2020-0688", "CVE-2020-0692"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.7" `
                -CVENames "CVE-2020-16969"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.8" `
                -CVENames "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.10" `
                -CVENames "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17142", "CVE-2020-17143"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1395.12", "1473.6", "1497.12" `
                -CVENames "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.12" `
                -CVENames "CVE-2021-26412", "CVE-2021-27078", "CVE-2021-26854"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.15" `
                -CVENames "CVE-2021-28480", "CVE-2021-28481", "CVE-2021-28482", "CVE-2021-28483"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.18" `
                -CVENames "CVE-2021-31195", "CVE-2021-31198", "CVE-2021-31207", "CVE-2021-31209"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1497.23" `
                -CVENames "CVE-2021-31206", "CVE-2021-31196", "CVE-2021-33768"
        }
    } elseif ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) {

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU8) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1261.39", "1415.4" `
                -CVENames "CVE-2018-0924", "CVE-2018-0940", "CVE-2018-0941"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU9) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1415.7", "1466.8" `
                -CVENames "CVE-2018-8151", "CVE-2018-8152", "CVE-2018-8153", "CVE-2018-8154", "CVE-2018-8159"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU10) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1466.9", "1531.6" `
                -CVENames "CVE-2018-8374", "CVE-2018-8302"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1531.8" `
                -CVENames "CVE-2018-8265", "CVE-2018-8448"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU11) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1531.8", "1591.11" `
                -CVENames "CVE-2018-8604"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1531.10", "1591.13" `
                -CVENames "CVE-2019-0586", "CVE-2019-0588"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU12) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1591.16", "1713.6" `
                -CVENames "CVE-2019-0817", "CVE-2018-0858"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1591.17", "1713.7" `
                -CVENames "ADV190018"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1713.5" `
                -CVENames "CVE-2019-0686", "CVE-2019-0724"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU13) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1713.8", "1779.4" `
                -CVENames "CVE-2019-1084", "CVE-2019-1136", "CVE-2019-1137"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1713.9", "1779.5" `
                -CVENames "CVE-2019-1233", "CVE-2019-1266"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU14) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1779.7", "1847.5" `
                -CVENames "CVE-2019-1373"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU15) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1847.7", "1913.7" `
                -CVENames "CVE-2020-0688", "CVE-2020-0692"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1847.10", "1913.10" `
                -CVENames "CVE-2020-0903"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU17) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1979.6", "2044.6" `
                -CVENames "CVE-2020-16875"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU18) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2106.2" `
                -CVENames "CVE-2021-1730"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2044.7", "2106.3" `
                -CVENames "CVE-2020-16969"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2044.8", "2106.4" `
                -CVENames "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2044.12", "2106.6" `
                -CVENames "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17141", "CVE-2020-17142", "CVE-2020-17143"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU19) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2106.8", "2176.4" `
                -CVENames "CVE-2021-24085"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "1415.8", "1466.13", "1531.12", "1591.18", "1713.10", "1779.8", "1847.12", "1913.12", "1979.8", "2044.13", "2106.13", "2176.9" `
                -CVENames "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2106.13", "2176.9" `
                -CVENames "CVE-2021-26412", "CVE-2021-27078", "CVE-2021-26854"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU20) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2176.12", "2242.8" `
                -CVENames "CVE-2021-28480", "CVE-2021-28481", "CVE-2021-28482", "CVE-2021-28483"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2176.14", "2242.10" `
                -CVENames "CVE-2021-31195", "CVE-2021-31198", "CVE-2021-31207", "CVE-2021-31209"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU21) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "2242.12", "2308.14" `
                -CVENames "CVE-2021-31206", "CVE-2021-31196", "CVE-2021-33768"
        }
    } elseif ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU1) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "221.14" `
                -CVENames "CVE-2019-0586", "CVE-2019-0588"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "221.16", "330.7" `
                -CVENames "CVE-2019-0817", "CVE-2019-0858"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "221.17", "330.8" `
                -CVENames "ADV190018"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "330.6" `
                -CVENames "CVE-2019-0686", "CVE-2019-0724"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU2) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "330.9", "397.5" `
                -CVENames "CVE-2019-1084", "CVE-2019-1137"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "397.6", "330.10" `
                -CVENames "CVE-2019-1233", "CVE-2019-1266"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU3) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "397.9", "464.7" `
                -CVENames "CVE-2019-1373"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU4) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "464.11", "529.8" `
                -CVENames "CVE-2020-0688", "CVE-2020-0692"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "464.14", "529.11" `
                -CVENames "CVE-2020-0903"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU6) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "595.6", "659.6" `
                -CVENames "CVE-2020-16875"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU7) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "721.2" `
                -CVENames "CVE-2021-1730"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "659.7", "721.3" `
                -CVENames "CVE-2020-16969"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "659.8", "721.4" `
                -CVENames "CVE-2020-17083", "CVE-2020-17084", "CVE-2020-17085"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "659.11", "721.6" `
                -CVENames "CVE-2020-17117", "CVE-2020-17132", "CVE-2020-17141", "CVE-2020-17142", "CVE-2020-17143"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU8) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "721.8", "792.5" `
                -CVENames "CVE-2021-24085"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "221.18", "330.11", "397.11", "464.15", "529.13", "595.8", "659.12", "721.13", "792.10" `
                -CVENames "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "721.13", "792.10" `
                -CVENames "CVE-2021-26412", "CVE-2021-27078", "CVE-2021-26854"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU9) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "792.13", "858.10" `
                -CVENames "CVE-2021-28480", "CVE-2021-28481", "CVE-2021-28482", "CVE-2021-28483"
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "792.15", "858.12" `
                -CVENames "CVE-2021-31195", "CVE-2021-31198", "CVE-2021-31207", "CVE-2021-31209"
        }

        if ($exchangeCU -le [HealthChecker.ExchangeCULevel]::CU10) {
            TestVulnerabilitiesByBuildNumbersForDisplay -ExchangeBuildRevision $buildRevision `
                -SecurityFixedBuilds "858.15", "922.13" `
                -CVENames "CVE-2021-31206", "CVE-2021-31196", "CVE-2021-33768"
        }
    } else {
        Write-Verbose "Unknown Version of Exchange"
    }

    $securityObject = [PSCustomObject]@{
        MajorVersion        = $exchangeInformation.BuildInformation.MajorVersion
        ServerRole          = $exchangeInformation.BuildInformation.ServerRole
        CU                  = $exchangeCU
        BuildRevision       = $buildRevision
        ExchangeInformation = $exchangeInformation
        OsInformation       = $osInformation
    }

    Invoke-AnalyzerSecurityCve-2020-0796 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2020-1147 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2021-1730 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-2021-34470 -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
    Invoke-AnalyzerSecurityCve-MarchSuSpecial -AnalyzeResults $AnalyzeResults -SecurityObject $securityObject -DisplayGroupingKey $DisplayGroupingKey
}
