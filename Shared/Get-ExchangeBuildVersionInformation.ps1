# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1

# This function is used to determine the version of Exchange based off a build number or
# by providing the Exchange Version and CU and/or SU. This provides one location in the entire repository
# that is required to be updated for when a new release of Exchange is dropped.
function Get-ExchangeBuildVersionInformation {
    [CmdletBinding(DefaultParameterSetName = "AdminDisplayVersion")]
    param(
        [Parameter(ParameterSetName = "AdminDisplayVersion", Position = 1)]
        [object]$AdminDisplayVersion,

        [Parameter(ParameterSetName = "ExSetup")]
        [System.Version]$FileVersion,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $true)]
        [ValidateSet("Exchange2013", "Exchange2016", "Exchange2019")]
        [string]$Version,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $true)]
        [ValidateSet("CU1", "CU2", "CU3", "CU4", "CU5", "CU6", "CU7", "CU8",
            "CU9", "CU10", "CU11", "CU12", "CU13", "CU14", "CU15", "CU16", "CU17",
            "CU18", "CU19", "CU20", "CU21", "CU22", "CU23")]
        [string]$CU,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $false)]
        [ValidateSet("Mar21SU", "Apr21SU", "May21SU", "Jul21SU", "Oct21SU",
            "Nov21SU", "Jan22SU", "Mar22SU", "May22SU", "Aug22SU", "Oct22SU",
            "Nov22SU", "Jan23SU")]
        [string]$SU,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        function NewCUAndSUObject {
            param(
                [string]$CUBuildNumber,
                [Hashtable]$SUBuildNumber
            )
            return @{
                "CU" = $CUBuildNumber
                "SU" = $SUBuildNumber
            }
        }

        function GetBuildVersion {
            param(
                [Parameter(Position = 1)]
                [string]$ExchangeVersion,
                [Parameter(Position = 2)]
                [string]$CU,
                [Parameter(Position = 3)]
                [string]$SU
            )
            $cuResult = $exchangeBuildDictionary[$ExchangeVersion][$CU]

            if ((-not [string]::IsNullOrEmpty($SU))  -and
                $cuResult.SU.ContainsKey($SU)) {
                return $cuResult.SU[$SU]
            } else {
                return $cuResult.CU
            }
        }

        # Dictionary of Exchange Version/CU/SU to build number
        $exchangeBuildDictionary = @{
            "Exchange2013" = @{
                "CU1"  = (NewCUAndSUObject "15.0.620.29")
                "CU2"  = (NewCUAndSUObject "15.0.712.24")
                "CU3"  = (NewCUAndSUObject "15.0.775.38")
                "CU4"  = (NewCUAndSUObject "15.0.847.32")
                "CU5"  = (NewCUAndSUObject "15.0.913.22")
                "CU6"  = (NewCUAndSUObject "15.0.995.29")
                "CU7"  = (NewCUAndSUObject "15.0.1044.25")
                "CU8"  = (NewCUAndSUObject "15.0.1076.9")
                "CU9"  = (NewCUAndSUObject "15.0.1104.5")
                "CU10" = (NewCUAndSUObject "15.0.1130.7")
                "CU11" = (NewCUAndSUObject "15.0.1156.6")
                "CU12" = (NewCUAndSUObject "15.0.1178.4")
                "CU13" = (NewCUAndSUObject "15.0.1210.3")
                "CU14" = (NewCUAndSUObject "15.0.1236.3")
                "CU15" = (NewCUAndSUObject "15.0.1263.5")
                "CU16" = (NewCUAndSUObject "15.0.1293.2")
                "CU17" = (NewCUAndSUObject "15.0.1320.4")
                "CU18" = (NewCUAndSUObject "15.0.1347.2")
                "CU19" = (NewCUAndSUObject "15.0.1365.1")
                "CU20" = (NewCUAndSUObject "15.0.1367.3")
                "CU21" = (NewCUAndSUObject "15.0.1395.4")
                "CU22" = (NewCUAndSUObject "15.0.1473.3")
                "CU23" = (NewCUAndSUObject "15.0.1497.2" @{
                        "Mar21SU" = "15.0.1497.12"
                        "Apr21SU" = "15.0.1497.15"
                        "May21SU" = "15.0.1497.18"
                        "Jul21SU" = "15.0.1497.23"
                        "Oct21SU" = "15.0.1497.24"
                        "Nov21SU" = "15.0.1497.26"
                        "Jan22SU" = "15.0.1497.28"
                        "Mar22SU" = "15.0.1497.33"
                        "May22SU" = "15.0.1497.36"
                        "Aug22SU" = "15.0.1497.40"
                        "Oct22SU" = "15.0.1497.42"
                        "Nov22SU" = "15.0.1497.44"
                        "Jan23SU" = "15.0.1497.45"
                    })
            }
            "Exchange2016" = @{
                "CU1"  = (NewCUAndSUObject "15.1.396.30")
                "CU2"  = (NewCUAndSUObject "15.1.466.34")
                "CU3"  = (NewCUAndSUObject "15.1.544.27")
                "CU4"  = (NewCUAndSUObject "15.1.669.32")
                "CU5"  = (NewCUAndSUObject "15.1.845.34")
                "CU6"  = (NewCUAndSUObject "15.1.1034.26")
                "CU7"  = (NewCUAndSUObject "15.1.1261.35")
                "CU8"  = (NewCUAndSUObject "15.1.1415.2")
                "CU9"  = (NewCUAndSUObject "15.1.1466.3")
                "CU10" = (NewCUAndSUObject "15.1.1531.3")
                "CU11" = (NewCUAndSUObject "15.1.1591.10")
                "CU12" = (NewCUAndSUObject "15.1.1713.5")
                "CU13" = (NewCUAndSUObject "15.1.1779.2")
                "CU14" = (NewCUAndSUObject "15.1.1847.3")
                "CU15" = (NewCUAndSUObject "15.1.1913.5")
                "CU16" = (NewCUAndSUObject "15.1.1979.3")
                "CU17" = (NewCUAndSUObject "15.1.2044.4")
                "CU18" = (NewCUAndSUObject "15.1.2106.2")
                "CU19" = (NewCUAndSUObject "15.1.2176.2")
                "CU20" = (NewCUAndSUObject "15.1.2242.4")
                "CU21" = (NewCUAndSUObject "15.1.2308.8")
                "CU22" = (NewCUAndSUObject "15.1.2375.7" @{
                        "Oct21SU" = "15.1.2375.12"
                        "Nov21SU" = "15.1.2375.17"
                        "Jan22SU" = "15.1.2375.18"
                        "Mar22SU" = "15.1.2375.24"
                        "May22SU" = "15.1.2375.28"
                        "Aug22SU" = "15.1.2375.31"
                        "Oct22SU" = "15.1.2375.32"
                        "Nov22SU" = "15.1.2375.37"
                    })
                "CU23" = (NewCUAndSUObject "15.1.2507.6" @{
                        "May22SU" = "15.1.2507.9"
                        "Aug22SU" = "15.1.2507.12"
                        "Oct22SU" = "15.1.2507.13"
                        "Nov22SU" = "15.1.2507.16"
                        "Jan23SU" = "15.1.2507.17"
                    })
            }
            "Exchange2019" = @{
                "CU1"  = (NewCUAndSUObject "15.2.330.5")
                "CU2"  = (NewCUAndSUObject "15.2.397.3")
                "CU3"  = (NewCUAndSUObject "15.2.464.5")
                "CU4"  = (NewCUAndSUObject "15.2.529.5")
                "CU5"  = (NewCUAndSUObject "15.2.595.3")
                "CU6"  = (NewCUAndSUObject "15.2.659.4")
                "CU7"  = (NewCUAndSUObject "15.2.721.2")
                "CU8"  = (NewCUAndSUObject "15.2.792.3")
                "CU9"  = (NewCUAndSUObject "15.2.858.5")
                "CU10" = (NewCUAndSUObject "15.2.922.7")
                "CU11" = (NewCUAndSUObject "15.2.986.5" @{
                        "Oct21SU" = "15.2.986.9"
                        "Nov21SU" = "15.2.986.14"
                        "Jan22SU" = "15.2.986.15"
                        "Mar22SU" = "15.2.986.22"
                        "May22SU" = "15.2.986.26"
                        "Aug22SU" = "15.2.986.29"
                        "Oct22SU" = "15.2.986.30"
                        "Nov22SU" = "15.2.986.36"
                        "Jan23SU" = "15.2.986.37"
                    })
                "CU12" = (NewCUAndSUObject "15.2.1118.7" @{
                        "May22SU" = "15.2.1118.9"
                        "Aug22SU" = "15.2.1118.12"
                        "Oct22SU" = "15.2.1118.15"
                        "Nov22SU" = "15.2.1118.20"
                        "Jan23SU" = "15.2.1118.21"
                    })
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeMajorVersion = [string]::Empty
        $exchangeVersion = $null
        $supportedBuildNumber = $false
        $latestSUBuild = $false
        $extendedSupportDate = [string]::Empty
        $cuReleaseDate = [string]::Empty
        $friendlyName = [string]::Empty
        $cuLevel = [string]::Empty
        $suName = [string]::Empty
        $orgValue = 0
        $schemaValue = 0
        $mesoValue = 0
        $ex19 = "Exchange2019"
        $ex16 = "Exchange2016"
        $ex13 = "Exchange2013"
    }
    process {
        # Convert both input types to a [System.Version]
        try {
            if ($PSCmdlet.ParameterSetName -eq "VersionCU") {
                [System.Version]$exchangeVersion = GetBuildVersion -ExchangeVersion $Version -CU $CU -SU $SU
            } elseif ($PSCmdlet.ParameterSetName -eq "AdminDisplayVersion") {
                $AdminDisplayVersion = $AdminDisplayVersion.ToString()
                Write-Verbose "Passed AdminDisplayVersion: $AdminDisplayVersion"
                $split1 = $AdminDisplayVersion.Substring(($AdminDisplayVersion.IndexOf(" ")) + 1, 4).Split(".")
                $buildStart = $AdminDisplayVersion.LastIndexOf(" ") + 1
                $split2 = $AdminDisplayVersion.Substring($buildStart, ($AdminDisplayVersion.LastIndexOf(")") - $buildStart)).Split(".")
                [System.Version]$exchangeVersion = "$($split1[0]).$($split1[1]).$($split2[0]).$($split2[1])"
            } else {
                [System.Version]$exchangeVersion = $FileVersion
            }
        } catch {
            Write-Verbose "Failed to convert to system.version"
            Invoke-CatchActionError $CatchActionFunction
        }

        <#
            Exchange Build Numbers: https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
            Exchange 2016 & 2019 AD Changes: https://learn.microsoft.com/en-us/exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-2019
            Exchange 2013 AD Changes: https://learn.microsoft.com/en-us/exchange/prepare-active-directory-and-domains-exchange-2013-help
        #>
        if ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 2) {
            Write-Verbose "Exchange 2019 is detected"
            $exchangeMajorVersion = "Exchange2019"
            $extendedSupportDate = "10/14/2025"
            $friendlyName = "Exchange 2019"

            #Latest Version AD Settings
            $schemaValue = 17003
            $mesoValue = 13243
            $orgValue = 16760

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex19 "CU12") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "04/20/2022"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex19 "CU12" -SU "Jan23SU") { $suName = "Jan23SU"; $latestSUBuild = $true }
                (GetBuildVersion $ex19 "CU12" -SU "Nov22SU") { $suName = "Nov22SU" }
                (GetBuildVersion $ex19 "CU12" -SU "Oct22SU") { $suName = "Oct22SU" }
                (GetBuildVersion $ex19 "CU12" -SU "Aug22SU") { $suName = "Aug22SU" }
                (GetBuildVersion $ex19 "CU12" -SU "May22SU") { $suName = "May22SU" }
                { $_ -lt (GetBuildVersion $ex19 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "09/28/2021"
                    $supportedBuildNumber = $true
                    $mesoValue = 13242
                    $orgValue = 16759
                }
                (GetBuildVersion $ex19 "CU11" -SU "Jan23SU") { $suName = "Jan23SU"; $latestSUBuild = $true }
                (GetBuildVersion $ex19 "CU11" -SU "Nov22SU") { $suName = "Nov22SU" }
                (GetBuildVersion $ex19 "CU11" -SU "Oct22SU") { $suName = "Oct22SU" }
                (GetBuildVersion $ex19 "CU11" -SU "Aug22SU") { $suName = "Aug22SU" }
                (GetBuildVersion $ex19 "CU11" -SU "May22SU") { $suName = "May22SU"; $mesoValue = 13243 }
                (GetBuildVersion $ex19 "CU11" -SU "Mar22SU") { $suName = "Mar22SU" }
                (GetBuildVersion $ex19 "CU11" -SU "Jan22SU") { $suName = "Jan22SU" }
                (GetBuildVersion $ex19 "CU11" -SU "Nov21SU") { $suName = "Nov21SU" }
                (GetBuildVersion $ex19 "CU11" -SU "Oct21SU") { $suName = "Oct21SU" }
                { $_ -lt (GetBuildVersion $ex19 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16758
                    $supportedBuildNumber = $false
                }
                { $_ -lt (GetBuildVersion $ex19 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "03/16/2021"
                    $schemaValue = 17002
                    $mesoValue = 13240
                    $orgValue = 16757
                }
                { $_ -lt (GetBuildVersion $ex19 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "12/15/2020"
                    $mesoValue = 13239
                    $orgValue = 16756
                }
                { $_ -lt (GetBuildVersion $ex19 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "09/15/2020"
                    $schemaValue = 17001
                    $mesoValue = 13238
                    $orgValue = 16755
                }
                { $_ -lt (GetBuildVersion $ex19 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "06/16/2020"
                    $mesoValue = 13237
                    $orgValue = 16754
                }
                { $_ -lt (GetBuildVersion $ex19 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "03/17/2020"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "12/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "09/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "06/18/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "02/12/2019"
                    $schemaValue = 17000
                    $mesoValue = 13236
                    $orgValue = 16752
                }
                { $_ -lt (GetBuildVersion $ex19 "CU1") } {
                    $cuLevel = "RTM"
                    $cuReleaseDate = "10/22/2018"
                    $orgValue = 16751
                }
            }
        } elseif ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 1) {
            Write-Verbose "Exchange 2016 is detected"
            $exchangeMajorVersion = "Exchange2016"
            $extendedSupportDate = "10/14/2025"
            $friendlyName = "Exchange 2016"

            #Latest Version AD Settings
            $schemaValue = 15334
            $mesoValue = 13243
            $orgValue = 16223

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex16 "CU23") } {
                    $cuLevel = "CU23"
                    $cuReleaseDate = "04/20/2022"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex16 "CU23" -SU "Jan23SU") { $suName = "Jan23SU"; $latestSUBuild = $true }
                (GetBuildVersion $ex16 "CU23" -SU "Nov22SU") { $suName = "Nov22SU" }
                (GetBuildVersion $ex16 "CU23" -SU "Oct22SU") { $suName = "Oct22SU" }
                (GetBuildVersion $ex16 "CU23" -SU "Aug22SU") { $suName = "Aug22SU" }
                (GetBuildVersion $ex16 "CU23" -SU "May22SU") { $suName = "May22SU" }
                { $_ -lt (GetBuildVersion $ex16 "CU23") } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "09/28/2021"
                    $supportedBuildNumber = $false
                    $mesoValue = 13242
                    $orgValue = 16222
                }
                (GetBuildVersion $ex16 "CU22" -SU "Nov22SU") { $suName = "Nov22SU" }
                (GetBuildVersion $ex16 "CU22" -SU "Oct22SU") { $suName = "Oct22SU" }
                (GetBuildVersion $ex16 "CU22" -SU "Aug22SU") { $suName = "Aug22SU" }
                (GetBuildVersion $ex16 "CU22" -SU "May22SU") { $suName = "May22SU"; $mesoValue = 13243 }
                (GetBuildVersion $ex16 "CU22" -SU "Mar22SU") { $suName = "Mar22SU" }
                (GetBuildVersion $ex16 "CU22" -SU "Jan22SU") { $suName = "Jan22SU" }
                (GetBuildVersion $ex16 "CU22" -SU "Nov21SU") { $suName = "Nov21SU" }
                (GetBuildVersion $ex16 "CU22" -SU "Oct21SU") { $suName = "Oct21SU" }
                { $_ -lt (GetBuildVersion $ex16 "CU22") } {
                    $cuLevel = "CU21"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16221
                }
                { $_ -lt (GetBuildVersion $ex16 "CU21") } {
                    $cuLevel = "CU20"
                    $cuReleaseDate = "03/16/2021"
                    $schemaValue = 15333
                    $mesoValue = 13240
                    $orgValue = 16220
                }
                { $_ -lt (GetBuildVersion $ex16 "CU20") } {
                    $cuLevel = "CU19"
                    $cuReleaseDate = "12/15/2020"
                    $mesoValue = 13239
                    $orgValue = 16219
                }
                { $_ -lt (GetBuildVersion $ex16 "CU19") } {
                    $cuLevel = "CU18"
                    $cuReleaseDate = "09/15/2020"
                    $schemaValue = 15332
                    $mesoValue = 13238
                    $orgValue = 16218
                }
                { $_ -lt (GetBuildVersion $ex16 "CU18") } {
                    $cuLevel = "CU17"
                    $cuReleaseDate = "06/16/2020"
                    $mesoValue = 13237
                    $orgValue = 16217
                }
                { $_ -lt (GetBuildVersion $ex16 "CU17") } {
                    $cuLevel = "CU16"
                    $cuReleaseDate = "03/17/2020"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU16") } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "12/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU15") } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "09/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU14") } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "06/18/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU13") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "02/12/2019"
                    $mesoValue = 13236
                    $orgValue = 16215
                }
                { $_ -lt (GetBuildVersion $ex16 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "10/16/2018"
                    $orgValue = 16214
                }
                { $_ -lt (GetBuildVersion $ex16 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/19/2018"
                    $orgValue = 16213
                }
                { $_ -lt (GetBuildVersion $ex16 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "03/20/2018"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "12/19/2017"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "09/16/2017"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "06/24/2017"
                    $schemaValue = 15330
                }
                { $_ -lt (GetBuildVersion $ex16 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "03/21/2017"
                    $schemaValue = 15326
                }
                { $_ -lt (GetBuildVersion $ex16 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "12/13/2016"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "09/20/2016"
                    $orgValue = 16212
                }
                { $_ -lt (GetBuildVersion $ex16 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "06/21/2016"
                    $schemaValue = 15325
                }
                { $_ -lt (GetBuildVersion $ex16 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "03/15/2016"
                    $schemaValue = 15323
                    $orgValue = 16211
                }
            }
        } elseif ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 0) {
            Write-Verbose "Exchange 2013 is detected"
            $exchangeMajorVersion = "Exchange2013"
            $extendedSupportDate = "04/11/2023"
            $friendlyName = "Exchange 2013"

            #Latest Version AD Settings
            $schemaValue = 15312
            $mesoValue = 13237
            $orgValue = 16133

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex13 "CU23") } {
                    $cuLevel = "CU23"
                    $cuReleaseDate = "06/18/2019"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex13 "CU23" -SU "Jan23SU") { $suName = "Jan23SU"; $latestSUBuild = $true }
                (GetBuildVersion $ex13 "CU23" -SU "Nov22SU") { $suName = "Nov22SU" }
                (GetBuildVersion $ex13 "CU23" -SU "Oct22SU") { $suName = "Oct22SU" }
                (GetBuildVersion $ex13 "CU23" -SU "Aug22SU") { $suName = "Aug22SU" }
                (GetBuildVersion $ex13 "CU23" -SU "May22SU") { $suName = "May22SU"; $mesoValue = 13238 }
                (GetBuildVersion $ex13 "CU23" -SU "Mar22SU") { $suName = "Mar22SU" }
                (GetBuildVersion $ex13 "CU23" -SU "Jan22SU") { $suName = "Jan22SU" }
                (GetBuildVersion $ex13 "CU23" -SU "Nov21SU") { $suName = "Nov21SU" }
                (GetBuildVersion $ex13 "CU23" -SU "Oct21SU") { $suName = "Oct21SU" }
                (GetBuildVersion $ex13 "CU23" -SU "Jul21SU") { $suName = "Jul21SU" }
                (GetBuildVersion $ex13 "CU23" -SU "May21SU") { $suName = "May21SU" }
                (GetBuildVersion $ex13 "CU23" -SU "Apr21SU") { $suName = "Apr21SU" }
                (GetBuildVersion $ex13 "CU23" -SU "Mar21SU") { $suName = "Mar21SU" }
                { $_ -lt (GetBuildVersion $ex13 "CU23") } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "02/12/2019"
                    $mesoValue = 13236
                    $orgValue = 16131
                    $supportedBuildNumber = $false
                }
                { $_ -lt (GetBuildVersion $ex13 "CU22") } {
                    $cuLevel = "CU21"
                    $cuReleaseDate = "06/19/2018"
                    $orgValue = 16130
                }
                { $_ -lt (GetBuildVersion $ex13 "CU21") } {
                    $cuLevel = "CU20"
                    $cuReleaseDate = "03/20/2018"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU20") } {
                    $cuLevel = "CU19"
                    $cuReleaseDate = "12/19/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU19") } {
                    $cuLevel = "CU18"
                    $cuReleaseDate = "09/16/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU18") } {
                    $cuLevel = "CU17"
                    $cuReleaseDate = "06/24/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU17") } {
                    $cuLevel = "CU16"
                    $cuReleaseDate = "03/21/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU16") } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "12/13/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU15") } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "09/20/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU14") } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "06/21/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU13") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "03/15/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "12/15/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "09/15/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "06/17/2015"
                    $orgValue = 15965
                }
                { $_ -lt (GetBuildVersion $ex13 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "03/17/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "12/09/2014"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "08/26/2014"
                    $schemaValue = 15303
                }
                { $_ -lt (GetBuildVersion $ex13 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "05/27/2014"
                    $schemaValue = 15300
                    $orgValue = 15870
                }
                { $_ -lt (GetBuildVersion $ex13 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "02/25/2014"
                    $schemaValue = 15292
                    $orgValue = 15844
                }
                { $_ -lt (GetBuildVersion $ex13 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "11/25/2013"
                    $schemaValue = 15283
                    $orgValue = 15763
                }
                { $_ -lt (GetBuildVersion $ex13 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "07/09/2013"
                    $schemaValue = 15281
                    $orgValue = 15688
                }
                { $_ -lt (GetBuildVersion $ex13 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "04/02/2013"
                    $schemaValue = 15254
                    $orgValue = 15614
                }
            }
        } else {
            Write-Verbose "Unknown version of Exchange is detected."
        }
    }
    end {
        $friendlyName = "$friendlyName $cuLevel $suName".Trim()
        Write-Verbose "Determined Build Version $friendlyName"
        return [PSCustomObject]@{
            MajorVersion        = $exchangeMajorVersion
            FriendlyName        = $friendlyName
            BuildVersion        = $exchangeVersion
            CU                  = $cuLevel
            ReleaseDate         = if (-not([System.String]::IsNullOrEmpty($cuReleaseDate))) { ([System.Convert]::ToDateTime([DateTime]$cuReleaseDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) } else { $null }
            ExtendedSupportDate = if (-not([System.String]::IsNullOrEmpty($extendedSupportDate))) { ([System.Convert]::ToDateTime([DateTime]$extendedSupportDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) } else { $null }
            Supported           = $supportedBuildNumber
            LatestSU            = $latestSUBuild
            ADLevel             = [PSCustomObject]@{
                SchemaValue = $schemaValue
                MESOValue   = $mesoValue
                OrgValue    = $orgValue
            }
        }
    }
}
