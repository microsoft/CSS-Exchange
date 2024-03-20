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
        [ValidateScript( { ValidateVersionParameter $_ } )]
        [string]$Version,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $true)]
        [ValidateScript( { ValidateCUParameter $_ } )]
        [string]$CU,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $false)]
        [ValidateScript( { ValidateSUParameter $_ } )]
        [string]$SU,

        [Parameter(ParameterSetName = "FindSUBuilds", Mandatory = $true)]
        [ValidateScript( { ValidateSUParameter $_ } )]
        [string]$FindBySUName,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    begin {

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

            if ((-not [string]::IsNullOrEmpty($SU)) -and
                $cuResult.SU.ContainsKey($SU)) {
                return $cuResult.SU[$SU]
            } else {
                return $cuResult.CU
            }
        }

        # Dictionary of Exchange Version/CU/SU to build number
        $exchangeBuildDictionary = GetExchangeBuildDictionary

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
            if ($PSCmdlet.ParameterSetName -eq "FindSUBuilds") {
                foreach ($exchangeKey in $exchangeBuildDictionary.Keys) {
                    foreach ($cuKey in $exchangeBuildDictionary[$exchangeKey].Keys) {
                        if ($null -ne $exchangeBuildDictionary[$exchangeKey][$cuKey].SU -and
                            $exchangeBuildDictionary[$exchangeKey][$cuKey].SU.ContainsKey($FindBySUName)) {
                            Get-ExchangeBuildVersionInformation -FileVersion $exchangeBuildDictionary[$exchangeKey][$cuKey].SU[$FindBySUName]
                        }
                    }
                }
                return
            } elseif ($PSCmdlet.ParameterSetName -eq "VersionCU") {
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
            $orgValue = 16762

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex19 "CU14") } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "02/13/2024"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex19 "CU14" -SU "Mar24SU") { $latestSUBuild = $true }
                { $_ -lt (GetBuildVersion $ex19 "CU14") } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "05/03/2023"
                    $supportedBuildNumber = $true
                    $orgValue = 16761
                }
                (GetBuildVersion $ex19 "CU13" -SU "Mar24SU") { $latestSUBuild = $true }
                { $_ -lt (GetBuildVersion $ex19 "CU13") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "04/20/2022"
                    $supportedBuildNumber = $false
                    $orgValue = 16760
                }
                { $_ -lt (GetBuildVersion $ex19 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "09/28/2021"
                    $mesoValue = 13242
                    $orgValue = 16759
                }
                (GetBuildVersion $ex19 "CU11" -SU "May22SU") { $mesoValue = 13243 }
                { $_ -lt (GetBuildVersion $ex19 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16758
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
                (GetBuildVersion $ex16 "CU23" -SU "Mar24SU") { $latestSUBuild = $true }
                { $_ -lt (GetBuildVersion $ex16 "CU23") } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "09/28/2021"
                    $supportedBuildNumber = $false
                    $mesoValue = 13242
                    $orgValue = 16222
                }
                (GetBuildVersion $ex16 "CU22" -SU "May22SU") { $mesoValue = 13243 }
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
                (GetBuildVersion $ex13 "CU23" -SU "May22SU") { $mesoValue = 13238 }
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

        # Now get the SU Name
        if ([string]::IsNullOrEmpty($exchangeMajorVersion) -or
            [string]::IsNullOrEmpty($cuLevel)) {
            Write-Verbose "Can't lookup when keys aren't set"
            return
        }

        $currentSUInfo = $exchangeBuildDictionary[$exchangeMajorVersion][$cuLevel].SU
        $compareValue = $exchangeVersion.ToString()
        if ($null -ne $currentSUInfo -and
            $currentSUInfo.ContainsValue($compareValue)) {
            foreach ($key in $currentSUInfo.Keys) {
                if ($compareValue -eq $currentSUInfo[$key]) {
                    $suName = $key
                }
            }
        }
    }
    end {

        if ($PSCmdlet.ParameterSetName -eq "FindSUBuilds") {
            Write-Verbose "Return nothing here, results were already returned on the pipeline"
            return
        }

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

function GetExchangeBuildDictionary {

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

    @{
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
            "CU18" = (NewCUAndSUObject "15.0.1347.2" @{
                    "Mar18SU" = "15.0.1347.5"
                })
            "CU19" = (NewCUAndSUObject "15.0.1365.1" @{
                    "Mar18SU" = "15.0.1365.3"
                    "May18SU" = "15.0.1365.7"
                })
            "CU20" = (NewCUAndSUObject "15.0.1367.3" @{
                    "May18SU" = "15.0.1367.6"
                    "Aug18SU" = "15.0.1367.9"
                })
            "CU21" = (NewCUAndSUObject "15.0.1395.4" @{
                    "Aug18SU" = "15.0.1395.7"
                    "Oct18SU" = "15.0.1395.8"
                    "Jan19SU" = "15.0.1395.10"
                    "Mar21SU" = "15.0.1395.12"
                })
            "CU22" = (NewCUAndSUObject "15.0.1473.3" @{
                    "Feb19SU" = "15.0.1473.3"
                    "Apr19SU" = "15.0.1473.4"
                    "Jun19SU" = "15.0.1473.5"
                    "Mar21SU" = "15.0.1473.6"
                })
            "CU23" = (NewCUAndSUObject "15.0.1497.2" @{
                    "Jul19SU" = "15.0.1497.3"
                    "Nov19SU" = "15.0.1497.4"
                    "Feb20SU" = "15.0.1497.6"
                    "Oct20SU" = "15.0.1497.7"
                    "Nov20SU" = "15.0.1497.8"
                    "Dec20SU" = "15.0.1497.10"
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
                    "Feb23SU" = "15.0.1497.47"
                    "Mar23SU" = "15.0.1497.48"
                })
        }
        "Exchange2016" = @{
            "CU1"  = (NewCUAndSUObject "15.1.396.30")
            "CU2"  = (NewCUAndSUObject "15.1.466.34")
            "CU3"  = (NewCUAndSUObject "15.1.544.27")
            "CU4"  = (NewCUAndSUObject "15.1.669.32")
            "CU5"  = (NewCUAndSUObject "15.1.845.34")
            "CU6"  = (NewCUAndSUObject "15.1.1034.26")
            "CU7"  = (NewCUAndSUObject "15.1.1261.35" @{
                    "Mar18SU" = "15.1.1261.39"
                })
            "CU8"  = (NewCUAndSUObject "15.1.1415.2" @{
                    "Mar18SU" = "15.1.1415.4"
                    "May18SU" = "15.1.1415.7"
                    "Mar21SU" = "15.1.1415.8"
                })
            "CU9"  = (NewCUAndSUObject "15.1.1466.3" @{
                    "May18SU" = "15.1.1466.8"
                    "Aug18SU" = "15.1.1466.9"
                    "Mar21SU" = "15.1.1466.13"
                })
            "CU10" = (NewCUAndSUObject "15.1.1531.3" @{
                    "Aug18SU" = "15.1.1531.6"
                    "Oct18SU" = "15.1.1531.8"
                    "Jan19SU" = "15.1.1531.10"
                    "Mar21SU" = "15.1.1531.12"
                })
            "CU11" = (NewCUAndSUObject "15.1.1591.10" @{
                    "Dec18SU" = "15.1.1591.11"
                    "Jan19SU" = "15.1.1591.13"
                    "Apr19SU" = "15.1.1591.16"
                    "Jun19SU" = "15.1.1591.17"
                    "Mar21SU" = "15.1.1591.18"
                })
            "CU12" = (NewCUAndSUObject "15.1.1713.5" @{
                    "Feb19SU" = "15.1.1713.5"
                    "Apr19SU" = "15.1.1713.6"
                    "Jun19SU" = "15.1.1713.7"
                    "Jul19SU" = "15.1.1713.8"
                    "Sep19SU" = "15.1.1713.9"
                    "Mar21SU" = "15.1.1713.10"
                })
            "CU13" = (NewCUAndSUObject "15.1.1779.2" @{
                    "Jul19SU" = "15.1.1779.4"
                    "Sep19SU" = "15.1.1779.5"
                    "Nov19SU" = "15.1.1779.7"
                    "Mar21SU" = "15.1.1779.8"
                })
            "CU14" = (NewCUAndSUObject "15.1.1847.3" @{
                    "Nov19SU" = "15.1.1847.5"
                    "Feb20SU" = "15.1.1847.7"
                    "Mar20SU" = "15.1.1847.10"
                    "Mar21SU" = "15.1.1847.12"
                })
            "CU15" = (NewCUAndSUObject "15.1.1913.5" @{
                    "Feb20SU" = "15.1.1913.7"
                    "Mar20SU" = "15.1.1913.10"
                    "Mar21SU" = "15.1.1913.12"
                })
            "CU16" = (NewCUAndSUObject "15.1.1979.3" @{
                    "Sep20SU" = "15.1.1979.6"
                    "Mar21SU" = "15.1.1979.8"
                })
            "CU17" = (NewCUAndSUObject "15.1.2044.4" @{
                    "Sep20SU" = "15.1.2044.6"
                    "Oct20SU" = "15.1.2044.7"
                    "Nov20SU" = "15.1.2044.8"
                    "Dec20SU" = "15.1.2044.12"
                    "Mar21SU" = "15.1.2044.13"
                })
            "CU18" = (NewCUAndSUObject "15.1.2106.2" @{
                    "Oct20SU" = "15.1.2106.3"
                    "Nov20SU" = "15.1.2106.4"
                    "Dec20SU" = "15.1.2106.6"
                    "Feb21SU" = "15.1.2106.8"
                    "Mar21SU" = "15.1.2106.13"
                })
            "CU19" = (NewCUAndSUObject "15.1.2176.2" @{
                    "Feb21SU" = "15.1.2176.4"
                    "Mar21SU" = "15.1.2176.9"
                    "Apr21SU" = "15.1.2176.12"
                    "May21SU" = "15.1.2176.14"
                })
            "CU20" = (NewCUAndSUObject "15.1.2242.4" @{
                    "Apr21SU" = "15.1.2242.8"
                    "May21SU" = "15.1.2242.10"
                    "Jul21SU" = "15.1.2242.12"
                })
            "CU21" = (NewCUAndSUObject "15.1.2308.8" @{
                    "Jul21SU" = "15.1.2308.14"
                    "Oct21SU" = "15.1.2308.15"
                    "Nov21SU" = "15.1.2308.20"
                    "Jan22SU" = "15.1.2308.21"
                    "Mar22SU" = "15.1.2308.27"
                })
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
                    "May22SU"   = "15.1.2507.9"
                    "Aug22SU"   = "15.1.2507.12"
                    "Oct22SU"   = "15.1.2507.13"
                    "Nov22SU"   = "15.1.2507.16"
                    "Jan23SU"   = "15.1.2507.17"
                    "Feb23SU"   = "15.1.2507.21"
                    "Mar23SU"   = "15.1.2507.23"
                    "Jun23SU"   = "15.1.2507.27"
                    "Aug23SU"   = "15.1.2507.31"
                    "Aug23SUv2" = "15.1.2507.32"
                    "Oct23SU"   = "15.1.2507.34"
                    "Nov23SU"   = "15.1.2507.35"
                    "Mar24SU"   = "15.1.2507.37"
                })
        }
        "Exchange2019" = @{
            "CU1"  = (NewCUAndSUObject "15.2.330.5" @{
                    "Feb19SU" = "15.2.330.5"
                    "Apr19SU" = "15.2.330.7"
                    "Jun19SU" = "15.2.330.8"
                    "Jul19SU" = "15.2.330.9"
                    "Sep19SU" = "15.2.330.10"
                    "Mar21SU" = "15.2.330.11"
                })
            "CU2"  = (NewCUAndSUObject "15.2.397.3" @{
                    "Jul19SU" = "15.2.397.5"
                    "Sep19SU" = "15.2.397.6"
                    "Nov19SU" = "15.2.397.9"
                    "Mar21SU" = "15.2.397.11"
                })
            "CU3"  = (NewCUAndSUObject "15.2.464.5" @{
                    "Nov19SU" = "15.2.464.7"
                    "Feb20SU" = "15.2.464.11"
                    "Mar20SU" = "15.2.464.14"
                    "Mar21SU" = "15.2.464.15"
                })
            "CU4"  = (NewCUAndSUObject "15.2.529.5" @{
                    "Feb20SU" = "15.2.529.8"
                    "Mar20SU" = "15.2.529.11"
                    "Mar21SU" = "15.2.529.13"
                })
            "CU5"  = (NewCUAndSUObject "15.2.595.3" @{
                    "Sep20SU" = "15.2.595.6"
                    "Mar21SU" = "15.2.595.8"
                })
            "CU6"  = (NewCUAndSUObject "15.2.659.4" @{
                    "Sep20SU" = "15.2.659.6"
                    "Oct20SU" = "15.2.659.7"
                    "Nov20SU" = "15.2.659.8"
                    "Dec20SU" = "15.2.659.11"
                    "Mar21SU" = "15.2.659.12"
                })
            "CU7"  = (NewCUAndSUObject "15.2.721.2" @{
                    "Oct20SU" = "15.2.721.3"
                    "Nov20SU" = "15.2.721.4"
                    "Dec20SU" = "15.2.721.6"
                    "Feb21SU" = "15.2.721.8"
                    "Mar21SU" = "15.2.721.13"
                })
            "CU8"  = (NewCUAndSUObject "15.2.792.3" @{
                    "Feb21SU" = "15.2.792.5"
                    "Mar21SU" = "15.2.792.10"
                    "Apr21SU" = "15.2.792.13"
                    "May21SU" = "15.2.792.15"
                })
            "CU9"  = (NewCUAndSUObject "15.2.858.5" @{
                    "Apr21SU" = "15.2.858.10"
                    "May21SU" = "15.2.858.12"
                    "Jul21SU" = "15.2.858.15"
                })
            "CU10" = (NewCUAndSUObject "15.2.922.7" @{
                    "Jul21SU" = "15.2.922.13"
                    "Oct21SU" = "15.2.922.14"
                    "Nov21SU" = "15.2.922.19"
                    "Jan22SU" = "15.2.922.20"
                    "Mar22SU" = "15.2.922.27"
                })
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
                    "Feb23SU" = "15.2.986.41"
                    "Mar23SU" = "15.2.986.42"
                })
            "CU12" = (NewCUAndSUObject "15.2.1118.7" @{
                    "May22SU"   = "15.2.1118.9"
                    "Aug22SU"   = "15.2.1118.12"
                    "Oct22SU"   = "15.2.1118.15"
                    "Nov22SU"   = "15.2.1118.20"
                    "Jan23SU"   = "15.2.1118.21"
                    "Feb23SU"   = "15.2.1118.25"
                    "Mar23SU"   = "15.2.1118.26"
                    "Jun23SU"   = "15.2.1118.30"
                    "Aug23SU"   = "15.2.1118.36"
                    "Aug23SUv2" = "15.2.1118.37"
                    "Oct23SU"   = "15.2.1118.39"
                    "Nov23SU"   = "15.2.1118.40"
                })
            "CU13" = (NewCUAndSUObject "15.2.1258.12" @{
                    "Jun23SU"   = "15.2.1258.16"
                    "Aug23SU"   = "15.2.1258.23"
                    "Aug23SUv2" = "15.2.1258.25"
                    "Oct23SU"   = "15.2.1258.27"
                    "Nov23SU"   = "15.2.1258.28"
                    "Mar24SU"   = "15.2.1258.32"
                })
            "CU14" = (NewCUAndSUObject "15.2.1544.4" @{
                    "Mar24SU" = "15.2.1544.9"
                })
        }
    }
}

# Must be outside function to use it as a validate script
function GetValidatePossibleParameters {
    $exchangeBuildDictionary = GetExchangeBuildDictionary
    $suNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $cuNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $versionNames = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($exchangeKey in $exchangeBuildDictionary.Keys) {
        [void]$versionNames.Add($exchangeKey)
        foreach ($cuKey in $exchangeBuildDictionary[$exchangeKey].Keys) {
            [void]$cuNames.Add($cuKey)
            if ($null -eq $exchangeBuildDictionary[$exchangeKey][$cuKey].SU) { continue }
            foreach ($suKey in $exchangeBuildDictionary[$exchangeKey][$cuKey].SU.Keys) {
                [void]$suNames.Add($suKey)
            }
        }
    }
    return [PSCustomObject]@{
        Version = $versionNames
        CU      = $cuNames
        SU      = $suNames
    }
}

function ValidateSUParameter {
    param($name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.SU.Contains($Name)
}

function ValidateCUParameter {
    param($Name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.CU.Contains($Name)
}

function ValidateVersionParameter {
    param($Name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.Version.Contains($Name)
}
