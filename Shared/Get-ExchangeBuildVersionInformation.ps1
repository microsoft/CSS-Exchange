# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1

function Get-ExchangeBuildVersionInformation {
    [CmdletBinding(DefaultParameterSetName = "AdminDisplayVersion")]
    param(
        [Parameter(ParameterSetName = "AdminDisplayVersion", Position = 1)]
        [object]$AdminDisplayVersion,

        [Parameter(ParameterSetName = "ExSetup")]
        [System.Version]$FileVersion,

        [Parameter(Mandatory = $false)]
        [scriptblock]$CatchActionFunction
    )
    begin {
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
    }
    process {
        # Convert both input types to a [System.Version]
        try {
            if ($PSCmdlet.ParameterSetName -eq "AdminDisplayVersion") {
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
                { $_ -ge "15.2.1118.7" } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "04/20/2022"
                    $supportedBuildNumber = $true
                }
                "15.2.1118.20" { $suName = "Nov22SU"; $latestSUBuild = $true }
                "15.2.1118.15" { $suName = "Oct22SU" }
                "15.2.1118.12" { $suName = "Aug22SU" }
                "15.2.1118.9" { $suName = "May22SU" }
                { $_ -lt "15.2.1118.7" } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "09/28/2021"
                    $supportedBuildNumber = $true
                    $mesoValue = 13242
                    $orgValue = 16759
                }
                "15.2.986.36" { $suName = "Nov22SU"; $latestSUBuild = $true }
                "15.2.986.30" { $suName = "Oct22SU" }
                "15.2.986.29" { $suName = "Aug22SU" }
                "15.2.986.26" { $suName = "May22SU"; $mesoValue = 13243 }
                "15.2.986.22" { $suName = "Mar22SU" }
                "15.2.986.15" { $suName = "Jan22SU" }
                "15.2.986.14" { $suName = "Nov21SU" }
                "15.2.986.9" { $suName = "Oct21SU" }
                { $_ -lt "15.2.986.5" } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16758
                    $supportedBuildNumber = $false
                }
                { $_ -lt "15.2.922.7" } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "03/16/2021"
                    $schemaValue = 17002
                    $mesoValue = 13240
                    $orgValue = 16757
                }
                { $_ -lt "15.2.858.5" } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "12/15/2020"
                    $mesoValue = 13239
                    $orgValue = 16756
                }
                { $_ -lt "15.2.792.3" } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "09/15/2020"
                    $schemaValue = 17001
                    $mesoValue = 13238
                    $orgValue = 16755
                }
                { $_ -lt "15.2.721.2" } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "06/16/2020"
                    $mesoValue = 13237
                    $orgValue = 16754
                }
                { $_ -lt "15.2.659.4" } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "03/17/2020"
                }
                { $_ -lt "15.2.595.3" } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "12/17/2019"
                }
                { $_ -lt "15.2.529.5" } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "09/17/2019"
                }
                { $_ -lt "15.2.464.5" } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "06/18/2019"
                }
                { $_ -lt "15.2.397.3" } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "02/12/2019"
                    $schemaValue = 17000
                    $mesoValue = 13236
                    $orgValue = 16752
                }
                { $_ -lt "15.2.330.5" } {
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
                { $_ -ge "15.1.2507.6" } {
                    $cuLevel = "CU23"
                    $cuReleaseDate = "04/20/2022"
                    $supportedBuildNumber = $true
                }
                "15.1.2507.16" { $suName = "Nov22SU"; $latestSUBuild = $true }
                "15.1.2507.13" { $suName = "Oct22SU" }
                "15.1.2507.12" { $suName = "Aug22SU" }
                "15.1.2507.9" { $suName = "May22SU" }
                { $_ -lt "15.1.2507.6" } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "09/28/2021"
                    $supportedBuildNumber = $true
                    $mesoValue = 13242
                    $orgValue = 16222
                }
                "15.1.2375.37" { $suName = "Nov22SU"; $latestSUBuild = $true }
                "15.1.2375.32" { $suName = "Oct22SU" }
                "15.1.2375.31" { $suName = "Aug22SU" }
                "15.1.2375.28" { $suName = "May22SU"; $mesoValue = 13243 }
                "15.1.2375.24" { $suName = "Mar22SU" }
                "15.1.2375.18" { $suName = "Jan22SU" }
                "15.1.2375.17" { $suName = "Nov21SU" }
                "15.1.2375.12" { $suName = "Oct21SU" }
                { $_ -lt "15.1.2375.7" } {
                    $cuLevel = "CU21"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16221
                    $supportedBuildNumber = $false
                }
                { $_ -lt "15.1.2308.8" } {
                    $cuLevel = "CU20"
                    $cuReleaseDate = "03/16/2021"
                    $schemaValue = 15333
                    $mesoValue = 13240
                    $orgValue = 16220
                }
                { $_ -lt "15.1.2242.4" } {
                    $cuLevel = "CU19"
                    $cuReleaseDate = "12/15/2020"
                    $mesoValue = 13239
                    $orgValue = 16219
                }
                { $_ -lt "15.1.2176.2" } {
                    $cuLevel = "CU18"
                    $cuReleaseDate = "09/15/2020"
                    $schemaValue = 15332
                    $mesoValue = 13238
                    $orgValue = 16218
                }
                { $_ -lt "15.1.2106.2" } {
                    $cuLevel = "CU17"
                    $cuReleaseDate = "06/16/2020"
                    $mesoValue = 13237
                    $orgValue = 16217
                }
                { $_ -lt "15.1.2044.4" } {
                    $cuLevel = "CU16"
                    $cuReleaseDate = "03/17/2020"
                }
                { $_ -lt "15.1.1979.3" } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "12/17/2019"
                }
                { $_ -lt "15.1.1913.5" } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "09/17/2019"
                }
                { $_ -lt "15.1.1847.3" } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "06/18/2019"
                }
                { $_ -lt "15.1.1779.2" } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "02/12/2019"
                    $mesoValue = 13236
                    $orgValue = 16215
                }
                { $_ -lt "15.1.1713.5" } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "10/16/2018"
                    $orgValue = 16214
                }
                { $_ -lt "15.1.1591.10" } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/19/2018"
                    $orgValue = 16213
                }
                { $_ -lt "15.1.1531.3" } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "03/20/2018"
                }
                { $_ -lt "15.1.1466.3" } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "12/19/2017"
                }
                { $_ -lt "15.1.1415.2" } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "09/16/2017"
                }
                { $_ -lt "15.1.1261.35" } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "06/24/2017"
                    $schemaValue = 15330
                }
                { $_ -lt "15.1.1034.26" } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "03/21/2017"
                    $schemaValue = 15326
                }
                { $_ -lt "15.1.845.34" } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "12/13/2016"
                }
                { $_ -lt "15.1.669.32" } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "09/20/2016"
                    $orgValue = 16212
                }
                { $_ -lt "15.1.544.27" } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "06/21/2016"
                    $schemaValue = 15325
                }
                { $_ -lt "15.1.466.34" } {
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
                { $_ -ge "15.0.1497.2" } {
                    $cuLevel = "CU23"
                    $cuReleaseDate = "06/18/2019"
                    $supportedBuildNumber = $true
                }
                "15.0.1497.44" { $suName = "Nov22SU"; $latestSUBuild = $true }
                "15.0.1497.42" { $suName = "Oct22SU" }
                "15.0.1497.40" { $suName = "Aug22SU" }
                "15.0.1497.36" { $suName = "May22SU"; $mesoValue = 13238 }
                "15.0.1497.33" { $suName = "Mar22SU" }
                "15.0.1497.28" { $suName = "Jan22SU" }
                "15.0.1497.26" { $suName = "Nov21SU" }
                "15.0.1497.24" { $suName = "Oct21SU" }
                "15.0.1497.23" { $suName = "Jul21SU" }
                "15.0.1497.18" { $suName = "May21SU" }
                "15.0.1497.15" { $suName = "Apr21SU" }
                "15.0.1497.12" { $suName = "Mar21SU" }
                { $_ -lt "15.0.1497.2" } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "02/12/2019"
                    $mesoValue = 13236
                    $orgValue = 16131
                    $supportedBuildNumber = $false
                }
                { $_ -lt "15.0.1473.3" } {
                    $cuLevel = "CU21"
                    $cuReleaseDate = "06/19/2018"
                    $orgValue = 16130
                }
                { $_ -lt "15.0.1395.4" } {
                    $cuLevel = "CU20"
                    $cuReleaseDate = "03/20/2018"
                }
                { $_ -lt "15.0.1367.3" } {
                    $cuLevel = "CU19"
                    $cuReleaseDate = "12/19/2017"
                }
                { $_ -lt "15.0.1365.1" } {
                    $cuLevel = "CU18"
                    $cuReleaseDate = "09/16/2017"
                }
                { $_ -lt "15.0.1347.2" } {
                    $cuLevel = "CU17"
                    $cuReleaseDate = "06/24/2017"
                }
                { $_ -lt "15.0.1320.4" } {
                    $cuLevel = "CU16"
                    $cuReleaseDate = "03/21/2017"
                }
                { $_ -lt "15.0.1293.2" } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "12/13/2016"
                }
                { $_ -lt "15.0.1263.5" } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "09/20/2016"
                }
                { $_ -lt "15.0.1236.3" } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "06/21/2016"
                }
                { $_ -lt "15.0.1210.3" } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "03/15/2016"
                }
                { $_ -lt "15.0.1178.4" } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "12/15/2015"
                }
                { $_ -lt "15.0.1156.6" } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "09/15/2015"
                }
                { $_ -lt "15.0.1130.7" } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "06/17/2015"
                    $orgValue = 15965
                }
                { $_ -lt "15.0.1104.5" } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "03/17/2015"
                }
                { $_ -lt "15.0.1076.9" } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "12/09/2014"
                }
                { $_ -lt "15.0.1044.25" } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "08/26/2014"
                    $schemaValue = 15303
                }
                { $_ -lt "15.0.995.29" } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "05/27/2014"
                    $schemaValue = 15300
                    $orgValue = 15870
                }
                { $_ -lt "15.0.913.22" } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "02/25/2014"
                    $schemaValue = 15292
                    $orgValue = 15844
                }
                { $_ -lt "15.0.847.32" } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "11/25/2013"
                    $schemaValue = 15283
                    $orgValue = 15763
                }
                { $_ -lt "15.0.775.38" } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "07/09/2013"
                    $schemaValue = 15281
                    $orgValue = 15688
                }
                { $_ -lt "15.0.712.24" } {
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
            ReleaseDate         = ([System.Convert]::ToDateTime([DateTime]$cuReleaseDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            ExtendedSupportDate = ([System.Convert]::ToDateTime([DateTime]$extendedSupportDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
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
