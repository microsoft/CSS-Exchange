# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Get-ExchangeBuildVersionInformation.ps1

    function Invoke-ProcessSUProcess {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$ResultsKeyName,
            [bool]$ProcessLatestCUOnly = $false,
            [bool]$ExchangeVersionSupported = $true
        )
        $exchangeLatestCUs = $Script:results[$ResultsKeyName]

        # Most Current CU
        $latestCU = Get-ExchangeBuildVersionInformation -FileVersion $exchangeLatestCUs[0]
        $noSUsYet = $null -eq (GetExchangeBuildDictionary)[$ResultsKeyName][$latestCU.CU].SU
        $trueSUReleaseForLatestCU = $false

        $latestCU.Supported | Should -Be $true

        if ($noSUsYet) {
            $latestCU.LatestSU | Should -Be $ExchangeVersionSupported
        } else {

            $allSUsOnLatestCU = (GetExchangeBuildDictionary)[$ResultsKeyName][$latestCU.CU].SU.Values |
                ForEach-Object { [System.Version]$_ } |
                Sort-Object -Descending

            foreach ($su in $allSUsOnLatestCU) {
                $test = Get-ExchangeBuildVersionInformation -FileVersion $su
                $isSU = $null -ne ($test.FriendlyName | Select-String "\D{3}\d{2}SU")

                if ($isSU) { $trueSUReleaseForLatestCU = $true; break }
            }

            $latestSU = Get-ExchangeBuildVersionInformation -FileVersion $allSUsOnLatestCU[0]
            $notSecondVersionSU = $null -eq ($latestSU.FriendlyName | Select-String "\D{3}\d{2}SUv\d")

            # On the latest CU, it shouldn't be secure if we have released an SU
            $latestCU.LatestSU | Should -Be (-not $trueSUReleaseForLatestCU)

            # Latest SU release should always be secure and supported
            $latestSU.Supported | Should -Be $true
            $latestSU.LatestSU | Should -Be $ExchangeVersionSupported

            # Walk through the SUs, make sure that they are set correctly.
            # Latest Release should be always secure, the previous one just depends on the more recent release.
            <#
            May25HU - Secure
            Apr25HU - Secure
            Mar25SU - Secure
            vs
            Aug25SU - Secure
            May25HU - not secure going down
            Apr25HU
            Mar25SU
        #>
            $processedSUAlready = $false

            foreach ($su in $allSUsOnLatestCU) {
                $currentSUTest = Get-ExchangeBuildVersionInformation -FileVersion $su
                $currentSUTest.Supported | Should -Be $true # Still supported, just might not be secure.

                if (-not $processedSUAlready) {
                    $currentSUTest.LatestSU | Should -Be $ExchangeVersionSupported

                    if ($notSecondVersionSU) {
                        # Once we hit a SU, processedSUAlready will be set to true, causing all remaining SUs to test false for LatestSU
                        $processedSUAlready = $null -ne ($currentSUTest.FriendlyName | Select-String "\D{3}\d{2}SU")
                    }
                } else {
                    $currentSUTest.LatestSU | Should -Be $false
                }
            }
        }

        if ($ProcessLatestCUOnly -or
            $exchangeLatestCUs.Count -eq 1) { return }

        $supportedCU = Get-ExchangeBuildVersionInformation -FileVersion $exchangeLatestCUs[1]

        if ($exchangeLatestCUs.Count -ge 3) {
            $unSupportedCU = Get-ExchangeBuildVersionInformation -FileVersion $exchangeLatestCUs[2]
        }

        # N-1 CU Testing. We still support this CU, and should be releasing security releases for it.
        $latestSupportedSUs = (GetExchangeBuildDictionary)[$ResultsKeyName][$supportedCU.CU].SU.Values |
            ForEach-Object { [System.Version]$_ } |
            Sort-Object -Descending
        $processedSUAlready = $false

        foreach ($su in $latestSupportedSUs) {
            $currentSUTest = Get-ExchangeBuildVersionInformation -FileVersion $su
            $currentSUTest.Supported | Should -Be $true # Still supported, just might not be secure.

            if (-not $processedSUAlready) {
                $currentSUTest.LatestSU | Should -Be $ExchangeVersionSupported

                if ($notSecondVersionSU) {
                    # Once we hit a SU, processedSUAlready will be set to true, causing all remaining SUs to test false for LatestSU
                    $processedSUAlready = $null -ne ($currentSUTest.FriendlyName | Select-String "\D{3}\d{2}SU")
                }
            } else {
                $currentSUTest.LatestSU | Should -Be $false
            }
        }

        if ($null -ne $unSupportedCU) {
            # Testing out N - 3 for Exchange 2019. This is to test out to make sure we state for this CU that it is not supported and may or may not be secure.
            # In order for this CU to not be secure, 1 SU has to be released for the current CU.
            $latestUnsupportedSUs = (GetExchangeBuildDictionary)[$ResultsKeyName][$unSupportedCU.CU].SU.Values |
                ForEach-Object { [System.Version]$_ } |
                Sort-Object -Descending |
                Select-Object -First 2

            $latestSUOnUnsupportedCU = Get-ExchangeBuildVersionInformation -FileVersion $latestUnsupportedSUs[0]
            $latestSUOnUnsupportedCU.Supported | Should -Be $false
            $latestSUOnUnsupportedCU.LatestSU | Should -Be (-not $trueSUReleaseForLatestCU)

            if ($latestUnsupportedSUs.Count -eq 2) {
                $unsupportedSU = Get-ExchangeBuildVersionInformation -FileVersion $latestUnsupportedSUs[1]
                $unsupportedSU.Supported | Should -Be $false
                $unsupportedSU.LatestSU | Should -Be $false
            }
        }
    }
}

Describe "Testing Get-ExchangeBuildVersionInformation.ps1" {

    Context "Parse AdminDisplayVersion CU Build ServerVersion Object" {
        BeforeAll {
            [object]$e19CU11ServerVersion = Import-Clixml $Script:parentPath\Tests\E19CU11AdminDisplayVersion.xml
            $Script:results = Get-ExchangeBuildVersionInformation -AdminDisplayVersion $e19CU11ServerVersion
        }

        It "Return the final E19CU11 version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.FriendlyName | Should -Be  "Exchange 2019 CU11"
            $results.BuildVersion.ToString() | Should -Be "15.2.986.5"
            $results.CU | Should -Be "CU11"
            $results.ReleaseDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"9/28/2021", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.ExtendedSupportDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"10/14/2025", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.Supported | Should -Be $false
            $results.LatestSU | Should -Be $false
            $results.ADLevel.SchemaValue | Should -Be 17003
            $results.ADLevel.MESOValue | Should -Be 13242
            $results.ADLevel.OrgValue | Should -Be 16759
        }
    }

    Context "Parse AdminDisplayVersion CU Build String Object" {
        BeforeAll {
            [string]$e19CU11 = "Version 15.2 (Build 986.5)"
            $Script:results = Get-ExchangeBuildVersionInformation -AdminDisplayVersion $e19CU11
        }

        It "Return the final E19CU11 version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.FriendlyName | Should -Be  "Exchange 2019 CU11"
            $results.BuildVersion.ToString() | Should -Be "15.2.986.5"
            $results.CU | Should -Be "CU11"
            $results.ReleaseDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"9/28/2021", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.ExtendedSupportDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"10/14/2025", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.Supported | Should -Be $false
            $results.LatestSU | Should -Be $false
            $results.ADLevel.SchemaValue | Should -Be 17003
            $results.ADLevel.MESOValue | Should -Be 13242
            $results.ADLevel.OrgValue | Should -Be 16759
        }
    }

    Context "Parse FileVersion String Object" {
        BeforeAll {
            [string]$fileVersion = "15.2.1118.15"
            $Script:results = Get-ExchangeBuildVersionInformation -FileVersion $fileVersion
        }

        It "Return the final E19CU12 Oct22SU version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.FriendlyName | Should -Be "Exchange 2019 CU12 Oct22SU"
            $results.BuildVersion.ToString() | Should -Be "15.2.1118.15"
            $results.CU | Should -Be "CU12"
            $results.ReleaseDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"04/20/2022", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.ExtendedSupportDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"10/14/2025", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.Supported | Should -Be $false
            $results.LatestSU | Should -Be $false
            $results.ADLevel.SchemaValue | Should -Be 17003
            $results.ADLevel.MESOValue | Should -Be 13243
            $results.ADLevel.OrgValue | Should -Be 16760
        }
    }

    Context "Testing Unsupported CU Exchange 2019 CU 10 Jul21SU" {
        BeforeAll {
            [string]$fileVersion = "15.02.0922.013"
            $Script:results = Get-ExchangeBuildVersionInformation -FileVersion $fileVersion
        }

        It "Return the final E19CU10 Jul21SU version object" {
            $results.MajorVersion | Should -Be "Exchange2019"
            $results.FriendlyName | Should -Be "Exchange 2019 CU10 Jul21SU"
            $results.BuildVersion.ToString() | Should -Be "15.2.922.13"
            $results.CU | Should -Be "CU10"
            $results.ReleaseDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"06/29/2021", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.ExtendedSupportDate | Should -Be ([System.Convert]::ToDateTime([DateTime]"10/14/2025", [System.Globalization.DateTimeFormatInfo]::InvariantInfo))
            $results.Supported | Should -Be $false
            $results.LatestSU | Should -Be $false
            $results.ADLevel.SchemaValue | Should -Be 17003
            $results.ADLevel.MESOValue | Should -Be 13241
            $results.ADLevel.OrgValue | Should -Be 16758
        }
    }

    Context "Testing Exchange CU Build Lookups" {
        It "Exchange 2013 CU23" {
            $results = Get-ExchangeBuildVersionInformation -Version "Exchange2013" -CU "CU23"
            $results.BuildVersion.ToString() | Should -Be "15.0.1497.2"
            $results.FriendlyName | Should -Be "Exchange 2013 CU23"
        }

        It "Exchange 2013 CU23 Jan23SU" {
            $results = Get-ExchangeBuildVersionInformation -Version "Exchange2013" -CU "CU23" -SU "Jan23SU"
            $results.BuildVersion.ToString() | Should -Be "15.0.1497.45"
            $results.FriendlyName | Should -Be "Exchange 2013 CU23 Jan23SU"
        }

        It "Exchange 2016 CU22" {
            $results = Get-ExchangeBuildVersionInformation -Version "Exchange2016" -CU "CU22"
            $results.BuildVersion.ToString() | Should -Be "15.1.2375.7"
            $results.FriendlyName | Should -Be "Exchange 2016 CU22"
        }

        It "Exchange 2016 CU22 Jan23SU - Should Be CU22 Base" {
            $results = Get-ExchangeBuildVersionInformation -Version "Exchange2016" -CU "CU22" -SU "Jan23SU"
            $results.BuildVersion.ToString() | Should -Be "15.1.2375.7"
            $results.FriendlyName | Should -Be "Exchange 2016 CU22"
        }

        It "Exchange 2019 CU12" {
            $results = Get-ExchangeBuildVersionInformation -Version "Exchange2019" -CU "CU12"
            $results.BuildVersion.ToString() | Should -Be "15.2.1118.7"
            $results.FriendlyName | Should -Be "Exchange 2019 CU12"
        }

        It "Exchange 2019 CU23 - Should be NULL" {
            $results = Get-ExchangeBuildVersionInformation -Version "Exchange2019" -CU "CU23"
            $results.BuildVersion | Should -Be $null
        }
    }

    Context "Testing FindBySUName" {
        It "Nov22SU" {
            $results = Get-ExchangeBuildVersionInformation -FindBySUName "Nov22SU"
            $results.Count | Should -Be 5
        }
    }

    # This is to make sure the latest SU do include the flag for latest SU.
    Context "Latest SU Results" {
        BeforeAll {
            $Script:results = @{
                "ExchangeSE"   = (GetExchangeBuildDictionary)["ExchangeSE"].Values.CU |
                    ForEach-Object { [System.Version]$_ } |
                    Sort-Object -Descending |
                    Select-Object -First 3
                "Exchange2019" = (GetExchangeBuildDictionary)["Exchange2019"].Values.CU |
                    ForEach-Object { [System.Version]$_ } |
                    Sort-Object -Descending |
                    Select-Object -First 3
                "Exchange2016" = (GetExchangeBuildDictionary)["Exchange2016"].Values.CU |
                    ForEach-Object { [System.Version]$_ } |
                    Sort-Object -Descending |
                    Select-Object -First 2
            }
        }
        It "Exchange SE SU testing" {
            Invoke-ProcessSUProcess -ResultsKeyName "ExchangeSE"
        }
        It "Exchange 2019 SU testing" {
            Invoke-ProcessSUProcess -ResultsKeyName "Exchange2019" -ExchangeVersionSupported $true #This gets set to false once ESU is no longer a thing
        }
        It "Exchange 2016 Latest SU" {
            Invoke-ProcessSUProcess -ResultsKeyName "Exchange2016" -ProcessLatestCUOnly $true -ExchangeVersionSupported $true #This gets set to false once ESU is no longer a thing
        }
    }
}
