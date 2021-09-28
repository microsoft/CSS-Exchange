# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\UserContext\Test-UserGroupMemberOf.ps1
Function Test-ExchangeADSetupLevel {

    # Extract for Pester Testing - Start
    Function TestPrepareAD {
        param(
            [string]$ExchangeVersion
        )
        $netDom = netdom query fsmo
        $params = @{
            TestName = "Prepare AD Requirements"
            Result   = "Failed"
        }

        if ($null -eq $netDom) {
            New-TestResult @params -Details "Failed to query FSMO Role"
            return
        }

        $schemaMaster = ($netDom | Select-String "Schema master (.+)").Matches.Groups[1].Value.Trim()
        $smSite = nltest /server:$schemaMaster /dsgetsite

        if ($smSite[-1] -eq "The command completed successfully") {
            $smSite = $smSite[0]
        } else {
            $smSite = "Failed to get correct site"
        }

        $localSite = nltest /dsgetsite

        if ($localSite[-1] -eq "The command completed successfully") {
            $localSite = $localSite[0]
        } else {
            $localSite = "Failed to get correct site"
        }

        $serverFQDN = ([System.Net.Dns]::GetHostByName(($env:computerName))).HostName
        $serverDomain = $serverFQDN.Substring($serverFQDN.IndexOf(".") + 1)
        $smDomain = $schemaMaster.Substring($schemaMaster.IndexOf(".") + 1)

        if ($serverDomain -eq $smDomain -and
            $localSite -eq $smSite) {
            $runPrepareAD = "Run /PrepareAD from this computer"
        } else {
            $runPrepareAD = "/PrepareAD needs to be run from a computer in domain '$smDomain' and site '$smSite'"
        }

        $details = @(
            "Schema Master:        $schemaMaster",
            "Schema Master Domain: $smDomain",
            "Schema Master Site:   $smSite",
            "---------------------------------------",
            "Local Server:         $serverFQDN",
            "Local Server Domain:  $serverDomain",
            "Local Server Site:    $localSite")

        New-TestResult @params -Details $details -ReferenceInfo $runPrepareAD
        Test-UserGroupMemberOf -PrepareAdRequired $true -PrepareSchemaRequired ($latestExchangeVersion.$ExchangeVersion.UpperRange -ne $currentSchemaValue)
    }

    Function TestMismatchLevel {
        param(
            [string]$ExchangeVersion,
            [object]$ADSetupLevel
        )
        $params = @{
            TestName      = $testName
            Result        = "Failed"
            ReferenceInfo = "Mismatch detected `n    More Info: https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-$ExchangeVersion"
        }
        New-TestResult @params -Details ("DN Value: $($ADSetupLevel.Org.DN) Version: $($ADSetupLevel.Org.Value)`n`n" +
            "DN Value: $($ADSetupLevel.Schema.DN) Version: $($ADSetupLevel.Schema.Value)`n`n" +
            "DN Value: $($ADSetupLevel.MESO.DN) Version: $($ADSetupLevel.MESO.Value)")
        TestPrepareAD -ExchangeVersion $ExchangeVersion
    }

    Function TestReadyLevel {
        param(
            [string]$ExchangeVersion,
            [string]$CULevel
        )

        if ($latestExchangeVersion.$ExchangeVersion.CU -eq $CULevel) { $result = "Passed" } else { $result = "Failed" }

        $params = @{
            TestName      = $testName
            Result        = $result
            Details       = "At Exchange $ExchangeVersion $CULevel"
            ReferenceInfo = "Latest Version is Exchange $ExchangeVersion $($latestExchangeVersion.$ExchangeVersion.CU). More Info: https://aka.ms/SA-ExchangeLatest"
        }

        New-TestResult @params
        if ($result -eq "Failed") {
            TestPrepareAD -ExchangeVersion $ExchangeVersion
        } else {
            Test-UserGroupMemberOf -PrepareAdRequired $false
        }
    }

    Function GetVersionObject {
        param(
            [object]$SearchResults,
            [string]$VersionValueName = "ObjectVersion"
        )
        return [PSCustomObject]@{
            DN    = $SearchResults.Properties["DistinguishedName"]
            Value = ($SearchResults.Properties[$VersionValueName]).ToInt32([System.Globalization.NumberFormatInfo]::InvariantInfo)
        }
    }

    Function GetExchangeADSetupLevel {
        $rootDSE = [ADSI]("LDAP://RootDSE")
        $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher
        $directorySearcher.SearchScope = "Subtree"
        $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.configurationNamingContext.ToString())
        $directorySearcher.Filter = "(objectCategory=msExchOrganizationContainer)"
        $orgFindAll = $directorySearcher.FindAll()

        $directorySearcher.SearchRoot = [ADSI]("LDAP://CN=Schema," + $rootDSE.configurationNamingContext.ToString())
        $directorySearcher.Filter = "(&(name=ms-Exch-Schema-Version-Pt)(objectCategory=attributeSchema))"
        $schemaFindAll = $directorySearcher.FindAll()

        $directorySearcher.SearchScope = "OneLevel"
        $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.rootDomainNamingContext.ToString())
        $directorySearcher.Filter = "(objectCategory=msExchSystemObjectsContainer)"
        $mesoFindAll = $directorySearcher.FindAll()

        return [PSCustomObject]@{
            Org    = (GetVersionObject -SearchResults $orgFindAll)
            Schema = (GetVersionObject -SearchResults $schemaFindAll -VersionValueName "RangeUpper")
            MESO   = (GetVersionObject -SearchResults $mesoFindAll)
        }
    }
    # Extract for Pester Testing - End

    #https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-2019
    #https://docs.microsoft.com/en-us/exchange/prepare-active-directory-and-domains-exchange-2013-help
    $latestExchangeVersion = [PSCustomObject]@{
        2013 = [PSCustomObject]@{
            CU         = "CU23"
            UpperRange = 15312
        }
        2016 = [PSCustomObject]@{
            CU         = "CU22"
            UpperRange = 15334
        }
        2019 = [PSCustomObject]@{
            CU         = "CU11"
            UpperRange = 17003
        }
    }

    $adLevel = GetExchangeADSetupLevel
    $testName = "Exchange AD Latest Level"
    $currentSchemaValue = $adLevel.Schema.Value

    #Less than the known Exchange 2013 schema version
    if ($adLevel.Schema.Value -lt 15137) {
        New-TestResult -TestName $testName -Result "Failed" -Details "Unknown Exchange Schema Version"
        return
    }

    #Exchange 2013 CU23 Only
    if ($adLevel.Schema.Value -eq 15312) {
        if ($adLevel.MESO.Value -eq 13237 -and
            $adLevel.Org.Value -eq 16133) {
            New-TestResult -TestName $testName -Result "Passed" -Details "Exchange 2013 CU23 Ready"
        } else {
            New-TestResult -TestName $testName -Result "Failed" -Details "Exchange 2013 CU23 Not Ready"
        }
    } elseif ($adLevel.Schema.Value -eq 15332) {
        #Exchange 2016 CU10+
        if ($adLevel.MESO.Value -eq 13236) {
            if ($adLevel.Org.Value -eq 16213) {
                TestReadyLevel "2016" "CU10"
            } elseif ($adLevel.Org.Value -eq 16214) {
                TestReadyLevel "2016" "CU11"
            } elseif ($adLevel.Org.Value -eq 16215) {
                TestReadyLevel "2016" "CU12"
            } else {
                TestMismatchLevel -ExchangeVersion "2016" -ADSetupLevel $adLevel
            }
        } elseif ($adLevel.MESO.Value -eq 13237 -and
            $adLevel.Org.Value -eq 16217) {
            TestReadyLevel "2016" "CU17"
        } elseif ($adLevel.MESO.Value -eq 13238 -and
            $adLevel.Org.Value -eq 16218) {
            TestReadyLevel "2016" "CU18"
        } else {
            TestMismatchLevel -ExchangeVersion "2016" -ADSetupLevel $adLevel
        }
    } elseif ($adLevel.Schema.Value -eq 15333) {
        if ($adLevel.MESO.Value -eq 13239 -and
            $adLevel.Org.Value -eq 16219) {
            TestReadyLevel "2016" "CU19"
        } elseif ($adLevel.MESO.Value -eq 13240 -and
            $adLevel.Org.Value -eq 16220) {
            TestReadyLevel "2016" "CU20"
        } else {
            TestMismatchLevel -ExchangeVersion "2016" -ADSetupLevel $adLevel
        }
    } elseif ($adLevel.Schema.Value -eq 15334) {
        if ($adLevel.MESO.Value -eq 13241 -and
            $adLevel.Org.Value -eq 16221) {
            TestReadyLevel "2016" "CU21"
        } elseif ( $adLevel.MESO.Value -eq 13242 -and
            $adLevel.Org.Value -eq 16222) {
            TestReadyLevel "2016" "CU22"
        } else {
            TestMismatchLevel -ExchangeVersion "2016" -ADSetupLevel $adLevel
        }
    } elseif ($adLevel.schema.Value -eq 17002) {
        #Exchange 2019 CU2+
        if ($adLevel.MESO.Value -eq 13239 -and
            $adLevel.Org.Value -eq 16756) {
            TestReadyLevel "2019" "CU8"
        } elseif ($adLevel.MESO.Value -eq 13240 -and
            $adLevel.Org.Value -eq 16757) {
            TestReadyLevel "2019" "CU9"
        } else {
            TestMismatchLevel -ExchangeVersion "2019" -ADSetupLevel $adLevel
        }
    } elseif ($adLevel.Schema.Value -eq 17003) {
        if ($adLevel.MESO.Value -eq 13241 -and
            $adLevel.Org.Value -eq 16758) {
            TestReadyLevel "2019" "CU10"
        } elseif ($adLevel.MESO.Value -eq 13242 -and
            $adLevel.Org.Value -eq 16759) {
            TestReadyLevel "2019" "CU11"
        } else {
            TestMismatchLevel -ExchangeVersion "2019" -ADSetupLevel $adLevel
        }
    } else {
        TestMismatchLevel -ExchangeVersion "2019" -ADSetupLevel $adLevel
    }
}
