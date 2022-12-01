# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\UserContext\Test-UserGroupMemberOf.ps1
. $PSScriptRoot\..\..\..\Shared\SetupLogReviewerFunctions.ps1
function Test-ExchangeADSetupLevel {

    # Extract for Pester Testing - Start
    function TestPrepareAD {
        param(
            [string]$ExchangeVersion,
            [object]$ADSetupLevel
        )
        # Make sure this gets called first before any other returns can occur
        #TODO Fix this logic. This isn't going to work if local domain needs to be prepared if local domain has been prepared at least once before.
        #To make this an easier fix, need to complete #1314 first.
        # If UNKNOWN user must be in the Enterprise Admin, otherwise setup will fail
        $localDomainPrep = $null -ne $ADSetupLevel -and $ADSetupLevel.MESO.DN -eq "Unknown"
        Test-UserGroupMemberOf -PrepareAdRequired $true -PrepareSchemaRequired ($latestExchangeVersion.$ExchangeVersion.UpperRange -ne $currentSchemaValue) # -PrepareDomainOnly $localDomainPrep

        $forest = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest
        $params = @{
            TestName = "Prepare AD Requirements"
            Result   = "Failed"
        }

        # Need to prepare the local domain domain
        if ($localDomainPrep) {
            New-TestResult @params -Details "Run /PrepareDomain from this computer with Domain Admins and Enterprise Admin account"
            return
        }

        if ($null -eq $forest) {
            New-TestResult @params -Details "Failed to get current forest"
            return
        }

        if ($null -eq $forest.SchemaRoleOwner) {
            New-TestResult @params -Details "Failed to get schema master role owner"
            return
        }

        $schemaMaster = $forest.SchemaRoleOwner.Name
        $smSite = $forest.SchemaRoleOwner.SiteName

        if ($null -eq $smSite) {
            $smSite = "Failed to get correct site"
        }

        try {
            $localSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
        } catch {
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
    }

    function TestMismatchLevel {
        param(
            [string]$ExchangeVersion,
            [object]$ADSetupLevel
        )
        $params = @{
            TestName      = $testName
            Result        = "Failed"
            ReferenceInfo = "Mismatch detected `n    More Info: https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-$ExchangeVersion"
        }
        New-TestResult @params -Details @("Org DN Value: $($ADSetupLevel.Org.DN) Version: $($ADSetupLevel.Org.Value)",
            "Schema DN Value: $($ADSetupLevel.Schema.DN) Version: $($ADSetupLevel.Schema.Value)",
            "MESO DN Value: $($ADSetupLevel.MESO.DN) Version: $($ADSetupLevel.MESO.Value)")
        TestPrepareAD -ExchangeVersion $ExchangeVersion -ADSetupLevel $ADSetupLevel
    }

    function TestReadyLevel {
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

    function GetVersionObject {
        param(
            [object]$SearchResults,
            [string]$VersionValueName = "ObjectVersion"
        )
        if ($null -eq $SearchResults.Properties) {
            return [PSCustomObject]@{
                DN    = "Unknown"
                Value = -1
            }
        }

        foreach ($result in $SearchResults) {
            [PSCustomObject]@{
                DN    = $result.Properties["DistinguishedName"]
                Value = ($result.Properties[$VersionValueName]).ToInt32([System.Globalization.NumberFormatInfo]::InvariantInfo)
            }
        }
    }

    function GetExchangeADSetupLevel {
        $rootDSE = [ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
        $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher
        $directorySearcher.SearchScope = "Subtree"
        $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.configurationNamingContext.ToString())
        $directorySearcher.Filter = "(objectCategory=msExchOrganizationContainer)"
        $orgFindAll = $directorySearcher.FindAll()
        Write-Verbose "Found $($orgFindAll.Count) ORG object(s)"

        # Should only be 1 schema
        $directorySearcher.SearchRoot = [ADSI]("LDAP://CN=Schema," + $rootDSE.configurationNamingContext.ToString())
        $directorySearcher.Filter = "(&(name=ms-Exch-Schema-Version-Pt)(objectCategory=attributeSchema))"
        $schemaFindAll = $directorySearcher.FindAll()
        Write-Verbose "Found $($schemaFindAll.Count) Schema object(s)"

        $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.defaultNamingContext.ToString())
        $directorySearcher.Filter = "(objectCategory=msExchSystemObjectsContainer)"
        $mesoFindAll = $directorySearcher.FindAll()
        Write-Verbose "Found $($mesoFindAll.Count) MESO object(s)"

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
            CU         = "CU23"
            UpperRange = 15334
        }
        2019 = [PSCustomObject]@{
            CU         = "CU12"
            UpperRange = 17003
        }
    }

    $adLevel = GetExchangeADSetupLevel
    $testName = "Exchange AD Latest Level"
    $setupLog = "$env:SystemDrive\ExchangeSetupLogs\ExchangeSetup.log"
    $currentSchemaValue = $adLevel.Schema.Value
    $currentInstallingExchangeVersion = $null

    if (Test-Path $setupLog) {
        $logReviewer = Get-SetupLogReviewer -SetupLog $setupLog
        $setupBuildNumber = $logReviewer.SetupBuildNumber
        Write-Verbose "User: $($logReviewer.User) SetupBuildNumber: $setupBuildNumber"

        if ($setupBuildNumber -like "15.0.*") {
            $currentInstallingExchangeVersion = "2013"
        } elseif ($setupBuildNumber -like "15.1.*") {
            $currentInstallingExchangeVersion = "2016"
        } elseif ($setupBuildNumber -like "15.2.*") {
            $currentInstallingExchangeVersion = "2019"
        } else {
            Write-Verbose "Couldn't determine the build number. This shouldn't occur."
        }

        Write-Verbose "currentInstallingExchangeVersion: $currentInstallingExchangeVersion"
    } else {
        Write-Verbose "No Setup Log to test against."
    }

    # Two MESO containers found in domain, that could prevent you from installing Exchange in it.
    if ($adLevel.MESO.Count -gt 1) {

        $problemMesos = @($adLevel.MESO | Where-Object { $_.Value -lt 12433 })

        if ($problemMesos.Count -ge 1) {
            $problemMesos | ForEach-Object {
                New-TestResult -TestName $testName -Result "Failed" -Details "Problem MESO Container: $($_.DN)" -ReferenceInfo "Must update or delete container"
            }
            return
        }
    }

    #Less than the known Exchange 2013 schema version
    if ($adLevel.Schema.Value -lt 15137) {
        New-TestResult -TestName $testName -Result "Failed" -Details "Unknown Exchange Schema Version"

        if ($null -ne $currentInstallingExchangeVersion) {
            TestMismatchLevel -ExchangeVersion $currentInstallingExchangeVersion -ADSetupLevel $adLevel
        } else {
            TestMismatchLevel -ExchangeVersion "2019" -ADSetupLevel $adLevel
        }
        return
    }

    # Test if not on schema version of install attempt
    if ($null -eq $currentInstallingExchangeVersion) {
        Write-Verbose "No current install exchange version detected. Skipping over this logic."
    } elseif ($adLevel.Schema.Value -le 15312 -and
        $currentInstallingExchangeVersion -ne "2013") {
        Write-Verbose "Determined that we are trying install a newer version of Exchange than what schema level is at for 2013"
        TestMismatchLevel -ExchangeVersion $currentInstallingExchangeVersion -ADSetupLevel $adLevel
        return
    } elseif ($adLevel.Schema.Value -gt 15312 -and
        $adLevel.Schema.Value -le 15334 -and
        $currentInstallingExchangeVersion -ne "2016") {
        Write-Verbose "Determined that we are trying install a newer version of Exchange than what schema level is at for 2016"
        TestMismatchLevel -ExchangeVersion $currentInstallingExchangeVersion -ADSetupLevel $adLevel
        return
    } elseif ($adLevel.Schema.Value -gt 15334 -and
        $adLevel.Schema.Value -le 17003 -and
        $currentInstallingExchangeVersion -ne "2019") {
        Write-Verbose "Determined that we are trying install a newer version of Exchange than what schema level is at for 2019"
        TestMismatchLevel -ExchangeVersion $currentInstallingExchangeVersion -ADSetupLevel $adLevel
        return
    }

    #Exchange 2013 CU23 Only
    if ($adLevel.Schema.Value -eq 15312) {
        if ($adLevel.MESO.Value -eq 13237 -and
            $adLevel.Org.Value -eq 16133) {
            New-TestResult -TestName $testName -Result "Passed" -Details "Exchange 2013 CU23 Ready"
            Test-UserGroupMemberOf
        } else {
            New-TestResult -TestName $testName -Result "Failed" -Details "Exchange 2013 CU23 Not Ready"
            Test-UserGroupMemberOf
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
        } elseif ($adLevel.MESO.Value -eq 13243 -and
            $adLevel.Org.Value -eq 16223) {
            TestReadyLevel "2016" "CU23"
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
        } elseif ($adLevel.MESO.Value -eq 13243 -and
            $adLevel.Org.Value -eq 16760) {
            TestReadyLevel "2019" "CU12"
        } else {
            TestMismatchLevel -ExchangeVersion "2019" -ADSetupLevel $adLevel
        }
    } else {
        TestMismatchLevel -ExchangeVersion "2019" -ADSetupLevel $adLevel
    }
}
