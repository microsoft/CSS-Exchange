# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\UserContext\Test-UserGroupMemberOf.ps1
. $PSScriptRoot\..\..\..\Shared\SetupLogReviewerFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
function Test-ExchangeADSetupLevel {

    # Extract for Pester Testing - Start
    function TestPrepareAD {

        $forest = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest
        $params = @{
            TestName = "Prepare AD Requirements"
            Result   = "Failed"
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

    function TestADLevelToBuildInformation {
        [CmdletBinding()]
        param(
            [object]$CurrentADLevel, # From GetExchangeADSetupLevel
            [object]$BuildLevelInformation # From Get-ExchangeBuildVersionInformation
        )

        $params = @{
            TestName      = "Exchange AD Level"
            Details       = $BuildLevelInformation.FriendlyName
            ReferenceInfo = @(
                "Org DN Value: $($CurrentADLevel.Org.DN) Version: $($CurrentADLevel.Org.Value)",
                "Schema DN Value: $($CurrentADLevel.Schema.DN) Version: $($CurrentADLevel.Schema.Value)",
                "MESO DN Value: $($CurrentADLevel.MESO.DN) Version: $($CurrentADLevel.MESO.Value)",
                "More Info: https://aka.ms/SA-ExchangeLatest"
            )
        }

        # We don't care about schema versions less than 2013 for current AD.
        # We are going to be relying on Exchange 2013 latest otherwise based off the current logic.

        # Two MESO containers found in domain, that could prevent you from installing Exchange in it.
        if ($CurrentADLevel.MESO.Count -gt 1) {

            $problemMesos = @($CurrentADLevel.MESO | Where-Object { $_.Value -lt 12433 })

            if ($problemMesos.Count -ge 1) {
                $problemMesos | ForEach-Object {
                    $params.Details = "Problem MESO Container: $($_.DN)"
                    $params.ReferenceInfo = "Must update or delete container"
                    New-TestResult @params -Result "Failed"
                }
                return
            }
        }

        # Test out to make sure you are running the correct version of the script that knows about this version of AD.
        # This must be against 2019 as that would be the latest version that you can have.
        $latestExchangeVersionBuild = Get-ExchangeBuildVersionInformation -FileVersion "15.2.9999.9"

        if ($CurrentADLevel.Schema.Value -gt $latestExchangeVersionBuild.ADLevel.SchemaValue -or
            $CurrentADLevel.MESO.Value -gt $latestExchangeVersionBuild.ADLevel.MESOValue -or
            $CurrentADLevel.Org.Value -gt $latestExchangeVersionBuild.ADLevel.OrgValue) {
            $referenceInfo = $params.ReferenceInfo
            $params.ReferenceInfo = @(
                "Unknown AD Version. Script is out of date. Please update prior to determining next steps.",
                ""
            )
            $params.ReferenceInfo += $referenceInfo
            New-TestResult @params -Result "Warning"
            return
        }

        if ($BuildLevelInformation.ADLevel.SchemaValue -gt $CurrentADLevel.Schema.Value) {
            # Trying to install a newer version of Exchange thus requires /PrepareAD with Schema Admin rights.
            Test-UserGroupMemberOf -PrepareAdRequired $true -PrepareSchemaRequired $true
            New-TestResult @params -Result "Failed"
            TestPrepareAD
        } else {
            # Schema Admin rights should not be required since we aren't updating the schema.
            if ($BuildLevelInformation.ADLevel.MESOValue -le $CurrentADLevel.MESO.Value -and
                $BuildLevelInformation.ADLevel.OrgValue -le $CurrentADLevel.Org.Value) {
                Write-Verbose "We have a newer or equal ORG and MESO in AD. No AD Update is required"
                New-TestResult @params -Result "Passed"
            } elseif ($BuildLevelInformation.ADLevel.OrgValue -gt $CurrentADLevel.Org.Value) {
                # /PrepareAD is required
                Write-Verbose "Determined that /PrepareAD is required."
                Test-UserGroupMemberOf -PrepareAdRequired $true
                New-TestResult @params -Result "Failed"
                TestPrepareAD
            } else {
                # /PrepareDomain is required. AKA Updating the MESO container.
                Write-Verbose "Determined that /PrepareDomain is required."
                $localDomainPrep = $null -ne $ADSetupLevel -and $ADSetupLevel.MESO.DN -ne "Unknown"
                Test-UserGroupMemberOf -PrepareAdRequired $true -PrepareDomainOnly $localDomainPrep
                New-TestResult @params -Result "Failed"
                TestPrepareAD
            }
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

    <#
        Get the current AD Level (SchemaValue, MESOValue, OrgValue)
        Determine if Exchange install was attempted on this server by the SetupLog and OwaVersion
            - Use the Setup Log Version if newer than the registry OwaVersion otherwise use OwaVersion
        When trying to install Exchange 2016 Server, but have 2019 Schema, we should be okay providing the other AD Levels are at or above that CUs requirements.
    #>

    $adLevel = GetExchangeADSetupLevel
    $setupLog = "$env:SystemDrive\ExchangeSetupLogs\ExchangeSetup.log"
    $setupBuildInformation = $null                 # Current build information based off the setup log
    $currentInstallBuildInformation = $null       # current install build information we are testing against.
    $owaVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).OwaVersion

    if (Test-Path $setupLog) {

        try {
            $logReviewer = Get-SetupLogReviewer -SetupLog $setupLog
            $setupBuildNumber = $logReviewer.SetupBuildNumber
            Write-Verbose "User: $($logReviewer.User) SetupBuildNumber: $setupBuildNumber"
            $setupBuildInformation = Get-ExchangeBuildVersionInformation -FileVersion $setupBuildNumber
        } catch {
            Write-Warning "Failed to determine proper information from the setup log."
        }
    } else {
        Write-Verbose "No Setup Log to test against."
    }

    if ($null -ne $owaVersion -or
        $null -ne $setupBuildInformation) {
        Write-Verbose "Setting the `$currentInstallBuildInformation to test against based off the build number on the computer."

        if ($null -ne $owaVersion -and
            $null -ne $setupBuildInformation) {
            $owaBuildInfo = Get-ExchangeBuildVersionInformation -FileVersion $owaVersion

            if ($owaBuildInfo.BuildVersion -lt $setupBuildInformation.BuildVersion) {
                Write-Verbose "Trying to install newer CU, setting to Setup Build Number."
                $currentInstallBuildInformation = $setupBuildInformation
            } else {
                Write-Verbose "Setting to OWA Build Number."
                $currentInstallBuildInformation = $owaBuildInfo
            }
        } elseif ($null -ne $owaVersion) {
            Write-Verbose "Setup Build Number was null, setting to OwaVersion"
            $currentInstallBuildInformation = Get-ExchangeBuildVersionInformation -FileVersion $owaVersion
        } else {
            Write-Verbose "OwaVersion was null, setting to Setup Build Number."
            $currentInstallBuildInformation = $setupBuildInformation
        }
    } else {
        Write-Verbose "Setting the `$currentInstallBuildInformation to test against based off the latest version of the schema range."

        # Exchange 2016 RTM Schema Value is 15317
        # Exchange 2019 RTM Schema Value is 17000
        if ($adLevel.Schema.Value -lt 15317) {
            Write-Verbose "Setting to latest 2013"
            $currentInstallBuildInformation = Get-ExchangeBuildVersionInformation -FileVersion "15.0.9999.9"
        } elseif ($adLevel.Schema.Value -lt 17000) {
            Write-Verbose "Setting to latest 2016"
            $currentInstallBuildInformation = Get-ExchangeBuildVersionInformation -FileVersion "15.1.9999.9"
        } else {
            Write-Verbose "Setting to latest 2019"
            $currentInstallBuildInformation = Get-ExchangeBuildVersionInformation -FileVersion "15.2.9999.9"
        }
    }

    TestADLevelToBuildInformation -CurrentADLevel $adLevel -BuildLevelInformation $currentInstallBuildInformation
}
