# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Write-PrepareADInfo {
    param(
        [bool]$SchemaUpdateRequired
    )

    $netDom = netdom query fsmo

    if ($null -eq $netDom) {
        "Failed to query FSMO role" | Receive-Output -IsError
        return
    }

    $schemaMaster = ($netDom | Select-String "Schema master (.+)").Matches.Groups[1].Value.Trim()
    $smSite = nltest /server:$schemaMaster /dsgetsite

    if ($smSite[-1] -eq "The command completed successfully") {
        $smSite = $smSite[0]
    } else {
        "Failed to get the correct site for the Schema Master" | Receive-Output -IsError
    }

    $localSite = nltest /dsgetsite

    if ($localSite[-1] -eq "The command completed successfully") {
        $localSite = $localSite[0]
    } else {
        "Failed to get the server's local site." | Receive-Output -IsError
    }

    $serverFQDN = ([System.Net.Dns]::GetHostByName(($env:computerName))).HostName
    $serverDomain = $serverFQDN.Substring($serverFQDN.IndexOf(".") + 1)
    $smDomain = $schemaMaster.Substring($schemaMaster.IndexOf(".") + 1)

    if ($SchemaUpdateRequired -and
        $Script:NotSchemaAdmin) {
        "Schema Update is required and you must be in the Schema Admins group" | Receive-Output -IsWarning
    }

    if ($Script:NotEnterpriseAdmin) {
        "/PrepareAd is required and you must be in the Enterprise Admins group" | Receive-Output -IsWarning
    }

    "Schema Master:         $schemaMaster" | Receive-Output
    "Schema Master Domain:  $smDomain" | Receive-Output
    "Schema Master AD Site: $smSite" | Receive-Output
    "-----------------------------------" | Receive-Output
    "Local Server:          $serverFQDN" | Receive-Output
    "Local Server Domain:   $serverDomain" | Receive-Output
    "Local Server AD Site:  $localSite" | Receive-Output

    #If we are in the correct domain and correct site we can run /prepareAD.
    if (($serverDomain -eq $smDomain) -and
        ($smSite -eq $localSite)) {
        "We are able to run /PrepareAD from this computer" | Receive-Output
    } else {

        if ($smSite -ne $localSite) {
            "We are not in the same site as the Schema Master. Must be in AD Site: $smSite" | Receive-Output -IsWarning
        }

        if ($smDomain -ne $serverDomain) {
            "We are not in the same domain as the Schema Master. Must be in domain: $smDomain" | Receive-Output -IsWarning
        }
    }
}

#https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-2019
#https://docs.microsoft.com/en-us/exchange/prepare-active-directory-and-domains-exchange-2013-help
function Test-ExchangeAdSetupObjects {

    $AdSetup = Get-ExchangeAdSetupObjects
    $schemaValue = $AdSetup["Schema"].VersionValue
    $orgValue = $AdSetup["Org"].VersionValue
    $MESOValue = $AdSetup["MESO"].VersionValue

    $exchLatest = @{}
    $exchLatest.Add("2016", [PSCustomObject]@{
            CU         = "CU21"
            UpperRange = 15334
        })
    $exchLatest.Add("2019", [PSCustomObject]@{
            CU         = "CU10"
            UpperRange = 17003
        })
    $exchLatest.Add("2013", [PSCustomObject]@{
            CU         = "CU23"
            UpperRange = 15312
        })

    function Write-Mismatch {
        param(
            [string]$ExchVersion,
            [bool]$DisplayMismatch = $true,
            [int]$UpperRange
        )

        if ($DisplayMismatch) {
            "Exchange $ExchVersion AD Level Failed. Mismatch detected." | Receive-Output -IsWarning
        }

        foreach ($key in $AdSetup.Keys) {
            "DN Value: '$([string]($AdSetup[$key].DN))' - Version: $([string]($AdSetup[$key].VersionValue))" | Receive-Output -IsWarning
        }

        if ($ExchVersion -eq "2013") {
            "More Info: https://docs.microsoft.com/en-us/exchange/prepare-active-directory-and-domains-exchange-2013-help" | Receive-Output -IsWarning
        } else {
            "More Info: https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-$ExchVersion" | Receive-Output -IsWarning
        }

        Write-PrepareADInfo -SchemaUpdateRequired (($exchLatest[$ExchVersion].UpperRange -ne $UpperRange))
    }

    Function Write-ReadyFor {
        param(
            [string]$ExchangeVersion,
            [string]$CU,
            [int]$UpperRange
        )

        "Exchange $ExchangeVersion $CU Ready." | Receive-Output

        if ($exchLatest[$ExchangeVersion].CU -ne $CU) {
            "Not ready for the latest Exchange $ExchangeVersion $($exchLatest[$ExchangeVersion].CU). /PrepareAD is required to be ready for this version" | Receive-Output -IsWarning
            Write-PrepareADInfo -SchemaUpdateRequired ($exchLatest[$ExchangeVersion].UpperRange -ne $UpperRange)
        }
    }

    #Schema doesn't change often and and quickly tell the highest ExchangeVersion
    if ($schemaValue -lt 15137) {
        "Unable to determine AD Exchange Level readiness." | Receive-Output -IsWarning
        Write-Mismatch -ExchVersion "Unknown" -DisplayMismatch $false
        return
    }

    #Exchange 2013 CU23 only
    if ($schemaValue -le 15312) {

        if ($MESOValue -eq 13237 -and
            $orgValue -eq 16133) {
            "Exchange 2013 CU23 Ready." | Receive-Output
            return
        }
        Write-Mismatch -ExchVersion "2013" -UpperRange $schemaValue
    }

    #Exchange 2016 CU10+
    elseif ($schemaValue -eq 15332) {

        if ($MESOValue -eq 13236) {

            if ($orgValue -eq 16213) {
                $CU = "CU10"
            } elseif ($orgValue -eq 16214) {
                $CU = "CU11"
            } elseif ($orgValue -eq 16215) {
                $CU = "CU12"
            } else {
                Write-Mismatch -ExchVersion "2016" -UpperRange $schemaValue
                return
            }
        } elseif ($MESOValue -eq 13237 -and
            $orgValue -eq 16217) {
            $CU = "CU17"
        } elseif ($MESOValue -eq 13238 -and
            $orgValue -eq 16218) {
            $CU = "CU18"
        } else {
            Write-Mismatch -ExchVersion "2016" -UpperRange $schemaValue
            return
        }
        Write-ReadyFor -ExchangeVersion "2016" -UpperRange $schemaValue -CU $CU
    } elseif ($schemaValue -eq 15333) {
        if ($MESOValue -eq 13239 -and
            $orgValue -eq 16219) {
            $CU = "CU19"
        } elseif ($MESOValue -eq 13240 -and
            $orgValue -eq 16220) {
            $CU = "CU20"
        } else {
            Write-Mismatch -ExchVersion "2016" -UpperRange $schemaValue
            return
        }
        Write-ReadyFor -ExchangeVersion "2016" -UpperRange $schemaValue -CU $CU
    } elseif ($schemaValue -eq 15334) {

        if ($MESOValue -eq 13241 -and
            $orgValue -eq 16221) {
            $CU = "CU21"
        } else {
            Write-Mismatch -ExchVersion "2016" -UpperRange $schemaValue
            return
        }
        Write-ReadyFor -ExchangeVersion "2016" -UpperRange $schemaValue -CU $CU
    }
    #Exchange 2019 CU2+
    elseif ($schemaValue -eq 17001) {

        if ($MESOValue -eq 13237 -and
            $orgValue -eq 16754) {
            $CU = "CU6"
        } elseif ($MESOValue -eq 13238 -and
            $orgValue -eq 16755) {
            $CU = "CU7"
        } else {
            Write-Mismatch -ExchVersion "2019" -UpperRange $schemaValue
            return
        }
        Write-ReadyFor -ExchangeVersion "2019" -UpperRange $schemaValue -CU $CU
    } elseif ($schemaValue -eq 17002) {

        if ($MESOValue -eq 13239 -and
            $orgValue -eq 16756) {
            $CU = "CU8"
        } elseif ($MESOValue -eq 13240 -and
            $orgValue -eq 16757) {
            $CU = "CU9"
        } else {
            Write-Mismatch -ExchVersion "2019" -UpperRange $schemaValue
            return
        }
        Write-ReadyFor -ExchangeVersion "2019" -UpperRange $schemaValue -CU $CU
    } elseif ($schemaValue -eq 17003) {

        if ($MESOValue -eq 13241 -and
            $orgValue -eq 16758) {
            $CU = "CU10"
        } else {
            Write-Mismatch -ExchVersion "2019" -UpperRange $schemaValue
            return
        }
        Write-ReadyFor -ExchangeVersion "2019" -UpperRange $schemaValue -CU $CU
    } else {
        Write-Mismatch -ExchVersion "2019" -UpperRange $schemaValue
    }
}

function Get-ExchangeAdSetupObjects {
    $rootDSE = [ADSI]("LDAP://RootDSE")

    if ([string]::IsNullOrEmpty($rootDSE.configurationNamingContext) -or
        [string]::IsNullOrEmpty($rootDSE.defaultNamingContext)) {
        return $null
    }

    Function Get-VersionObject {
        param(
            [object]$SearchResults,
            [string]$VersionValueName = "ObjectVersion"
        )
        $versionObject = [PSCustomObject]@{
            DN           = $SearchResults.Properties["DistinguishedName"]
            VersionValue = ($SearchResults.Properties[$VersionValueName]).ToInt32([System.Globalization.NumberFormatInfo]::InvariantInfo)
        }

        return $versionObject
    }

    $hash = @{}

    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher
    $directorySearcher.SearchScope = "Subtree"
    $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.configurationNamingContext.ToString())
    $directorySearcher.Filter = "(objectCategory=msExchOrganizationContainer)"

    $findAll = $directorySearcher.FindAll()
    $hash.Add("Org", (Get-VersionObject -SearchResults $findAll))

    $directorySearcher.SearchRoot = [ADSI]("LDAP://CN=Schema," + $rootDSE.configurationNamingContext.ToString())
    $directorySearcher.Filter = "(&(name=ms-Exch-Schema-Version-Pt)(objectCategory=attributeSchema))"

    $findAll = $directorySearcher.FindAll()
    $hash.Add("Schema", (Get-VersionObject -SearchResults $findAll -VersionValueName "RangeUpper"))

    $directorySearcher.SearchScope = "OneLevel"
    $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.rootDomainNamingContext.ToString())
    $directorySearcher.Filter = "(objectCategory=msExchSystemObjectsContainer)"

    $findAll = $directorySearcher.FindAll()
    $hash.Add("MESO", (Get-VersionObject -SearchResults $findAll))

    return $hash
}
