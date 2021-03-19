# SetupAssist.ps1 is used for running on the Exchange Server that we are wanting to install or upgrade.
# We validate common prerequisites that or overlooked and look at AD to make sure it is able to upgrade
#
# TODO: Add AD Object Permissions check
#
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'Need to do nothing about it')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Use is the best verb and do not need to confirm')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameter is used')]
[CmdletBinding()]
param(
    [switch]$OtherWellKnownObjects
)

. .\Utils\ConvertFrom-Ldif.ps1

function IsAdministrator {
    $ident = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object System.Security.Principal.WindowsPrincipal($ident)
    return $prin.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function GetGroupMatches($whoamiOutput, $groupName) {
    $m = @($whoamiOutput | Select-String "(^\w+\\$($groupName))\W+Group")
    if ($m.Count -eq 0) { return $m }
    return $m | ForEach-Object {
        [PSCustomObject]@{
            GroupName = ($_.Matches.Groups[1].Value)
            SID       = (GetSidFromLine $_.Line)
        }
    }
}

Function GetSidFromLine ([string]$Line) {
    $startIndex = $Line.IndexOf("S-")
    return $Line.Substring($startIndex,
        $Line.IndexOf(" ", $startIndex) - $startIndex)
}

# From https://stackoverflow.com/questions/47867949/how-can-i-check-for-a-pending-reboot
function Test-PendingReboot {
    if (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) {
        Write-Verbose "Key set in: HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending. Remove it if reboot doesn't work"
        Write-Verbose ("To Fix, only after reboot does work: `r`n`t" + `
                "Open regedit, find HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing.`r`n`t" + `
                "1. If you see PackagesPending, right click it, open Permissions, click on Advanced, change owner to your account. Close Advanced window.`r`n`t`t" + `
                "Give your account Full Control in Permissions window. Delete the key.`r`n`t" + `
                "2. Repeat step 1. with Reboot Pending")
        return $true
    }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) {
        Write-Verbose "Key exists at: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired. Remove it if reboot doesn't work"
        return $true
    }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) {
        Write-Verbose "Key set at: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager - PendingFileRenameOperations. Remove it if reboot doesn't work"
        return $true
    }
    try {
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()

        if (($null -ne $status) -and $status.RebootPending) {
            return $true
        }
    } catch { }

    return $false
}

Function Write-PrepareADInfo {
    param(
        [bool]$SchemaUpdateRequired
    )

    $netDom = netdom query fsmo

    if ($null -eq $netDom) {
        Write-Error "Failed to query FSMO role"
        return
    }

    $schemaMaster = ($netDom | Select-String "Schema master (.+)").Matches.Groups[1].Value.Trim()
    $smSite = nltest /server:$schemaMaster /dsgetsite

    if ($smSite[-1] -eq "The command completed successfully") {
        $smSite = $smSite[0]
    } else {
        Write-Error "Failed to get the correct site for the Schema Master"
    }

    $localSite = nltest /dsgetsite

    if ($localSite[-1] -eq "The command completed successfully") {
        $localSite = $localSite[0]
    } else {
        Write-Error "Failed to get the server's local site."
    }

    $serverFQDN = ([System.Net.Dns]::GetHostByName(($env:computerName))).HostName
    $serverDomain = $serverFQDN.Substring($serverFQDN.IndexOf(".") + 1)
    $smDomain = $schemaMaster.Substring($schemaMaster.IndexOf(".") + 1)

    if ($SchemaUpdateRequired -and
        $Script:NotSchemaAdmin) {
        Write-Warning "Schema Update is required and you must be in the Schema Admins group"
    }

    if ($Script:NotEnterpriseAdmin) {
        Write-Warning "/PrepareAd is required and you must be in the Enterprise Admins group"
    }

    Write-Host "Schema Master:         $schemaMaster"
    Write-Host "Schema Master Domain:  $smDomain"
    Write-Host "Schema Master AD Site: $smSite"
    Write-Host "-----------------------------------"
    Write-Host "Local Server:          $serverFQDN"
    Write-Host "Local Server Domain:   $serverDomain"
    Write-Host "Local Server AD Site:  $localSite"

    #If we are in the correct domain and correct site we can run /prepareAD.
    if (($serverDomain -eq $smDomain) -and
        ($smSite -eq $localSite)) {
        Write-Host "We are able to run /PrepareAD from this computer"
    } else {

        if ($smSite -ne $localSite) {
            Write-Warning "We are not in the same site as the Schema Master. Must be in AD Site: $smSite"
        }

        if ($smDomain -ne $serverDomain) {
            Write-Warning "We are not in the same domain as the Schema Master. Must be in domain: $smDomain"
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
            CU         = "CU19"
            UpperRange = 15333
        })
    $exchLatest.Add("2019", [PSCustomObject]@{
            CU         = "CU8"
            UpperRange = 17002
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
            Write-Warning("Exchange {0} AD Level Failed. Mismatch detected." -f $ExchVersion)
        }

        foreach ($key in $AdSetup.Keys) {
            Write-Warning("DN Value: '{0}' - Version: {1}" -f [string]($AdSetup[$key].DN), [string]($AdSetup[$key].VersionValue))
        }

        if ($ExchVersion -eq "2013") {
            Write-Warning ("More Info: https://docs.microsoft.com/en-us/exchange/prepare-active-directory-and-domains-exchange-2013-help")
        } else {
            Write-Warning("More Info: https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-{0}" -f $ExchVersion)
        }

        Write-PrepareADInfo -SchemaUpdateRequired (($exchLatest[$ExchVersion].UpperRange -ne $UpperRange))
    }

    Function Write-ReadyFor {
        param(
            [string]$ExchangeVersion,
            [string]$CU,
            [int]$UpperRange
        )

        Write-Host "Exchange $ExchangeVersion $CU Ready."

        if ($exchLatest[$ExchangeVersion].CU -ne $CU) {
            Write-Warning "Not ready for the latest Exchange $ExchangeVersion CU. /PrepareAD is required to be ready for this version"
            Write-PrepareADInfo -SchemaUpdateRequired ($exchLatest[$ExchangeVersion].UpperRange -ne $UpperRange)
        }
    }

    #Schema doesn't change often and and quickly tell the highest ExchangeVersion
    if ($schemaValue -lt 15137) {
        Write-Warning("Unable to determine AD Exchange Level readiness.")
        Write-Mismatch -ExchVersion "Unknown" -DisplayMismatch $false
        return
    }

    #Exchange 2013 CU23 only
    if ($schemaValue -le 15312) {

        if ($MESOValue -eq 13237 -and
            $orgValue -eq 16133) {
            Write-Host "Exchange 2013 CU23 Ready."
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
        Write-ReadyFor -ExchangeVersion "2016" -UpperRange $schemaValue -CU $CU
    } elseif ($schemaValue -eq 17002) {

        if ($MESOValue -eq 13239 -and
            $orgValue -eq 16756) {
            $CU = "CU8"
        } else {
            Write-Mismatch -ExchVersion "2019" -UpperRange $schemaValue
            return
        }
        Write-ReadyFor -ExchangeVersion "2016" -UpperRange $schemaValue -CU $CU
    } else {
        Write-Mismatch -ExchVersion "2019" -UpperRange $schemaValue
    }
}

Function Test-ValidHomeMDB {
    ldifde -t 3268 -r "(&(objectClass=user)(mailnickname=*)(!(msExchRemoteRecipientType=*))(!(targetAddress=*))(msExchHideFromAddressLists=TRUE)(!(cn=HealthMailbox*)))" -l distinguishedName, homeMDB -f validHomeMdb.txt | Out-Null
    $ldifeObject = @(Get-Content .\validHomeMdb.txt | ConvertFrom-Ldif)

    if ($ldifeObject.Count -gt 0) {

        $emptyHomeMDB = @()
        $runActions = $false
        foreach ($result in $ldifeObject) {
            $dbName = $result.homeMDB

            if (![string]::IsNullOrEmpty($dbName)) {

                if (!([ADSI]::Exists("LDAP://$dbName"))) {
                    Write-Warning "Mailbox DN: $($result.dn) has an invalid homeMDB value."
                    $runActions = $true
                }
            } else {
                $emptyHomeMDB += $result.dn
            }
        }

        if ($emptyHomeMDB.Count -ge 1) {
            $runActions = $true
            Write-Warning "The following mailbox(es) have empty homeMDB values that will cause issues with setup"
            foreach ($dn in $emptyHomeMDB) {
                Write-Host "`t$dn"
            }
        }

        if ($runActions) {
            Write-Host ""
            Write-Warning "Follow the below steps to address empty/invalid homeMDB"
            Write-Host "`tRun the below command in EMS against each of the above mailboxes. If EMS is down, launch PowerShell and run `"Add-PSSnapin *Exchange*`""
            Write-Host "`t`tSet-Mailbox 'DN' -Database 'DB_Name'"
            Write-Host ""
        } else {
            Write-Host "All Critical Mailboxes have valid HomeMDB values"
        }
    } else {
        throw "Unexpected LDIF data."
    }
}

function Get-ExchangeAdSetupObjects {
    $rootDSE = [ADSI]("LDAP://RootDSE")

    if ([string]::IsNullOrEmpty($rootDSE.configurationNamingContext) -or
        [string]::IsNullOrEmpty($rootDSE.defaultNamingContext)) {
        return $null
    }

    Function New-VersionObject {
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
    $hash.Add("Org", (New-VersionObject -SearchResults $findAll))

    $directorySearcher.SearchRoot = [ADSI]("LDAP://CN=Schema," + $rootDSE.configurationNamingContext.ToString())
    $directorySearcher.Filter = "(&(name=ms-Exch-Schema-Version-Pt)(objectCategory=attributeSchema))"

    $findAll = $directorySearcher.FindAll()
    $hash.Add("Schema", (New-VersionObject -SearchResults $findAll -VersionValueName "RangeUpper"))

    $directorySearcher.SearchScope = "OneLevel"
    $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.rootDomainNamingContext.ToString())
    $directorySearcher.Filter = "(objectCategory=msExchSystemObjectsContainer)"

    $findAll = $directorySearcher.FindAll()
    $hash.Add("MESO", (New-VersionObject -SearchResults $findAll))

    return $hash
}

Function Test-MissingDirectories {
    $installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath

    if ($null -ne $installPath -and
        (Test-Path $installPath)) {
        $paths = @("$installPath`UnifiedMessaging\Grammars", "$installPath`UnifiedMessaging\Prompts")

        foreach ($path in $paths) {

            if (!(Test-Path $path)) {
                Write-Warning "Failed to find path: '$path'. Create this or setup will fail"
            }
        }
    }
}

Function Test-OtherWellKnownObjects {
    [CmdletBinding()]
    param ()

    $rootDSE = [ADSI]("LDAP://RootDSE")
    $exchangeContainerPath = ("CN=Microsoft Exchange,CN=Services," + $rootDSE.configurationNamingContext)

    ldifde -d $exchangeContainerPath -p Base -l otherWellKnownObjects -f $PSScriptRoot\ExchangeContainerOriginal.txt

    $ldifObjects = @(Get-Content $PSScriptRoot\ExchangeContainerOriginal.txt | ConvertFrom-Ldif)

    if ($ldifObjects.Length -lt 1) {
        throw "Failed to export ExchangeContainerOriginal.txt file"
    }

    if ($ldifObjects.Length -gt 1) {
        throw "Unexpected LDIF data."
    }

    $exchangeContainer = $ldifObjects[0]
    $badValues = @($exchangeContainer.otherWellKnownObjects | Where-Object { $_ -like "*CN=Deleted Objects*" })
    if ($badValues.Length -gt 0) {
        Write-Host
        Write-Warning "otherWellKnownObjects contains the following deleted objects:"
        Write-Host
        $badValues | ForEach-Object { Write-Host $_ }

        $outputLines = New-Object 'System.Collections.Generic.List[string]'
        $outputLines.Add("dn: " + $exchangeContainer.dn[0])
        $outputLines.Add("changeType: modify")
        $outputLines.Add("replace: otherWellKnownObjects")

        $goodValues = @($exchangeContainer.otherWellKnownObjects | Where-Object { $_ -notlike "*CN=Deleted Objects*" })
        $goodValues | ForEach-Object { $outputLines.Add("otherWellKnownObjects: " + $_) }
        $outputLines.Add("-")
        $outputLines.Add("")
        $outputLines | Out-File -FilePath "ExchangeContainerImport.txt"

        Write-Host("`r`nVerify the results in ExchangeContainerImport.txt. Then run the following command:")
        Write-Host("`r`n`tldifde -i -f ExchangeContainerImport.txt")
        Write-Host("`r`nThen, run Setup.exe /PrepareAD to recreate the deleted groups.")
        Write-Host
    } else {
        Write-Host "No bad values found in otherWellKnownObjects."
    }

    return
}

Function MainUse {
    $whoamiOutput = whoami /all

    $whoamiOutput | Select-String "User Name" -Context (0, 3)

    if (IsAdministrator) {
        Write-Host "User is an administrator."
    } else {
        Write-Warning "User is not an administrator."
    }

    [array]$g = GetGroupMatches $whoamiOutput "Domain Admins"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { Write-Host "User is a member of $($_.GroupName)   $($_.SID)" }
    } else {
        Write-Warning "User is not a member of Domain Admins."
    }

    [array]$g = GetGroupMatches $whoamiOutput "Schema Admins"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { Write-Host "User is a member of $($_.GroupName)   $($_.SID)" }
    } else {
        Write-Warning "User is not a member of Schema Admins. - Only required if doing a Schema Update"
        $Script:NotSchemaAdmin = $true
    }

    [array]$g = GetGroupMatches $whoamiOutput "Enterprise Admins"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { Write-Host "User is a member of $($_.GroupName)   $($_.SID)" }
    } else {
        Write-Warning "User is not a member of Enterprise Admins. - Only required if doing a Schema Update or PrepareAD or PrepareDomain"
        $Script:NotEnterpriseAdmin = $true
    }

    [array]$g = GetGroupMatches $whoamiOutput "Organization Management"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { Write-Host "User is a member of $($_.GroupName)   $($_.SID)" }
    } else {
        Write-Warning "User is not a member of Organization Management."
    }

    $p = Get-ExecutionPolicy
    if ($p -ne "Unrestricted" -and $p -ne "Bypass") {
        Write-Warning "ExecutionPolicy is $p"
    } else {
        Write-Host "ExecutionPolicy is $p"
    }

    $products = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products
    $packageFiles = $products | ForEach-Object { Get-ItemProperty -Path "Registry::$($_.Name)\InstallProperties" -ErrorAction SilentlyContinue } | ForEach-Object { $_.LocalPackage }
    $packagesMissing = @($packageFiles | Where-Object { (Test-Path $_) -eq $false })

    if ($packagesMissing.Count -eq 0) {
        Write-Host "No installer packages missing."
    } else {
        Write-Warning "$($packagesMissing.Count) installer packages are missing. Please use this script to repair the installer folder:"
        Write-Warning "https://gallery.technet.microsoft.com/office/Restore-the-Missing-d11de3a1"
    }

    $powershellProcesses = @(Get-Process -IncludeUserName powershell)

    if ($powershellProcesses.Count -gt 1) {
        Write-Warning "More than one PowerShell process was found. Please close other instances of PowerShell."
        Write-Host ($powershellProcesses | Format-Table -AutoSize | Out-String)
    } else {
        Write-Host "No other PowerShell instances were detected."
    }

    if (Test-PendingReboot) {
        Write-Warning "Reboot pending."
    } else {
        Write-Host "No reboot pending."
    }

    Test-ValidHomeMDB
    Test-MissingDirectories
    Test-ExchangeAdSetupObjects
}

Function Main {

    if ($OtherWellKnownObjects) {
        Test-OtherWellKnownObjects
    } else {
        MainUse
    }
}

Main
