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
    [string]$OtherWellKnownObjectsContainer
)

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
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) {
        Write-Verbose "Key set in: HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending. Remove it if reboot doesn't work"
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

function Test-ExchangeAdSetupObjects {

    $AdSetup = Get-ExchangeAdSetupObjects
    $schemaValue = $AdSetup["Schema"].VersionValue
    $orgValue = $AdSetup["Org"].VersionValue
    $MESOValue = $AdSetup["MESO"].VersionValue

    $exch2016Ready = "Exchange 2016 {0} Ready."
    $exch2019Ready = "Exchange 2019 {0} Ready."

    function Write-Mismatch {
        param(
            [string]$exchVersion,
            [bool]$displayMismatch = $true
        )

        if ($displayMismatch) {
            Write-Warning("Exchange {0} AD Level Failed. Mismatch detected." -f $exchVersion)
        }

        foreach ($key in $AdSetup.Keys) {
            Write-Warning("DN Value: '{0}' - Version: {1}" -f [string]($AdSetup[$key].DN), [string]($AdSetup[$key].VersionValue))
        }
        Write-Warning("More Info: https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-{0}" -f $exchVersion)
    }

    #Schema doesn't change often and and quickly tell the highest ExchangeVersion
    if ($schemaValue -lt 15332) {
        Write-Warning("Unable to determine AD Exchange Level readiness.")
        Write-Mismatch -exchVersion "Unknown" -displayMismatch $false
        return
    }
    #Exchange 2016 CU10+
    elseif ($schemaValue -eq 15332) {

        if ($MESOValue -eq 13236) {

            if ($orgValue -eq 16213) {
                Write-Host($exch2016Ready -f "CU10")
            } elseif ($orgValue -eq 16214) {
                Write-Host($exch2016Ready -f "CU11")
            } elseif ($orgValue -eq 16215) {
                Write-Host($exch2016Ready -f "CU12")
            } else {
                Write-Mismatch -exchVersion "2016"
            }
        } elseif ($MESOValue -eq 13237 -and
            $orgValue -eq 16217) {
            Write-Host($exch2016Ready -f "CU17")
        } elseif ($MESOValue -eq 13238 -and
            $orgValue -eq 16218) {
            Write-Host($exch2016Ready -f "CU18")
        } else {
            Write-Mismatch -exchVersion "2016"
        }
    } elseif ($schemaValue -eq 15333) {
        if ($MESOValue -eq 13239 -and
            $orgValue -eq 16219) {
            Write-Host($exch2016Ready -f "CU19")
        } else {
            Write-Mismatch -exchVersion "2016"
        }
    }
    #Exchange 2019 CU2+
    elseif ($schemaValue -eq 17001) {

        if ($MESOValue -eq 13237 -and
            $orgValue -eq 16754) {
            Write-Host($exch2019Ready -f "CU6")
        } elseif ($MESOValue -eq 13238 -and
            $orgValue -eq 16755) {
            Write-Host($exch2019Ready -f "CU7")
        } else {
            Write-Mismatch -exchVersion "2019"
        }
    } elseif ($schemaValue -eq 17002) {

        if ($MESOValue -eq 13239 -and
            $orgValue -eq 16756) {
            Write-Host($exch2019Ready -f "CU8")
        } else {
            Write-Mismatch -exchVersion "2019"
        }
    } else {
        Write-Mismatch -exchVersion "2019"
    }
}

#https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-2019
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
            VersionValue = $SearchResults.Properties[$VersionValueName]
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
    }

    [array]$g = GetGroupMatches $whoamiOutput "Enterprise Admins"

    if ($g.Count -gt 0) {
        $g | ForEach-Object { Write-Host "User is a member of $($_.GroupName)   $($_.SID)" }
    } else {
        Write-Warning "User is not a member of Enterprise Admins. - Only required if doing a Schema Update or PrepareAD or PrepareDomain"
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

    Test-ExchangeAdSetupObjects
}

Function Main {

    if (![string]::IsNullOrEmpty($OtherWellKnownObjectsContainer)) {

        ldifde -d $OtherWellKnownObjectsContainer -p Base -l otherWellKnownObjects -f ExchangeContainerOriginal.txt

        [array]$content = Get-Content .\ExchangeContainerOriginal.txt

        if ($null -eq $content -or
            $content.Count -eq 0) {
            throw "Failed to export ExchangeContainerOriginal.txt file"
        }

        $owkoLine = "otherWellKnownObjects:"
        $inOwkoLine = $false
        $outputLines = New-Object 'System.Collections.Generic.List[string]'
        $outputLines.Add($content[0])
        $outputLines.Add("changeType: modify")
        $outputLines.Add("replace: otherWellKnownObjects")

        Function Test-DeleteObject ([string]$TestLine) {

            if ($TestLine.Contains("CN=Deleted Objects")) {
                return $true
            }

            return $false
        }

        $index = 0
        while ($index -lt $content.Count) {
            $line = $content[$index++]

            if ($line.Trim() -eq $owkoLine) {

                if ($null -ne $testStringLine -and
                    $null -ne $possibleAdd) {

                    if (!(Test-DeleteObject $testStringLine)) {
                        $outputLines.AddRange($possibleAdd)
                    } else {
                        Write-Host "Found object to remove: $testStringLine"
                    }
                }
                $inOwkoLine = $true
                $possibleAdd = New-Object 'System.Collections.Generic.List[string]'
                $possibleAdd.Add($line)
                [string]$testStringLine = $line
                continue
            }

            if ($inOwkoLine) {
                $possibleAdd.Add($line)
                $testStringLine += $line
            }

            if ($index -eq $content.Count) {

                if (!(Test-DeleteObject $testStringLine)) {
                    $outputLines.AddRange($possibleAdd)
                } else {
                    Write-Host "Found object to remove: $testStringLine"
                }
            }
        }

        if ([string]::IsNullOrEmpty($outputLines[-1])) {
            $outputLines[-1] = "-"
        } else {
            $outputLines.Add("-")
        }

        $outputLines | Out-File -FilePath "ExchangeContainerImport.txt"

        Write-Host("`r`nVerify the results in ExchangeContainerImport.txt. Then run the following command:")
        Write-Host("`tldifde -i -f ExchangeContainerImport.txt")
        Write-Host("Run Setup.exe again afterwards.")
        return
    }

    MainUse
}

Main