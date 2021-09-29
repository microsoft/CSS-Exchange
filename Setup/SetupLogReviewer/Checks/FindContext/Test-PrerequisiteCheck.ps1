# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-WriteObject.ps1
Function Test-PrerequisiteCheck {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $foundKnownIssue = $false

        $adValidationError = $SetupLogReviewer |
            SelectStringLastRunOfExchangeSetup -Pattern "\[ERROR\] Setup encountered a problem while validating the state of Active Directory: (.*) See the Exchange setup log for more information on this error."

        if ($adValidationError) {
            New-WriteObject -WriteType "Warning" -WriteData "Setup failed to validate AD environment level. This is the internal exception that occurred:"
            New-WriteObject $adValidationError.Matches.Groups[1].Value -ForegroundColor "Yellow"
            $returnNow = $true
        }

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule -SettingName "PendingRebootWindowsComponents" -SettingOrRule "Rule") -eq "True") {
            New-WriteObject "Computer is pending reboot based off the Windows Component is the registry" -ForegroundColor "Red"
            $returnNow = $true
        }

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule -SettingName "RebootPending" -SettingOrRule "Rule") -eq "True") {
            New-WriteObject "Computer is pending reboot based off the Session Manager is the registry" -ForegroundColor "Red"
            $returnNow = $true
        }

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule -SettingName "ProcessNeedsToBeClosedOnUpgrade" -SettingOrRule "Rule") -eq "True") {
            New-WriteObject "Additional PowerShell Sessions are open. Close them before running setup again." -ForegroundColor "Red"
            $returnNow = $true
        }

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule -SettingName "DomainControllerIsOutOfSite" -SettingOrRule "Rule") -eq "True") {
            New-WriteObject "Selected domain controller that isn't in the same site as the Exchange Server." -ForegroundColor "Red"
            $returnNow = $true
            $domainController = $SetupLogReviewer | GetEvaluatedSettingOrRule "DomainController" "Setting" "."
            $domainControllerSite = $SetupLogReviewer | GetEvaluatedSettingOrRule "DomainControllerSiteName" "Setting" "."

            if ($null -ne $domainController) {
                $dcValue = $domainController.Matches.Groups[1].Value
            } else {
                $dcValue = "Failed to find DC Value"
            }

            if ($null -ne $domainControllerSite) {
                $dcSite = $domainControllerSite.Matches.Groups[1].Value
            } else {
                $dcSite = "NULL VALUE"
            }
            if ($null -ne $domainController -or
                $null -ne $domainControllerSite) {
                New-WriteObject "`r`nDomain Controller: '$dcValue'"
                New-WriteObject "Domain Controller Site: '$dcSite'"
            }
        }

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule -SettingName "RemoteRegException" -SettingOrRule "Rule") -eq "True") {
            New-WriteObject "Failed to run '[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName)' on this computer causing setup to fail" -ForegroundColor "Red"
            $returnNow = $true
        }

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule -SettingName "MSDTCStopped" -SettingOrRule "Rule") -eq "True") {
            New-WriteObject "The MSDTC Service is currently stopped. Start it before running setup again." -ForegroundColor "Red"
        }

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule -SettingName "IISURLRewriteNotInstalled" -SettingOrRule "Rule") -eq "True") {
            New-WriteObject "IIS URL Rewrite is not installed on the computer. Install it before running setup again." -ForegroundColor "Red"
        }

        if ($returnNow) {
            $foundKnownIssue = $true
            return
        }

        $schemaUpdateRequired = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "Schema Update Required Status : '(\w+)'."
        $orgConfigUpdateRequired = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "Organization Configuration Update Required Status : '(\w+)'."
        $domainConfigUpdateRequired = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "Domain Configuration Update Required Status : '(\w+)'."

        if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer | TestEvaluatedSettingOrRule "SchemaAdmin") -eq "False") {
            New-WriteObject "/PrepareSchema is required and user $($SetupLogReviewer.User) isn't apart of the Schema Admins group." -ForegroundColor "Red"
            $foundKnownIssue = $true
        }

        if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer | TestEvaluatedSettingOrRule "EnterpriseAdmin") -eq "False") {
            New-WriteObject "/PrepareSchema is required and user $($SetupLogReviewer.User) isn't apart of the Enterprise Admins group." -ForegroundColor "Red"
            $foundKnownIssue = $true
        }

        if ($orgConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer | TestEvaluatedSettingOrRule "EnterpriseAdmin") -eq "False") {
            New-WriteObject "/PrepareAD is required and user $($SetupLogReviewer.User) isn't apart of the Enterprise Admins group." -ForegroundColor "Red"
            $foundKnownIssue = $true
        }

        if ($domainConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer | TestEvaluatedSettingOrRule "EnterpriseAdmin") -eq "False") {
            New-WriteObject "/PrepareDomain needs to be run in this domain, but we actually require Enterprise Admin group to properly run this command." -ForegroundColor "Red"
            $foundKnownIssue = $true
        }

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule "ExOrgAdmin") -eq "False") {
            $sid = $SetupLogReviewer | GetEvaluatedSettingOrRule "SidExOrgAdmins" "Setting" "."
            Write-Verbose "PrerequisiteCheck - Didn't find ExOrgAdmin"

            if ($null -ne $sid) {

                if (($SetupLogReviewer | TestEvaluatedSettingOrRule "DelegatedMailboxFirstInstall"  "Rule") -eq "True") {
                    New-WriteObject "User $($SetupLogReviewer.User) isn't apart of Organization Management group." -ForegroundColor "Red"
                    New-WriteObject "Looking to be in this group SID: $($sid.Matches.Groups[1].Value)" -ForegroundColor "Red"
                    $foundKnownIssue = $true
                } else {
                    Write-Verbose "PrerequisiteCheck - appears to be a delegated setup"
                }
            } else {
                Write-Verbose "PrerequisiteCheck - didn't find SID of ExOrgAdmin"
                New-WriteObject "Didn't find the user to be in ExOrgAdmin, but didn't find the SID for the group either. Suspect /PrepareAD hasn't been run yet." -ForegroundColor "Yellow"
            }
        }

        Write-Verbose "PrerequisiteCheck - no known issue"
    }
    end {

        if ($foundKnownIssue) {
            New-WriteObject "`r`nAdditional Context:"
            New-WriteObject "User Logged On: $($setupLogReviewer.User)"

            $serverFQDN = $setupLogReviewer | GetEvaluatedSettingOrRule "ComputerNameDnsFullyQualified" "Setting" "."

            if ($null -ne $serverFQDN) {
                $serverFQDN = $serverFQDN.Matches.Groups[1].Value
                New-WriteObject "Setup Running on: $serverFQDN"
                $setupDomain = $($serverFQDN.Split('.')[1])
                New-WriteObject "Setup Running in Domain: $setupDomain"
            }

            $siteName = $setupLogReviewer | GetEvaluatedSettingOrRule "SiteName" "Setting" "."

            if ($null -ne $siteName) {
                $siteName = $siteName.Matches.Groups[1].Value
                New-WriteObject "Setup Running in AD Site Name: $siteName"
            }

            $schemaMaster = $setupLogReviewer | SelectStringLastRunOfExchangeSetup -Pattern "Setup will attempt to use the Schema Master domain controller (.+)"

            if ($null -ne $schemaMaster) {
                New-WriteObject "----------------------------------"
                New-WriteObject "Schema Master: $($schemaMaster.Matches.Groups[1].Value)"
                $smDomain = $schemaMaster.Matches.Groups[1].Value.Split(".")[1]
                New-WriteObject "Schema Master in Domain: $smDomain"
                $schemaSiteName = [string]::Empty
                $siteNameSls = $setupLogReviewer | SelectStringLastRunOfExchangeSetup -Pattern "on a computer in the domain (\w+) and site (.+)\, and wait for replication to complete"

                if ($null -ne $siteNameSls) {
                    $schemaSiteName = $siteNameSls.Matches.Groups[2].Value
                    New-WriteObject "Schema Master in AD Site Name: $schemaSiteName"
                }

                if ($smDomain -ne $setupDomain) {
                    New-WriteObject "Unable to run setup in current domain." -ForegroundColor "Red"
                }

                if ($schemaSiteName -ne [string]::Empty -and
                    $schemaSiteName -ne $siteName) {
                    New-WriteObject "Unable to run setup in the current AD Site" -ForegroundColor "Red"
                }
            }
        }
    }
}
