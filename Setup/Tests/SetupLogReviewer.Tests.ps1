# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# PesterPriority: High
BeforeAll {
    $parent = Split-Path -Parent $PSScriptRoot
    $parent = [IO.Path]::Combine($parent, "SetupLogReviewer")
    $sut = "SetupLogReviewer.ps1"
    $Script:sr = "$parent\$sut"
}

Describe "Testing SetupLogReviewer" {

    Context "Prerequisite Checks" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
            Mock Write-Host {}
            function Test-GeneralAdditionalContext {
                param(
                    [bool]$SkipSchema = $false
                )
                Should -Invoke -Exactly 1 -CommandName Write-Host `
                    -ParameterFilter { $Object -like "User Logged On: *" }
                Should -Invoke -Exactly 1 -CommandName Write-Host `
                    -ParameterFilter { $Object -like "Setup Running on: *" }
                Should -Invoke -Exactly 1 -CommandName Write-Host `
                    -ParameterFilter { $Object -like "Setup Running in Domain: *" }
                Should -Invoke -Exactly 1 -CommandName Write-Host `
                    -ParameterFilter { $Object -like "Setup Running in AD Site Name: *" }

                if (!$SkipSchema) {
                    Should -Invoke -Exactly 1 -CommandName Write-Host `
                        -ParameterFilter { $Object -like "Schema Master: *" }
                    Should -Invoke -Exactly 1 -CommandName Write-Host `
                        -ParameterFilter { $Object -like "Schema Master in Domain: *" }
                }
            }
        }

        It "Prepare AD with Reboot and Remote Registry As Well" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_AD_Prep_Reboot.log"
            Should -Invoke -Exactly 1 -CommandName Write-Warning `
                -ParameterFilter { $Message -eq "Setup failed to validate AD environment level. This is the internal exception that occurred:" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "Exchange organization-level objects have not been created, and setup cannot create them because the local computer is not in the same domain and site as the schema master.*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Computer is pending reboot based off the Windows Component is the registry" -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Additional PowerShell Sessions are open. Close them before running setup again." -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "Schema Master in AD Site Name: *" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Unable to run setup in current domain." -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Unable to run setup in the current AD Site" -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Failed to run '[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName)' on this computer causing setup to fail" -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "The MSDTC Service is currently stopped. Start it before running setup again." -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "IIS URL Rewrite is not installed on the computer. Install it before running setup again." -and $ForegroundColor -eq "Red" }
            Test-GeneralAdditionalContext
        }

        It "Additional Context" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_Fail_In_Child.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "User Logged On: CHILD\Han" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Setup Running on: Solo-E16A.Child.Solo.net" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Setup Running in Domain: Child" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Setup Running in AD Site Name: Default-First-Site-Name" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Schema Master: Solo-DC1.Solo.net" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Schema Master in Domain: Solo" }
        }
        It "Prepare AD Failed" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_Fail_In_Child.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -eq "Unable to run setup in current domain." -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -like "*Run setup with the /prepareAD parameter on a computer in the domain Solo and site Default-First-Site-Name, and wait for replication to complete.*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -like "Setup Running in AD Site Name*" }
            Should -Invoke -Exactly 1 -CommandName Write-Warning `
                -Scope It `
                -ParameterFilter { $Message -eq "Setup failed to validate AD environment level. This is the internal exception that occurred:" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "Schema Master in AD Site Name: *" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Computer is pending reboot based off the Session Manager is the registry" -and $ForegroundColor -eq "Red" }
            Test-GeneralAdditionalContext
        }

        It "No ORG Man" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_ADUpdated_NoOrgMan.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -eq "User SOLO\Han isn't apart of Organization Management group." -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -eq "Looking to be in this group SID: S-1-5-21-2947011988-2654620456-2749465584-1105" }
            Test-GeneralAdditionalContext -SkipSchema $true
        }

        It "First Server Run - No ORG Man" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_FirstRun_NoOrgMan.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -eq "Didn't find the user to be in ExOrgAdmin, but didn't find the SID for the group either. Suspect /PrepareAD hasn't been run yet." -and $ForegroundColor -eq "Yellow" }
        }

        It "Schema Admins group" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_NoPerm.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "/PrepareSchema is required and user SOLO\Han isn't apart of the Schema Admins group." -and $ForegroundColor -eq "Red" }
            Test-GeneralAdditionalContext
        }

        It "Reboot Pending" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_Reboot_Pending.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Computer is pending reboot based off the Windows Component is the registry" -and $ForegroundColor -eq "Red" }
        }

        It "Enterprise Admins Group" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_SchemaAdmin_PrepareSchema.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "/PrepareSchema is required and user SOLO\Han isn't apart of the Enterprise Admins group." -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "/PrepareAD is required and user SOLO\Han isn't apart of the Enterprise Admins group." -and $ForegroundColor -eq "Red" }
            Test-GeneralAdditionalContext
        }

        It "Domain Prep Required" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_DomainPrepRequired.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Local Domain Is Not Prepped or might have duplicate MESO Containers" -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run SetupAssist on the server to determine the problem and correct action plan." }
        }

        It "DC Out of Site - 1" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\DCOutOfSite\ExchangeSetup_DC_Site_1.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Selected domain controller that isn't in the same site as the Exchange Server." -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`r`nDomain Controller: 'DC2.Solo.local'" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Domain Controller Site: 'NULL VALUE'" }
            Test-GeneralAdditionalContext -SkipSchema $true
        }

        It "DC Out of Site - 2" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\DCOutOfSite\ExchangeSetup_DC_Site_2.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Selected domain controller that isn't in the same site as the Exchange Server." -and $ForegroundColor -eq "Red" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`r`nDomain Controller: 'DC2.Child.Solo.local'" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Domain Controller Site: 'SiteA'" }
        }
    }

    Context "Known Issues" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
        }

        It "Microsoft Exchange Security Group was deleted" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetupMsExchangeSecurityGroupsContainerDeleted.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*OU=Microsoft Exchange Security Groups' was deleted from the root of the domain. We need to have it created again at the root of the domain to continue." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*System.NullReferenceException*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*at Microsoft.Exchange.Management.Tasks.InitializeExchangeUniversalGroups.CreateOrMoveEWPGroup(ADGroup ewp, ADOrganizationalUnit usgContainer)" -and $ForegroundColor -eq "Yellow" }
        }

        It "Failed to import schema" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup-PrepareSchema-8245.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tFailed to import schema setting from file 'C:\Windows\Temp\ExchangeSetup\Setup\Data\PostExchange2003_schema80.ldf'" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tReview ldif.err file 'C:\Users\Han\AppData\Local\Temp\ldif.err' to help determine which object in the file 'C:\Windows\Temp\ExchangeSetup\Setup\Data\PostExchange2003_schema80.ldf' was trying to be imported that was causing problems." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tIf you can't find the ldf file in the C:\Windows\Temp location, then find the file in the ISO." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*There was an error while running 'ldifde.exe' to import the schema file 'C:\Windows\Temp\ExchangeSetup\Setup\Data\PostExchange2003_schema80.ldf'. The error code is: 8245.*" -and $ForegroundColor -eq "Yellow" }
        }

        It "Wrong Group Type" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetupWrongGroupType.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $object -eq "`t- Change the CN=Exchange Servers,OU=Test,DC=Solo,DC=local object to Universal, SecurityEnabled" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Another problem can be that the group is set correctly, but is mail enabled and shouldn't be." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $object -like "`*The well-known object entry with the GUID `"6c01d2a7-f083-4503-8132-789eeb127b84`"*" -and $ForegroundColor -eq "Yellow" }
        }

        It "Invalid Well Known Objects Exception" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\OrganizationPreparation\ExchangeSetup_InvalidWKObjectException.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=Solo,DC=local points to an invalid DN or a deleted object*" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run the SetupAssist.ps1 script to address the deleted objects type" }
        }

        It "INSUFF_ACCESS_RIGHTS CN=Microsoft Exchange System Objects" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\OrganizationPreparation\ExchangeSetup_AccessDenied.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Used domain controller Solo-DC1.Solo.local to read object CN=Microsoft Exchange System Objects,DC=Solo,DC=local*" }
            Should -Invoke -Exactly 3 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Active directory response: 00000005: SecErr: DSid-03152857, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0*" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tWe failed to have the correct permissions to write ACE to 'CN=Microsoft Exchange System Objects,DC=Solo,DC=local' as the current user SOLO\Han" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Make sure there are no denies for this user on the object" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- By default Enterprise Admins and BUILTIN\Administrators give you the rights to do this action (dsAcls 'write permissions')" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- If unable to determine the cause, you can apply FULL CONTROL to 'CN=Microsoft Exchange System Objects,DC=Solo,DC=local' for the user SOLO\Han" }
        }

        It "Certificate has expired" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Certificate_Expired.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tCertificate: CN=mail.Solo.dom, OU=IT, O=John Doe, L=Pester, C=DE has expired." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tCertificate expired on: 3/20/2020 12:00:00 PM." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tPlease replace it, reboot the server and run setup again." }
        }

        It "Services Disabled" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Service_Disabled.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*System.ComponentModel.Win32Exception: The service cannot be started, either because it is disabled or because it has no enabled devices associated with it*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tRequired Exchange Services are failing to start because it appears to be disabled or dependent services are disabled. Enable them and try again" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tNOTE: Might need to do this often while setup is running" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tExample Command: Get-Service MSExchange* | Set-Service -StartupType Automatic" }
        }

        It "Missing PF Object" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Missing_PF_Object.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Active Directory operation failed on DC2.Solo.local. The object 'CN=Folder Hierarchies,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=SoloORG,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=Solo,DC=local' already exists.*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tPublic Folder Object needs to be created" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Open AdsiEdit and go to this location'CN=Folder Hierarchies,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=SoloORG,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=Solo,DC=local'" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Right Click select New - Object" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Select mxExchPFTree" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Enter any value for the cn (Common Name) value, such as PF" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Right-click the newly created msExchPFTree object and select Properties" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- On the Attribute Editor tab, click msExchPFTreeType, and then click Edit." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- In the Value box type 1, and then click OK two times." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Exit and wait for AD Replication" }
        }

        It "MSI Issue 1" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\MsiIssues\ExchangeSetup_MSI_1.log"
            Should -Invoke -Exactly 4 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Couldn't remove product with code 8466eaed-7024-4aee-9d13-f3a55b98d114. The installation source for this product is not available. Verify that the source exists and that you can access it. Error code is 1612*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run FixInstallerCache.ps1 against 15.0.995.29" }
        }

        It "MSI Issue 2" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\MsiIssues\ExchangeSetup_MSI_2.log"
            Should -Invoke -Exactly 3 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Installing product D:\cu23\Setup\ServerRoles\UnifiedMessaging\MSSpeech_SR_TEL.zh-CN.msi failed. The installation source for this product is not available. Verify that the source exists and that you can access it. Error code is 1612." -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run FixInstallerCache.ps1 against 15.0.1367.3" }
        }

        It "MSI Issue 3" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\MsiIssues\ExchangeSetup_MSI_3.log"
            Should -Invoke -Exactly 3 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* Installing product C:\ExchangeCU23\exchangeServer.msi failed. Fatal error during installation. Error code is 1603." -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run FixInstallerCache.ps1 against 15.0.1130.7" }
        }

        It "MSI Issue 4" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\MsiIssues\ExchangeSetup_MSI_4.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Installing a new product. Package: N:\en\ServerLanguagePack.msi. Property values*" }
            Should -Invoke -Exactly 4 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Object reference not set to an instance of an object." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run FixInstallerCache.ps1 against 15.1.1913.5" }
        }

        It "MSI Issue 5" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\MsiIssues\ExchangeSetup_MSI_5.log"
            Should -Invoke -Exactly 4 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Unable to remove product with code c3f10d8c-bd70-4516-b2b4-bf6901980741. Fatal error during installation. Error code is 1603.*" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run FixInstallerCache.ps1 against 15.1.2242.4" }
        }

        It "Arbitration Mailbox UPN" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Arbitration_UPN.log"
            Should -Invoke -Exactly 2 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Microsoft.Exchange.Data.Directory.ADConstraintViolationException: An Active Directory Constraint Violation error occurred on DC2.Solo.local. Additional information: The operation failed because UPN value provided for addition/modification is not unique forest-wide.*" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*This is a known issue, however, we are still investigating as to why this issue is occurring in some environments. Please email 'ExToolsFeedback@microsoft.com' ASAP to investigate this issue." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Do NOT remove the arbitration mailboxes/accounts as they may contain critical information for your environment." }
        }

        It "ServiceControl Reverse Error" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_ServiceControl_Reverse.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*System.Management.Automation.MethodInvocationException*" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*1. Find the ServiceControl.ps1 in the Exchange Bin Directory" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*2. Find the following line in the script, within the StopServices function:" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*`$services = Get-ServiceToControl `$Roles -Active" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*3. Add in the following:" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*if (`$services -eq `$null) { return `$true }" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*4. Save the file and try to run Setup again." }
        }
    }

    Context "Good Test Case" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
            Mock Write-Host {}
        }

        It "Good Run Of Setup" {
            & $sr -SetupLog "$PSScriptRoot\ExchangeSetup_Good.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "The most recent setup attempt completed successfully based off this line:" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "[04/02/2021 22:15:23.0126] [0] The Exchange Server setup operation completed successfully." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`r`nNo Action is required." }
        }
    }

    Context "Virtual Directory" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
        }

        AfterEach {
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run SetupAssist on the server and address the issues it calls out with the virtual directories." }
        }

        It "Virtual Directory 1" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\VirtualDirectories\ExchangeSetup_VDir_1.log"
            Should -Invoke -Exactly 5 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*The operation couldn't be performed because object 'ExSvr1\OWA (Exchange Back End)' couldn't be found on 'DC2.Solo.local'." -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException: The operation couldn't be performed because object 'ExSvr1\OWA (Exchange Back End)' couldn't be found on*" -and $ForegroundColor -eq "Yellow" }
        }

        It "Virtual Directory 2" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\VirtualDirectories\ExchangeSetup_VDir_2.log"
            Should -Invoke -Exactly 6 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*The virtual directory 'PushNotifications' already exists under 'ExSvr1.child.SoloORG.COM/Exchange Back End'." -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"System.ArgumentException: The virtual directory 'PushNotifications' already exists under 'ExSvr1.child.SoloORG.COM/Exchange Back End'." -and $ForegroundColor -eq "Yellow" }
        }

        It "Virtual Directory 3" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\VirtualDirectories\ExchangeSetup_VDir_3.log"
            Should -Invoke -Exactly 6 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Process execution failed with exit code 50." -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"Microsoft.Exchange.Configuration.Tasks.TaskException: Process execution failed with exit code 50." -and $ForegroundColor -eq "Yellow" }
        }
    }

    Context "Error Reference" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
        }

        It "FIPS Access Denied" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_FIPS_AccessDenied.log"
            Should -Invoke -Exactly 2 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "[03/11/2021 12:06:22.0926] [2] [ERROR] Upgrade of Configuration.xml was unsuccessful, Exception calling `"Upgrade`" with `"0`" argument(s): `"Access to the path is denied.`"" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Failed to access the path and upgrade '\V15\FIP-FS\Data\Configuration.xml'" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Check access rights to this location OR use PROCMON to determine why this is occurring." }
        }

        It "Multiple Active Sync Virtual Directories" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Multi_EAS_VDirs.log"
            Should -Invoke -Exactly 2 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Cannot convert 'System.Object*' to the type 'Microsoft.Exchange.Configuration.Tasks.VirtualDirectoryIdParameter' required by parameter 'Identity'*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Remove the secondary virtual directory that is custom on the server." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*NOTE: You should only return one value when running the following cmdlet on the server:" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Get-ActiveSyncVirtualDirectory -Server `$env:ComputerName" }
        }
    }

    Context "Error Context" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
        }

        It "Missing Grammars Directory" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_MissingDirectory.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"System.Management.Automation.ItemNotFoundException: Cannot find path 'C:\Program Files\Microsoft\Exchange Server\V15\UnifiedMessaging\grammars' because it does not exist." -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Create the directory: `"C:\Program Files\Microsoft\Exchange Server\V15\UnifiedMessaging\grammars`"" }
        }

        It "Firewall Endpoint Mapper" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Firewall_Endpoint.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"System.Runtime.InteropServices.COMException (0x800706D9): There are no more endpoints available from the endpoint mapper. (Exception from HRESULT: 0x800706D9)" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* at Interop.NetFw.INetFwRules.Add(NetFwRule rule)" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Start the Windows Firewall Service, as this is required to run setup." }
        }

        It "Failed Mount Database" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Failed_Mount_Database.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"System.InvalidOperationException: Failed to mount database `"ExSvr1 - DB1`". Error: An Active Manager operation failed. Error: The database action failed.*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* at Microsoft.Exchange.Data.Storage.ActiveManager.AmRpcClientHelper.MountDatabaseDirectEx(String serverToRpc, Guid dbGuid, AmMountArg mountArg)" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Determine why you aren't able to mount the database and have it mounted prior to running setup again." }
        }

        It "Search Foundation Failure - Upgrade" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Search_Foundation_Failure.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"System.Exception: Failure configuring SearchFoundation through InstallConfig.ps1*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 2 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*at Microsoft.Ceres.Exchange.PostSetup.DeploymentManager.WaitForAdminNode(String hostControllerNetTcpWcfUrl)" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*- Make sure the Microsoft Exchange Search Host Controller and Microsoft Exchange Search service is not disabled and started." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*- Make sure that all 4 noderunner.exe processes are able to start and run. If they aren't able to troubleshoot that." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*- Try to manually configure the Search Foundation by following these steps, and troubleshoot why it might be failing before trying setup again:" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* 1. Stop the Microsoft Exchange Search and Microsoft Exchange Search Host Controller services." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* 2. Remove all SubFolders under C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data\Nodes\Fsis" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* 3. Open Powershell as Administrator and navigate to the folder C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Installer" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* 4. Now uninstall the Search Foundation with this command: .\InstallConfig.ps1 -action U -DataFolder `"C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data`"" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* 5. Now install the Search Foundation with this command: .\InstallConfig.ps1 -action I -DataFolder `"C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data`"" }
        }

        It "Search Foundation Failure - Install" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Search_Foundation_Failure_Install.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"System.Exception: Failure configuring SearchFoundation through InstallConfig.ps1*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 2 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Old nodes belonging to the system 'Fsis', already exist in*" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*- Make sure the Microsoft Exchange Host Controller and Microsoft Exchange Search service is not running and not disabled." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*- Uninstall the Search Foundation" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* 1. Remove all SubFolders under C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data\Nodes\Fsis" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* 2. Open Powershell as Administrator and navigate to the folder C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\Installer" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* 3. Now uninstall the Search Foundation with this command: .\InstallConfig.ps1 -action U -DataFolder `"C:\Program Files\Microsoft\Exchange Server\V15\Bin\Search\Ceres\HostController\Data`"" }
        }

        It "Missing HomeMdb" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Missing_HomeMdb.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "[03/07/2021 16:22:39.0469] [2] [ERROR] Database is mandatory on UserMailbox." -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Missing homeMdb on critical mailbox. Run SetupAssist.ps1 to find all problem mailboxes that needs to be addressed." }
        }

        It "Install from bin" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_InstallFromBin.log"
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*was run: `"System.Management.Automation.CommandNotFoundException: The term 'D:\Program Files\Microsoft\Exchange Server\V15\Bin\ManageScheduledTask.ps1'*" -and $ForegroundColor -eq "Yellow" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run Setup again, but when using powershell.exe you MUST USE '.\' prior to setup.exe." }
        }
    }

    Context "Unable to set Shared Config DC" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
        }

        It "No Suitable Directory Services Found" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_NoSuitableDC.log"

            # splat doesn't work for pester for some reason.
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Unable to set shared config DC*'TopologyClientTcpEndpoint (localhost)' returned an error. Error details No Suitable Directory Servers Found*" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*It appears that the Microsoft Exchange Active Directory Topology service was started on the server and we ran into a different inner exception." }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*NOTE: It is common that the service will not stay started after the initial failure, make sure you keep the Microsoft Exchange Active Directory Topology service running during the entire setup process" }
        }

        It "AD Topology Service Not Started" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_ADServiceNotStarted.log"

            # cspell:disable
            $serviceStopLine = "Unable to set shared config DC.*Topology Provider coundn't find the Microsoft Exchange Active Directory Topology service on end point 'TopologyClientTcpEndpoint (localhost)'."
            # cspell:enable

            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*$serviceStopLine" }
            Should -Invoke -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*MAKE SURE IT IS RUNNING DURING THE WHOLE SETUP AFTER COPYING FILES" }
        }
    }
}
