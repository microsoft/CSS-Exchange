BeforeAll {
    $parent = Split-Path -Parent $PSScriptRoot
    $sut = "SetupLogReviewer.ps1"
    . "$parent\$sut" -PesterLoad

    $Script:sr = "$parent\$sut"
}

Describe "Testing SetupLogReviewer" {

    Context "Prerequisite Checks" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
            Mock Write-Output {}
            Function Test-GeneralAdditionalContext {
                param(
                    [bool]$SkipSchema = $false
                )
                Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                    -ParameterFilter { $InputObject -like "User Logged On: *" }
                Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                    -ParameterFilter { $InputObject -like "Setup Running on: *" }
                Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                    -ParameterFilter { $InputObject -like "Setup Running in Domain: *" }
                Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                    -ParameterFilter { $InputObject -like "Setup Running in AD Site Name: *" }

                if (!$SkipSchema) {
                    Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                        -ParameterFilter { $InputObject -like "Schema Master: *" }
                    Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                        -ParameterFilter { $InputObject -like "Schema Master in Domain: *" }
                }
            }
        }

        It "Prepare AD with Reboot As Well" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_AD_Prep_Reboot.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Warning `
                -ParameterFilter { $Message -eq "Setup failed to validate AD environment level. This is the internal exception that occurred:" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "Exchange organization-level objects have not been created, and setup cannot create them because the local computer is not in the same domain and site as the schema master.*" -and $ForegroundColor -eq "Yellow" }
            Assert-MockCalled -Exactly -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Computer is pending reboot based off the Windows Component is the registry" -and $ForegroundColor -eq "Red" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Additional PowerShell Sessions are open. Close them before running setup again." -and $ForegroundColor -eq "Red" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                -ParameterFilter { $InputObject -like "Schema Master in AD Site Name: *" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Unable to run setup in current domain." -and $ForegroundColor -eq "Red" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Unable to run setup in the current AD Site" -and $ForegroundColor -eq "Red" }
            Test-GeneralAdditionalContext
        }

        It "Additional Context" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_Fail_In_Child.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                -ParameterFilter { $InputObject -eq "User Logged On: CHILD\Kylo" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                -ParameterFilter { $InputObject -eq "Setup Running on: Solo-E16A.Child.Solo.net" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                -ParameterFilter { $InputObject -eq "Setup Running in Domain: Child" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                -ParameterFilter { $Inputobject -eq "Setup Running in AD Site Name: Default-First-Site-Name" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                -ParameterFilter { $InputObject -eq "Schema Master: Solo-DC1.Solo.net" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                -ParameterFilter { $InputObject -eq "Schema Master in Domain: Solo" }
        }
        It "Prepare AD Failed" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_Fail_In_Child.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -eq "Unable to run setup in current domain." -and $ForegroundColor -eq "Red" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -like "*Run setup with the /prepareAD parameter on a computer in the domain Solo and site Default-First-Site-Name, and wait for replication to complete.*" -and $ForegroundColor -eq "Yellow" }
            Assert-MockCalled -Exactly -CommandName Write-Output `
                -Scope It `
                -ParameterFilter { $Inputobject -like "Setup Running in AD Site Name*" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Warning `
                -Scope It `
                -ParameterFilter { $Message -eq "Setup failed to validate AD environment level. This is the internal exception that occurred:" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Output `
                -ParameterFilter { $InputObject -like "Schema Master in AD Site Name: *" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Computer is pending reboot based off the Session Manager is the registry" -and $ForegroundColor -eq "Red" }
            Test-GeneralAdditionalContext
        }

        It "No ORG Man" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_ADUpdated_NoOrgMan.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -eq "User SOLO\Kylo isn't apart of Organization Management group." -and $ForegroundColor -eq "Red" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -eq "Looking to be in this group SID: S-1-5-21-2947011988-2654620456-2749465584-1105" }
            Test-GeneralAdditionalContext -SkipSchema $true
        }

        It "First Server Run - No ORG Man" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_FirstRun_NoOrgMan.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -Scope It `
                -ParameterFilter { $Object -eq "Didn't find the user to be in ExOrgAdmin, but didn't find the SID for the group either. Suspect /PrepareAD hasn't been run yet." -and $ForegroundColor -eq "Yellow" }
        }

        It "Schema Admins group" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_NoPerm.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "/PrepareSchema is required and user SOLO\Kylo isn't apart of the Schema Admins group." -and $ForegroundColor -eq "Red" }
            Test-GeneralAdditionalContext
        }

        It "Reboot Pending" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_Reboot_Pending.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "Computer is pending reboot based off the Windows Component is the registry" -and $ForegroundColor -eq "Red" }
        }

        It "Enterprise Admins Group" {
            & $sr -SetupLog "$PSScriptRoot\PrerequisiteCheck\ExchangeSetup_SchemaAdmin_PrepareSchema.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "/PrepareSchema is required and user SOLO\Kylo isn't apart of the Enterprise Admins group." -and $ForegroundColor -eq "Red" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "/PrepareAD is required and user SOLO\Kylo isn't apart of the Enterprise Admins group." -and $ForegroundColor -eq "Red" }
            Test-GeneralAdditionalContext
        }
    }

    Context "Known Issues" {
        BeforeEach {
            Mock Write-Host {}
            Mock Write-Warning {}
        }

        It "MESG was deleted" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetupmsExchangeSecurityGroupsContainerDeleted.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t'OU=Microsoft Exchange Security Groups' was deleted from the root of the domain. We need to have it created again at the root of the domain to continue." }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*System.NullReferenceException*" -and $ForegroundColor -eq "Yellow" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*at Microsoft.Exchange.Management.Tasks.InitializeExchangeUniversalGroups.CreateOrMoveEWPGroup(ADGroup ewp, ADOrganizationalUnit usgContainer)" -and $ForegroundColor -eq "Yellow" }
        }

        It "Failed to import schema" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup-PrepareSchema-8245.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tFailed to import schema setting from file 'C:\Windows\Temp\ExchangeSetup\Setup\Data\PostExchange2003_schema80.ldf'" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tReview ldif.err file 'C:\Users\Han\AppData\Local\Temp\ldif.err' to help determine which object in the file 'C:\Windows\Temp\ExchangeSetup\Setup\Data\PostExchange2003_schema80.ldf' was trying to be imported that was causing problems." }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tIf you can't find the ldf file in the C:\Windows\Temp location, then find the file in the ISO." }
        }

        It "Wrong Group Type" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetupWrongGroupType.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $object -eq "`t- Change the CN=Exchange Servers,OU=Test,DC=Solo,DC=local object to Universal, SecurityEnabled" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Another problem can be that the group is set correctly, but is mail enabled and shouldn't be." }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $object -like "`*The well-known object entry with the GUID `"6c01d2a7-f083-4503-8132-789eeb127b84`"*" -and $ForegroundColor -eq "Yellow" }
        }

        It "Invalid Well Known Objects Exception" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\OrganizationPreparation\ExchangeSetup_InvalidWKObjectException.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=Solo,DC=local points to an invalid DN or a deleted object*" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Run the SetupAssist.ps1 script with '-OtherWellKnownObjects' to be able address deleted objects type" }
        }

        It "INSUFF_ACCESS_RIGHTS CN=Microsoft Exchange System Objects" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\OrganizationPreparation\ExchangeSetup_AccessDenied.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Used domain controller Solo-DC1.Solo.local to read object CN=Microsoft Exchange System Objects,DC=Solo,DC=local*" }
            Assert-MockCalled -Exactly 3 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Active directory response: 00000005: SecErr: DSID-03152857, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0*" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tWe failed to have the correct permissions to write ACE to 'CN=Microsoft Exchange System Objects,DC=Solo,DC=local' as the current user SOLO\Han" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Make sure there are no denies for this user on the object" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- By default Enterprise Admins and BUILTIN\Administrators give you the rights to do this action (dsacls 'write permissions')" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- If unable to determine the cause, you can apply FULL CONTROL to 'CN=Microsoft Exchange System Objects,DC=Solo,DC=local' for the user SOLO\Han" }
        }

        It "Certificate has expired" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Certificate_Expired.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tCertificate: CN=mail.Solo.dom, OU=IT, O=John Doe, L=Pester, C=DE has expired." }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tCertificate expired on: 3/20/2020 12:00:00 PM." }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tPlease replace it, reboot the server and run setup again." }
        }

        It "Services Disabled" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Service_Disabled.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*System.ComponentModel.Win32Exception: The service cannot be started, either because it is disabled or because it has no enabled devices associated with it*" -and $ForegroundColor -eq "Yellow" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tRequired Exchange Services are failing to start because it appears to be disabled or dependent services are disabled. Enable them and try again" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tNOTE: Might need to do this often while setup is running" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tExample Command: Get-Service MSExchange* | Set-Service -StartupType Automatic" }
        }

        It "Missing PF Object" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\ExchangeSetup_Missing_PF_Object.log"
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Active Directory operation failed on DC2.Solo.local. The object 'CN=Folder Hierarchies,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=SoloORG,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=Solo,DC=local' already exists.*" -and $ForegroundColor -eq "Yellow" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tPublic Folder Object needs to be created" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Open ADSIEDIT and go to this location'CN=Folder Hierarchies,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=SoloORG,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=Solo,DC=local'" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Right Click select New - Object" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Select mxExchPFTree" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Enter any value for the cn (Common Name) value, such as PF" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Right-click the newly created msExchPFTree object and select Properties" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- On the Attribute Editor tab, click msExchPFTreeType, and then click Edit." }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- In the Value box type 1, and then click OK two times." }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`t- Exit and wait for AD Replication" }
        }

        It "MSI Issue 1" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\MsiIssues\ExchangeSetup_MSI_1.log"
            Assert-MockCalled -Exactly 4 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Couldn't remove product with code 8466eaed-7024-4aee-9d13-f3a55b98d114. The installation source for this product is not available. Verify that the source exists and that you can access it. Error code is 1612*" -and $ForegroundColor -eq "Yellow" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tNeed to run FixInstallerCache.ps1 against 15.0.995.29" }
        }

        It "MSI Issue 2" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\MsiIssues\ExchangeSetup_MSI_2.log"
            Assert-MockCalled -Exactly 3 -CommandName Write-Host `
                -ParameterFilter { $Object -like "*Installing product D:\cu23\Setup\ServerRoles\UnifiedMessaging\MSSpeech_SR_TELE.zh-CN.msi failed. The installation source for this product is not available. Verify that the source exists and that you can access it. Error code is 1612." -and $ForegroundColor -eq "Yellow" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tNeed to run FixInstallerCache.ps1 against 15.0.1367.3" }
        }

        It "MSI Issue 3" {
            & $sr -SetupLog "$PSScriptRoot\KnownIssues\MsiIssues\ExchangeSetup_MSI_3.log"
            Assert-MockCalled -Exactly 3 -CommandName Write-Host `
                -ParameterFilter { $Object -like "* Installing product C:\ExchangeCU23\exchangeserver.msi failed. Fatal error during installation. Error code is 1603." -and $ForegroundColor -eq "Yellow" }
            Assert-MockCalled -Exactly 1 -CommandName Write-Host `
                -ParameterFilter { $Object -eq "`tNeed to run FixInstallerCache.ps1 against 15.0.1130.7" }
        }
    }
}