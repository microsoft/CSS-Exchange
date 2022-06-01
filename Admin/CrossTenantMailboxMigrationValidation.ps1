# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 5.1
#Requires -Modules AzureAD, ExchangeOnlineManagement

<#
.SYNOPSIS
    This script offers the ability to validate users and org settings related to the Cross-tenant mailbox migration before creating a migration batch and have a better experience.
.DESCRIPTION
    This script is intended to be used for:
    - Making sure the source mailbox object is a member of the Mail-Enabled Security Group defined on the MailboxMovePublishedScopes of the source organization relationship
    - Making sure the source mailbox object ExchangeGuid attribute value matches the one from the target MailUser object
    - Making sure the source mailbox object ArchiveGuid attribute (if there's an Archive enabled) value matches the one from the target MailUser object
    - Making sure the source mailbox object has no auxArchives
    - Making sure the source mailbox object TotalDeletedItemsSize is not bigger than Target MailUser recoverable items size
    - Making sure the source mailbox object LegacyExchangeDN attribute value is present on the target MailUser object as an X500 proxyAddress
    - Making sure the target MailUser object PrimarySMTPAddress attribute value is part of the target tenant accepted domains and give you the option to set it to be like the UPN if not true
    - Making sure the target MailUser object EmailAddresses are all part of the target tenant accepted domains and give you the option to remove them if any doesn't belong to are found
    - Making sure the target MailUser object ExternalEmailAddress attribute value points to the source Mailbox object PrimarySMTPAddress and give you the option to set it if not true
    - Checking if there's an AAD app as described on https://docs.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-destination-tenant-by-creating-the-migration-application-and-secret
    - Checking if the target tenant has an Organization Relationship as described on https://docs.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-tenant-by-creating-the-exchange-online-migration-endpoint-and-organization-relationship
    - Checking if the target tenant has a Migration Endpoint as described on https://docs.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-tenant-by-creating-the-exchange-online-migration-endpoint-and-organization-relationship
    - Checking if the source tenant has an Organization Relationship as described on https://docs.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-source-current-mailbox-location-tenant-by-accepting-the-migration-application-and-configuring-the-organization-relationship including a Mail-Enabled security group defined on the MailboxMovePublishedScopes property.
    - Gather all the necessary information for troubleshooting and send it to Microsoft Support if needed
    The script will prompt you to connect to your source and target tenants for EXO and AAD (only if you specify the "CheckOrgs" parameter)
    You can decide to run the checks for the source mailbox and target mailuser (individually or by providing a CSV file), or for the organization settings described above.
    PRE-REQUISITES:
    -Please make sure you have the Exchange Online V2 Powershell module (https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-and-maintain-the-exo-v2-module)
    -You would need the Azure AD Module (https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0#installing-the-azure-ad-module)
    -Also, you will be prompted for the SourceTenantId and TargetTenantId if you choose to run the script with the "CheckOrgs" parameter. To obtain the tenant ID of a subscription, sign in to the Microsoft 365 admin center and go to https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties. Click the copy icon for the Tenant ID property to copy it to the clipboard.
.PARAMETER CheckObjects
        This will allow you to perform the checks for the Source Mailbox and Target MailUser objects you provide. If used without the "-CSV" parameter, you will be prompted to type the identities.
.PARAMETER CSV
        This will allow you to specify a path for a CSV file you have with a list of users that contain the "SourceUser, TargetUser" columns.
        An example of the CSV file content would be:
        SourceUser, TargetUser
        Jdoe@contoso.com, Jdoe@fabrikam.com
        BSmith@contoso.com, BSmith@fabrikam.com
.PARAMETER CheckOrgs
        This will allow you to perform the checks for the source and target organizations. More specifically the organization relationship on both tenants, the migration endpoint on target tenant and the existence of the AAD application needed.

.PARAMETER SDP
        This will collect all the relevant information for troubleshooting from both tenants and be able to send it to Microsoft Support in case of needed.

.PARAMETER LogPath
        This will allow you to specify a log path to transcript all the script execution and it's results. This parameter is mandatory.


.EXAMPLE
        .\CrossTenantMailboxMigrationValidation.ps1 -CheckObjects -LogPath C:\Temp\LogFile.txt
        This will prompt you to type the source mailbox identity and the target identity, will establish 2 EXO remote powershell sessions (one to the source tenant and another one to the target tenant), and will check the objects.
.EXAMPLE

        .\CrossTenantMailboxMigrationValidation.ps1 -CheckObjects -CSV C:\Temp\UsersToMigrateValidationList.CSV -LogPath C:\Temp\LogFile.txt

        This will establish 2 EXO remote powershell sessions (one to the source tenant and another one to the target tenant), will import the CSV file contents and will check the objects one by one.
.EXAMPLE

        .\CrossTenantMailboxMigrationValidation.ps1 -CheckOrgs -LogPath C:\Temp\LogFile.txt

        This will prompt you for the soureTenantId and TargetTenantId, establish 3 remote powershell sessions (one to the source EXO tenant, one to the target EXO tenant and another one to AAD target tenant), and will validate the migration endpoint on the target tenant, AAD applicationId on target tenant and the Orgnization relationship on both tenants.
.EXAMPLE

        .\CrossTenantMailboxMigrationValidation.ps1 -SDP -LogPath C:\Temp\LogFile.txt

        This will prompt you for the sourceTenantId and TargetTenantId, establish 3 remote powershell sessions (one to the source EXO tenant, one to the target EXO tenant and another one to AAD target tenant), and will collect all the relevant information (config-wise) so it can be used for troubleshooting and send it to Microsoft Support if needed.
.#>

param (
    [Parameter(Mandatory = $True, ParameterSetName = "ObjectsValidation", HelpMessage = "Validate source Mailbox and Target MailUser objects. If used alone you will be prompted to introduce the identities you want to validate")]
    [System.Management.Automation.SwitchParameter]$CheckObjects,
    [Parameter(Mandatory = $False, ParameterSetName = "ObjectsValidation", HelpMessage = "Path pointing to the CSV containing the identities to validate. CheckObjects parameter needs also to be specified")]
    [System.String]$CSV,
    [Parameter(Mandatory = $True, HelpMessage = "Path pointing to the log file")]
    [System.String]$LogPath,
    [Parameter(Mandatory = $True, ParameterSetName = "OrgsValidation", HelpMessage = "Validate the organizations settings like organization relationships, migraiton endpoint and AADApplication")]
    [System.Management.Automation.SwitchParameter]$CheckOrgs,
    [Parameter(Mandatory = $True, ParameterSetName = "SDP", HelpMessage = "Collect relevant data for troubleshooting purposes and send it to Microsoft Support if needed")]
    [System.Management.Automation.SwitchParameter]$SDP
)

$wsh = New-Object -ComObject Wscript.Shell

function ConnectToEXOTenants {
    #Connect to SourceTenant (EXO)
    Write-Verbose -Message "Informational: Connecting to SOURCE EXO tenant"
    $wsh.Popup("You're about to connect to source tenant (EXO), please provide the SOURCE tenant admin credentials", 0, "SOURCE tenant") | Out-Null
    Connect-ExchangeOnline -Prefix Source -ShowBanner:$false

    #Connect to TargetTenant (EXO)
    Write-Verbose -Message "Informational: Connecting to TARGET EXO tenant"
    $wsh.Popup("You're about to connect to target tenant (EXO), please provide the TARGET tenant admin credentials", 0, "TARGET tenant") | Out-Null
    Connect-ExchangeOnline -Prefix Target -ShowBanner:$false
}

function CheckObjects {

    Write-Host "Informational: Loading SOURCE object"$SourceIdentity
    $SourceObject = Get-SourceMailbox $SourceIdentity -ErrorAction SilentlyContinue
    Write-Host "Informational: Loading TARGET object"$TargetIdentity
    $TargetObject = Get-TargetMailUser $TargetIdentity -ErrorAction SilentlyContinue

    #Validate if SourceObject is present
    if ($SourceObject) {
        #Since SourceObject is valid, validate if TargetObject is present
        if ($TargetObject) {
            #Check if source mailbox has aux archives and if so throw error, otherwise continue with the rest of validations
            Write-Verbose -Message "Checking if SOURCE mailbox has any aux-archives present"
            if ($SourceObject.MailboxLocations -like '*auxArchive*') {
                Write-Host ">> Error: The SOURCE mailbox has an auxArchive and as of now this object can't be migrated"
                exit
            } else {
                Write-Verbose -Message "No aux archives are present on SOURCE mailbox"

                #Verify if SOURCE mailbox is part of the Mail-Enabled Security Group defined on the SOURCE organization relationship
                Write-Verbose -Message "Informational: Checking if the SOURCE mailbox is a member of the SOURCE organization relationship Mail-Enabled Security Group defined on the MailboxMovePublishedScopes"
                $SourceTenantOrgRelationship = Get-SourceOrganizationRelationship | Where-Object { ($_.MailboxMoveCapability -eq "RemoteOutbound") -and ($null -ne $_.OauthApplicationId) }
                if ((Get-SourceDistributionGroupMember $SourceTenantOrgRelationship.MailboxMovePublishedScopes[0]).Name -contains $SourceObject.Name) {
                    Write-Host ">> SOURCE mailbox is within the MailboxMovePublishedScopes" -ForegroundColor Green
                } else {
                    Write-Host ">> Error: SOURCE mailbox is NOT within the MailboxMovePublishedScopes. The migration will fail if you don't correct this" -ForegroundColor Red
                }

                #Check the recoverableItems quota on TARGET MailUser and compare it with the SOURCE mailbox occupied quota
                Write-Verbose -Message "Checking if the current dumpster size on SOURCE mailbox is bigger than the TARGET MailUser recoverable items quota"
                if (((Get-SourceMailboxStatistics $SourceIdentity).TotalDeletedItemSize -replace '^.+\((.+\))', '$1' -replace '\D' -as [uint64]) -gt ([uint64]($TargetObject.RecoverableItemsQuota -replace '^.+\((.+\))', '$1' -replace '\D'))) {
                    Write-Host ">> Error: Dumpster size on SOURCE mailbox is bigger than TARGET MailUser RecoverableItemsQuota. This might cause the migration to fail" -ForegroundColor Red
                }

                #Verify ExchangeGuid on target object matches with source object and provide the option to set it in case it doesn't
                if (($null -eq $SourceObject.ExchangeGuid) -or ($null -eq $TargetObject.ExchangeGuid)) {
                    exit
                }
                Write-Verbose -Message "Informational: Checking ExchangeGUID"
                if ($SourceObject.ExchangeGuid -eq $TargetObject.ExchangeGuid) {
                    Write-Host ">> ExchangeGuid match ok" -ForegroundColor Green
                } else {
                    Write-Host ">> Error: ExchangeGuid mismatch. Expected Vaue: $($SourceObject.ExchangeGuid) ,Current value: $($TargetObject.ExchangeGuid)" -ForegroundColor Red
                    $ExchangeGuidSetOption = Read-Host "Would you like to set it? (Y/N)"
                    Write-Host " Your input: "$ExchangeGuidSetOption
                    if ($ExchangeGuidSetOption.ToLower() -eq "y") {
                        Write-Verbose -Message "Informational: Setting correct ExchangeGUID on TARGET object"
                        Set-TargetMailUser $TargetIdentity -ExchangeGuid $SourceObject.ExchangeGuid
                        #Reload TARGET object into variable as it has been changed
                        $TargetObject = Get-TargetMailUser $TargetIdentity
                    }
                }

                #Verify if Archive is present on source and if it is, verify ArchiveGuid on target object matches with source object and provide the option to set it in case it doesn't
                Write-Verbose -Message "Informational: Checking if there's an Archive enabled on SOURCE object"
                if ($null -eq $SourceObject.ArchiveGUID) {
                    if ($null -ne $TargetObject.ArchiveGUID) {
                        Write-Host ">> Error: The TARGET MailUser $($TargetObject.Name) has an archive present while source doesn't"
                    }
                    exit
                }
                if ($SourceObject.ArchiveGuid -ne "00000000-0000-0000-0000-000000000000") {
                    Write-Verbose -Message "Informational: Archive is enabled on SOURCE object"
                    Write-Verbose -Message "Informational: Checking ArchiveGUID"
                    if ($SourceObject.ArchiveGuid -eq $TargetObject.ArchiveGuid) {
                        Write-Host ">> ArchiveGuid match ok" -ForegroundColor Green
                    } else {
                        Write-Host ">> Error: ArchiveGuid mismatch. Expected Value: $($SourceObject.ArchiveGuid) , Current value: $($TargetObject.ArchiveGuid)" -ForegroundColor Red
                        $ArchiveGuidSetOption = Read-Host "Would you like to set it? (Y/N)"
                        Write-Host " Your input: "$ArchiveGuidSetOption
                        if ($ArchiveGuidSetOption.ToLower() -eq "y") {
                            Write-Verbose -Message "Informational: Setting correct ArchiveGUID on TARGET object"
                            Set-TargetMailUser $TargetIdentity -ArchiveGuid $SourceObject.ArchiveGuid
                            #Reload TARGET object into variable as it has been changed
                            $TargetObject = Get-TargetMailUser $TargetIdentity
                        }
                    }
                }

                else {
                    Write-Verbose -Message "Informational: Source object has no Archive enabled"
                }

                #Verify LegacyExchangeDN is present on target object as an X500 proxy address and provide the option to add it in case it isn't
                Write-Verbose -Message "Informational: Checking if LegacyExchangeDN from SOURCE object is part of EmailAddresses on TARGET object"
                if ($null -eq $TargetObject.EmailAddresses) {
                    exit
                }
                if ($TargetObject.EmailAddresses -contains "X500:" + $SourceObject.LegacyExchangeDN) {
                    Write-Host ">> LegacyExchangeDN found as an X500 ProxyAddress on Target Object." -ForegroundColor Green
                } else {
                    Write-Host ">> Error: LegacyExchangeDN not found as an X500 ProxyAddress on Target Object. LegacyExchangeDN expected on target object:" $SourceObject.LegacyExchangeDN -ForegroundColor Red
                    $LegDNAddOption = Read-Host "Would you like to add it? (Y/N)"
                    Write-Host " Your input: "$LegDNAddOption
                    if ($LegDNAddOption.ToLower() -eq "y") {
                        Write-Verbose -Message "Informational: Adding LegacyExchangeDN as a proxyAddress on TARGET object"
                        Set-TargetMailUser $TargetIdentity -EmailAddresses @{Add = "X500:" + $SourceObject.LegacyExchangeDN }
                        #Reload TARGET object into variable as it has been changed
                        $TargetObject = Get-TargetMailUser $TargetIdentity
                    }
                }

                #Check if the primarySMTPAddress of the target MailUser is part of the accepted domains on the target tenant and if any of the email addresses of the target MailUser doesn't belong to the target accepted domains
                Write-Verbose -Message "Informational: Loading TARGET accepted domains"
                $TargetTenantAcceptedDomains = Get-TargetAcceptedDomain

                #PrimarySMTP
                Write-Verbose -Message "Informational: Checking if the PrimarySTMPAddress of TARGET belongs to a TARGET accepted domain"
                if ($TargetTenantAcceptedDomains.DomainName -notcontains $TargetObject.PrimarySmtpAddress.Split('@')[1]) {
                    Write-Host ">> Error: The Primary SMTP address $($TargetObject.PrimarySmtpAddress) of the MailUser does not belong to an accepted domain on the target tenant, would you like to set it to $($TargetObject.UserPrincipalName) (Y/N): " -ForegroundColor Red -NoNewline
                    $PrimarySMTPAddressSetOption = Read-Host
                    Write-Host " Your input: "$PrimarySMTPAddressSetOption
                    if ($PrimarySMTPAddressSetOption.ToLower() -eq "y") {
                        Write-Verbose -Message "Informational: Setting the UserPrincipalName of TARGET object as the PrimarySMTPAddress"
                        Set-TargetMailUser $TargetIdentity -PrimarySmtpAddress $TargetObject.UserPrincipalName
                        #Reload TARGET object into variable as it has been changed
                        $TargetObject = Get-TargetMailUser $TargetIdentity
                    }
                } else {
                    Write-Host ">> Target MailUser PrimarySMTPAddress is part of target accepted domains" -ForegroundColor Green
                }

                #EMailAddresses
                Write-Verbose -Message "Informational: Checking for EmailAddresses on TARGET object that are not on the TARGET accepted domains list"
                foreach ($Address in $TargetObject.EmailAddresses) {
                    if ($Address.StartsWith("SMTP:") -or $Address.StartsWith("smtp:")) {
                        if ($TargetTenantAcceptedDomains.DomainName -notcontains $Address.Split("@")[1]) {
                            Write-Host ">> Error:"$Address" is not part of your organization, would you like to remove it? (Y/N): " -ForegroundColor Red -NoNewline
                            $RemoveAddressOption = Read-Host
                            Write-Host " Your input: "$RemoveAddressOption
                            if ($RemoveAddressOption.ToLower() -eq "y") {
                                Write-Host "Informational: Removing the EmailAddress"$Address" from the TARGET object"
                                Set-TargetMailUser $TargetIdentity -EmailAddresses @{Remove = $Address }
                                #Reload TARGET object into variable as it has been changed
                                $TargetObject = Get-TargetMailUser $TargetIdentity
                            }
                        }
                    } else {
                        Write-Host ">> Target MailUser ProxyAddresses are all part of the target organization" -ForegroundColor Green
                    }
                }

                #Sync X500 addresses from source mailbox to target mailUser
                Write-Verbose -Message "Informational: Checking for missing X500 adresses on TARGET that are present on SOURCE mailbox"
                if ($SourceObject.EmailAddresses -like '*500:*') {
                    Write-Verbose -Message "SOURCE mailbox contains X500 addresses, checking if they're present on the TARGET MailUser"
                    foreach ($Address in ($SourceObject.EmailAddresses | Where-Object { $_ -like '*500:*' })) {
                        if ($TargetObject.EmailAddresses -notcontains $Address) {
                            Write-Host ">> Error:"$Address" is not present on the TARGET MailUser, would you like to add it? (Y/N): " -ForegroundColor Red -NoNewline
                            $AddX500 = Read-Host
                            Write-Host " Your input: "$AddX500
                            if ($AddX500.ToLower() -eq "y") {
                                Write-Host "Informational: Adding the X500 Address"$Address" on the TARGET object"
                                Set-TargetMailUser $TargetIdentity -EmailAddresses @{Add = $Address }
                                #Reload TARGET object into variable as it has been changed
                                $TargetObject = Get-TargetMailUser $TargetIdentity
                            }
                        } else {
                            Write-Host ">> Informational: The X500 address from SOURCE object is present on TARGET object" -ForegroundColor Green
                        }
                    }
                } else {
                    Write-Verbose -Message "Informational: SOURCE mailbox doesn't contain any X500 address"
                }

                #Check ExternalEmailAddress on TargetMailUser with primarySMTPAddress from SourceMailbox:
                Write-Verbose -Message "Informational: Checking if the ExternalEmailAddress on TARGET object points to the PrimarySMTPAddress of the SOURCE object"
                if ($TargetObject.ExternalEmailAddress.Split(":")[1] -eq $SourceObject.PrimarySmtpAddress) {
                    Write-Host ">> ExternalEmailAddress of Target MailUser is pointing to PrimarySMTPAddress of Source Mailbox" -ForegroundColor Green
                } else {
                    Write-Host ">> Error: TargetMailUser ExternalEmailAddress value $($TargetObject.ExternalEmailAddress) does not match the PrimarySMTPAddress of the SourceMailbox $($SourceObject.PrimarySmtpAddress) , would you like to set it? (Y/N): " -ForegroundColor Red -NoNewline
                    $RemoveAddressOption = Read-Host
                    Write-Host " Your input: "$RemoveAddressOption
                    if ($RemoveAddressOption.ToLower() -eq "y") {
                        Write-Host "Informational: Setting the ExternalEmailAddress of SOURCE object to"$SourceObject.PrimarySmtpAddress
                        Set-TargetMailUser $TargetIdentity -ExternalEmailAddress $SourceObject.PrimarySmtpAddress
                        #Reload TARGET object into variable as it has been changed
                        $TargetObject = Get-TargetMailUser $TargetIdentity
                    }
                }
            }
        }

        else {
            Write-Host ">> Error: $($TargetIdentity) wasn't found on TARGET tenant" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: $($SourceIdentity) wasn't found on SOURCE tenant" -ForegroundColor Red
    }
}




function ConnectToTargetTenantAAD {
    #Connect to TargetTenant (AzureAD)
    Write-Verbose -Message "Informational: Connecting to AAD on TARGET tenant"
    $wsh.Popup("You're about to connect to target tenant (AAD), please provide the TARGET tenant admin credentials", 0, "TARGET tenant") | Out-Null
    Connect-AzureAD | Out-Null
}
function CheckOrgs {

    #Check if there's an AAD EXO app as expected and load it onto a variable
    Write-Verbose -Message "Informational: Checking if there's already an AAD Application on TARGET tenant that meets the criteria"
    $AADEXOAPP = Get-AzureADApplication | Where-Object { ($_.ReplyUrls -eq "https://office.com") -and ($_.RequiredResourceAccess -like "*ResourceAppId: 00000002-0000-0ff1-ce00-000000000000*") }
    if ($AADEXOAPP) {
        Write-Host "AAD application for EXO has been found" -ForegroundColor Green
        Write-Verbose -Message "Informational: Loading migration endpoints on TARGET tenant that meets the criteria"
        if (Get-TargetMigrationEndpoint | Where-Object { ($_.RemoteServer -eq "outlook.office.com") -and ($_.EndpointType -eq "ExchangeRemoteMove") -and ($_.ApplicationId -eq $AADEXOAPP.AppId) }) {
            Write-Host "Migration endpoint found and correctly set" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Expected Migration endpoint not found" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No AAD application for EXO has been found" -ForegroundColor Red
    }

    #Check orgrelationship flags on source and target orgs
    Write-Verbose -Message "Informational: Loading Organization Relationship on SOURCE tenant that meets the criteria"
    $SourceTenantOrgRelationship = Get-SourceOrganizationRelationship | Where-Object { $_.OauthApplicationId -eq $AADEXOAPP.AppId }
    Write-Verbose -Message "Informational: Loading Organization Relationship on TARGET tenant that meets the criteria"
    $TargetTenantOrgRelationship = Get-TargetOrganizationRelationship | Where-Object { $_.DomainNames -contains $SourceTenantId }

    Write-Verbose -Message "Informational: Checking TARGET tenant organization relationship"
    if ($TargetTenantOrgRelationship) {
        Write-Host "Organization relationship on TARGET tenant DomainNames is correctly pointing to SourceTenantId" -ForegroundColor Green
        if ($TargetTenantOrgRelationship.MailboxMoveEnabled) {
            Write-Host "Organization relationship on TARGET tenant is enabled for moves" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Organization relationship on TARGET tenant mailbox is not enabled for moves" -ForegroundColor Red
        }
        if ($TargetTenantOrgRelationship.MailboxMoveCapability -eq "Inbound") {
            Write-Host "Organization relationship on TARGET tenant MailboxMove is correctly set" -ForegroundColor Green
        } else {
            Write-Host ">> Error: Organization relationship on TARGET tenant MailboxMove is not correctly set. The expected value is 'Inbound' and the current value is"$TargetTenantOrgRelationship.MailboxMoveCapability -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No Organization relationship on TARGET tenant pointing to SourceTenantId has been found" -ForegroundColor Red
    }



    Write-Verbose -Message "Informational: Checking SOURCE tenant organization relationship"
    if ($SourceTenantOrgRelationship.MailboxMoveEnabled) {
        Write-Host "Organization relationship on SOURCE tenant is enabled for moves" -ForegroundColor Green
        if ($SourceTenantOrgRelationship.MailboxMoveCapability -eq "RemoteOutbound") {
            Write-Host "Organization relationship on SOURCE tenant MailboxMove is correctly set" -ForegroundColor Green
            if ($SourceTenantOrgRelationship.DomainNames -contains $TargetTenantId) {
                Write-Host "Organization relationship on SOURCE tenant DomainNames is correctly pointing to TargetTenantId" -ForegroundColor Green
            } else {
                Write-Host ">> Error: Organization relationship on SOURCE tenant DomainNames is not pointing to TargetTenantId" -ForegroundColor Red
            }
            if ($null -eq $SourceTenantOrgRelationship.MailboxMovePublishedScopes) {
                Write-Host ">> Error: Organization relationship on SOURCE tenant does not have a Mail-Enabled security group defined under the MailboxMovePublishedScopes property" -ForegroundColor Red
            }
        }

        else {
            Write-Host ">> Error: Organization relationship on SOURCE tenant MailboxMove is not correctly set. The expected value is 'RemoteOutbound' and the current value is"$TargetTenantOrgRelationship.MailboxMoveCapability -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: Organization relationship on TARGET tenant mailbox is not enabled for moves" -ForegroundColor Red
    }
}

function KillSessions {
    #Check if there's any existing session opened for EXO and remove it so it doesn't remains open
    Get-PSSession | Where-Object { $_.ComputerName -eq 'outlook.office365.com' } | Remove-PSSession
}

function CollectData {
    #Create the folders based on date and time to store the files
    $InputPath = Read-Host "Please specify an existing path to store the collected data "
    $currentdate = (Get-Date).ToString('ddMMyyHHMM')
    if (Test-Path $InputPath -PathType Container) {
        $OutputPath = New-Item -ItemType Directory -Path $InputPath -Name $currentdate | Out-Null
        $OutputPath = $InputPath + '\' + $currentdate
    } else {
        Write-Host ">> Error: The specified folder doesn't exist, please specify an existent one" -ForegroundColor Red
        exit
    }

    #Collect the Exchange Online data and export it to an XML file
    Write-Host "Informational: Saving SOURCE tenant id to text file"  -ForegroundColor Yellow
    "SourceTenantId: " + $SourceTenantId | Out-File $OutputPath\TenantIds.txt
    Write-Host "Informational: Saving TARGET tenant id to text file"  -ForegroundColor Yellow
    "TargetTenantId: " + $TargetTenantId | Out-File $OutputPath\TenantIds.txt -Append
    Write-Host "Informational: Exporting the SOURCE tenant organization relationship"  -ForegroundColor Yellow
    Get-SourceOrganizationRelationship | Export-Clixml $OutputPath\SourceOrgRelationship.xml
    Write-Host "Informational: Exporting the TARGET tenant migration endpoint"  -ForegroundColor Yellow
    Get-TargetMigrationEndpoint | Export-Clixml $OutputPath\TargetMigrationEndpoint.xml
    Write-Host "Informational: Exporting the TARGET tenant organization relationship"  -ForegroundColor Yellow
    Get-TargetOrganizationRelationship | Export-Clixml $OutputPath\TargetOrgRelationship.xml
    Write-Host "Informational: Exporting the TARGET tenant accepted domains"  -ForegroundColor Yellow
    Get-TargetAcceptedDomain | Export-Clixml $OutputPath\TargetAcceptedDomains.xml
    Write-Host "Informational: Exporting the TARGET tenant Azure AD applications" -ForegroundColor Yellow
    Get-AzureADApplication | Export-Clixml $OutputPath\TargetAADApps.xml

    #Compress folder contents into a zip file
    Write-Host "Informational: Data has been exported. Compressing it into a ZIP file"  -ForegroundColor Yellow
    if ((Get-ChildItem $OutputPath).count -gt 0) {
        try {
            Compress-Archive -Path $OutputPath\*.XML -DestinationPath $InputPath\CTMMCollectedData$currentdate.zip
            Compress-Archive -Path $OutputPath\TenantIds.txt -DestinationPath $InputPath\CTMMCollectedData$currentdate.zip -Update
            Write-Host "Informational: ZIP file has been generated with a total of $((Get-ChildItem $OutputPath).count) files, and can be found at"$InputPath\CTMMCollectedData$currentdate.zip" so it can be sent to Microsoft Support if needed, however you can still access the raw data at $($OutputPath)"  -ForegroundColor Yellow
        } catch {
            Write-Host ">> Error: There was an issue trying to compress the exported data" -ForegroundColor Red
        }
    } else {
        Write-Host ">> Error: No data has been detected at"$OutputPath", so there's nothing to compress" -ForegroundColor Red
    }
}

function LoggingOn {
    Write-Host ""
    Write-Host ""
    if (Test-Path $LogPath -PathType Leaf) {
        Write-Host ">> Error: The log file already exists, please specify a different name and run again" -ForegroundColor Red
        exit
    } else {
        Start-Transcript -Path $LogPath -NoClobber
    }
}

function LoggingOff {
    Stop-Transcript
}

if ($CheckObjects -and !$NoConn) {
    LoggingOn
    if ($CSV) {
        $Objects = Import-Csv $CSV
        if (($Objects.SourceUser) -and ($Objects.TargetUser)) {
            ConnectToEXOTenants
            foreach ($object in $Objects) {
                $SourceIdentity = $object.SourceUser
                $TargetIdentity = $object.TargetUser
                Write-Host ""
                Write-Host "----------------------------------------" -ForegroundColor Cyan
                Write-Host "----------------------------------------" -ForegroundColor Cyan
                Write-Host ""
                Write-Host $SourceIdentity" is being used as SOURCE object"
                Write-Host $TargetIdentity" is being used as TARGET object"
                CheckObjects
            }
        } else {
            Write-Host ">> Error: Invalid CSV file, please make sure you specify a correct one with the 'SourceUser' and 'TargetUser' columns" -ForegroundColor Red
            exit
        }
    } else {
        $SourceIdentity = Read-Host "Please type the SOURCE object to check at"
        $TargetIdentity = Read-Host "Please type the TARGET object to compare with"
        ConnectToEXOTenants
        Write-Host ""
        Write-Host "----------------------------------------" -ForegroundColor Cyan
        Write-Host "----------------------------------------" -ForegroundColor Cyan
        Write-Host ""
        CheckObjects
    }
    LoggingOff
    KillSessions
}

if ($CheckOrgs) {
    LoggingOn
    $SourceTenantId = Read-Host "Please specify the SOURCE TenantId"
    $TargetTenantId = Read-Host "Please specify the TARGET TenantId"
    ConnectToEXOTenants
    ConnectToTargetTenantAAD
    CheckOrgs
    LoggingOff
    KillSessions
}

if ($SDP) {
    LoggingOn
    $SourceTenantId = Read-Host "Please specify the SOURCE TenantId"
    $TargetTenantId = Read-Host "Please specify the TARGET TenantId"
    ConnectToEXOTenants
    ConnectToTargetTenantAAD
    CollectData
    LoggingOff
    KillSessions
}
