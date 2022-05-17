# CrossTenantMailboxMigrationValidation

## DESCRIPTION

This script offers the ability to validate users and org settings related to the Cross-tenant mailbox migration before creating a migration batch and have a better experience.

It will help you on:
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

### PRE-REQUISITES:

- Please make sure you have the Exchange Online V2 Powershell module (https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-and-maintain-the-exo-v2-module)
- You would need the Azure AD Module (https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0#installing-the-azure-ad-module)
- Also, you will be prompted for the SourceTenantId and TargetTenantId if you choose to run the script with the "CheckOrgs" parameter. To obtain the tenant ID of a subscription, sign in to the Microsoft 365 admin center and go to https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties. Click the copy icon for the Tenant ID property to copy it to the clipboard.

## PARAMETERS

### CheckObjects
This will allow you to perform the checks for the Source Mailbox and Target MailUser objects you provide. If used without the "-CSV" parameter, you will be prompted to type the identities.

### CSV
This will allow you to specify a path for a CSV file you have with a list of users that contain the "SourceUser, TargetUser" columns.
An example of the CSV file content would be:

        SourceUser, TargetUser
        Jdoe@contoso.com, Jdoe@fabrikam.com
        BSmith@contoso.com, BSmith@fabrikam.com

### CheckOrgs
This will allow you to perform the checks for the source and target organizations. More specifically the organization relationship on both tenants, the migration endpoint on target tenant and the existence of the AAD application needed.

### SDP
This will collect all the relevant information for troubleshooting from both tenants and be able to send it to Microsoft Support in case of needed.

### LogPath
This will allow you to specify a log path to transcript all the script execution and it's results. This parameter is mandatory.


## EXAMPLES
### EXAMPLE 1

    .\CrossTenantMailboxMigrationValidation.ps1 -CheckObjects -LogPath C:\Temp\LogFile.txt

This will prompt you to type the source mailbox identity and the target identity, will establish 2 EXO remote powershell sessions (one to the source tenant and another one to the target tenant), and will check the objects.

### EXAMPLE 2

    .\CrossTenantMailboxMigrationValidation.ps1 -CheckObjects -CSV C:\Temp\UsersToMigrateValidationList.CSV -LogPath C:\Temp\LogFile.txt

This will establish 2 EXO remote powershell sessions (one to the source tenant and another one to the target tenant), will import the CSV file contents and will check the objects one by one.


### EXAMPLE 3

    .\CrossTenantMailboxMigrationValidation.ps1 -CheckOrgs -LogPath C:\Temp\LogFile.txt

This will prompt you for the soureTenantId and TargetTenantId, establish 3 remote powershell sessions (one to the source EXO tenant, one to the target EXO tenant and another one to AAD target tenant), and will validate the migration endpoint on the target tenant, AAD applicationId on target tenant and the Orgnization relationship on both tenants.

### EXAMPLE 4


    .\CrossTenantMailboxMigrationValidation.ps1 -SDP -LogPath C:\Temp\LogFile.txt

This will prompt you for the soureTenantId and TargetTenantId, establish 3 remote powershell sessions (one to the source EXO tenant, one to the target EXO tenant and another one to AAD target tenant), and will collect all the relevant information (config-wise) so it can be used for troubleshooting and send it to Microsoft Support if needed.
