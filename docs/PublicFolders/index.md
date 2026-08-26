# Public Folders

This section contains scripts for managing, validating, and migrating Exchange public folders. Use the tables below to find the right script for your task.

## General Tools

These scripts operate on an existing public folder deployment (on-premises or Exchange Online).

| Script | Purpose | Docs | Download |
| --- | --- | --- | --- |
| Export-PublicFolderStatistics.ps1 | Exports statistics for a list of public folders to a CSV file. | [Docs](Export-PublicFolderStatistics.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Export-PublicFolderStatistics.ps1) |
| ManagePublicFolderPermissions.ps1 | Exports or imports public folder client permissions to/from a CSV file. | [Docs](ManagePublicFolderPermissions.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ManagePublicFolderPermissions.ps1) |
| Move-PublicFolderBranch.ps1 | Moves the contents of a public folder branch to a different public folder mailbox. | [Docs](Move-PublicFolderBranch.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Move-PublicFolderBranch.ps1) |
| Update-PublicFolderPermissions.ps1 | Updates the client permissions of a public folder (and optionally its children) for several users. | [Docs](Update-PublicFolderPermissions.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Update-PublicFolderPermissions.ps1) |
| ValidateEXOPFDumpster.ps1 | Investigates public folder/item deletion failures in Exchange Online and proposes fixes. | [Docs](ValidateEXOPFDumpster.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ValidateExoPfDumpster.ps1) |
| ValidateMailEnabledPublicFolders.ps1 | Finds and reports inconsistencies with mail-enabled public folders. | [Docs](ValidateMailEnabledPublicFolders.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ValidateMailEnabledPublicFolders.ps1) |
| SourceSideValidations.ps1 | Performs pre-migration public folder checks for Exchange 2013, 2016, and 2019. | [Docs](SourceSideValidations.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SourceSideValidations.ps1) |

## Mail Public Folder Sync

These scripts synchronize mail-enabled public folder directory objects between on-premises Exchange and Exchange Online.

| Script | Purpose | Docs | Download |
| --- | --- | --- | --- |
| Sync-ModernMailPublicFolders.ps1 | Syncs mail-enabled public folders from on-premises (Exchange 2013+) to Exchange Online using modern authentication. | [Docs](MailPublicFolderSync/Sync-ModernMailPublicFolders.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Sync-ModernMailPublicFolders.ps1) |
| Sync-MailPublicFolders.ps1 | Syncs mail-enabled public folders from legacy on-premises Exchange (2007/2010) to Exchange Online. | [Docs](MailPublicFolderSync/Sync-MailPublicFolders.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Sync-MailPublicFolders.ps1) |
| Sync-MailPublicFoldersCloudToOnprem.ps1 | Syncs mail-enabled public folders from Exchange Online back to on-premises. | [Docs](MailPublicFolderSync/Sync-MailPublicFoldersCloudToOnprem.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Sync-MailPublicFoldersCloudToOnprem.ps1) |
| Import-PublicFolderMailboxes.ps1 | Imports public folder mailboxes from Exchange Online as mail-enabled users on-premises. | [Docs](MailPublicFolderSync/Import-PublicFolderMailboxes.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Import-PublicFolderMailboxes.ps1) |
| Import-MailPublicFolders.ps1 | Creates placeholder mail-enabled public folder objects in the target forest. | [Docs](MailPublicFolderSync/Import-MailPublicFolders.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Import-MailPublicFolders.ps1) |

## Migration to Exchange Online

These scripts prepare and support a public folder to public folder migration from Exchange Server to Exchange Online.

| Script | Purpose | Docs | Download |
| --- | --- | --- | --- |
| Export-ModernPublicFolderStatistics.ps1 | Generates a CSV file listing public folders and their individual sizes. | [Docs](Migration/ToExchangeOnline/Export-ModernPublicFolderStatistics.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Export-ModernPublicFolderStatistics.ps1) |
| ModernPublicFolderToMailboxMapGenerator.ps1 | Generates a CSV that maps public folder branches to destination public folder mailboxes. | [Docs](Migration/ToExchangeOnline/ModernPublicFolderToMailboxMapGenerator.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ModernPublicFolderToMailboxMapGenerator.ps1) |
| SetMailPublicFolderExternalAddress.ps1 | Stamps the ExternalEmailAddress of mail-enabled public folders with their Exchange Online SMTP address for mail routing. | [Docs](Migration/ToExchangeOnline/SetMailPublicFolderExternalAddress.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SetMailPublicFolderExternalAddress.ps1) |

## Migration to Microsoft 365 Groups

These scripts support migrating public folders to Microsoft 365 Groups.

| Script | Purpose | Docs | Download |
| --- | --- | --- | --- |
| LockAndSavePublicFolderProperties.ps1 | Locks down the public folders being migrated and backs up their properties for rollback. | [Docs](Migration/ToMicrosoft365Groups/LockAndSavePublicFolderProperties.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/LockAndSavePublicFolderProperties.ps1) |
| AddMembersToGroups.ps1 | Adds users with public folder permissions as owners/members of the corresponding Microsoft 365 Group. | [Docs](Migration/ToMicrosoft365Groups/AddMembersToGroups.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/AddMembersToGroups.ps1) |
| UnlockAndRestorePublicFolderProperties.ps1 | Restores public folder permissions and properties from backup to roll back a Groups migration. | [Docs](Migration/ToMicrosoft365Groups/UnlockAndRestorePublicFolderProperties.md) | [Download](https://github.com/microsoft/CSS-Exchange/releases/latest/download/UnlockAndRestorePublicFolderProperties.ps1) |
