---
title: SourceSideValidations.ps1
parent: PublicFolders
---

## SourceSideValidations.ps1

Download the latest release: [SourceSideValidations.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/SourceSideValidations.ps1)

This script performs pre-migration public folder checks for Exchange 2013, 2016, and 2019. For Exchange 2010, please use previous script found [here](https://www.microsoft.com/en-us/download/details.aspx?id=100414).

### Syntax

Typically, the script should be run with no parameters:

`.\SourceSideValidations.ps1`

### Output

The script will generate one more of the following files, and it will display
examples that show how to use them. Examine the script output for those details.

File Name|Content|Use
-|-|-
IpmSubtree.csv|A subset of properties of all Public Folders|Running with -StartFresh $false loads this file instead of retrieving fresh data
ItemCounts.csv|EntryID and item count of every folder|Running with -StartFresh $false loads this file instead of retrieving fresh data
NonIpmSubtree.csv|A subset of properties of all System Folders|Running with -StartFresh $false loads this file instead of retrieving fresh data
FoldersToMailDisable.txt|Folders that should be mail-disabled, because they are system folders or because their mail objects are missing|Use with the command displayed in the script output to disable them
MailPublicFolderOrphans.txt|Mail objects that are not linked to any existing folder|Use with the command displayed in the script output to delete them
MailPublicFolderDuplicates.txt|Mail objects that point to folders which are linked to some other mail object|Use with the command displayed in the script output to delete them
AddAddressesFromDuplicates.ps1|Commands that add the email addresses from the folders listed in MailPublicFolderDuplicates.txt onto the mail objects currently linked to the folders|Run after deleting the duplicates to preserve the email addresses on the remaining valid mail object
MailDisabledWithProxyGuid.txt|Folders that are mail-disabled but have a mail object stamped on them|Pipe to Enable-MailPublicFolder using the syntax example shown in the script output to enable these
MailPublicFoldersDisconnected.txt|Mail objects that correspond to a valid, but mail-disabled, folder|These must be examined and corrected manually
BadDumpsterMappings.txt|Folders with invalid dumpster mappings|These folders can be deleted or the -ExcludeDumpsters switch can be used to skip the dumpsters during migration
TooManyChildFolders.txt|Folders that have too many child folders|Examine the list and manually reduce the number of child folders
PathTooDeep.txt|Folders that exceed the path depth limit|Examine the list and reduce the depth of these paths by moving or deleting folders
TooManyItems.txt|Folders that have too many items|Examine the list and manually reduce the number of items in these folders
InvalidPermissions.csv|Any invalid ACEs that were found|Use with -RemoveInvalidPermissions parameter to remove these
