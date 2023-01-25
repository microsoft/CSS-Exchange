# MigrateDLs

Download the latest release: [CrossTenantMailboxMigrationValidation.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/MigrateDLs.ps1)

## DESCRIPTION
This script offers the ability to migrate Distribution Lists (aka Distribution Groups) that are sitting in Exchage On-premises and need to be moved to Exchange Online, providing in this way, the ability for end users to manage them once their mailboxes have been migrated to Exchange Online.
It will process every DL listed on the CSV file and will do the following:
- Check if the DL is present on-premises (if it isn't, the entry will be bypassed and will move on to the next one)
- Check if the DL is present in EXO (if it is, the entry will be bypassed and will move on to the next one)
- Export all the properties of the on-premises DL and store them on a file matching the entry within the specified LogPath.
- Create the DL on EXO and stamp the properties from the on-premises DL.
- Validate every property of the DL, ensuring the on-premises ones match the one on EXO (including members). If a property is not matching, it will be shown on the screen and will be logged on the 'Failed-' log file that corresponds to the object being processed.
- If validation is successful, we will remove the DL from on-premises (check if the object was removed) and create a mail-contact on-premises, having the ExternalEmailAddress pointing to the provisioned onmicrosoft.com email address of the DL on EXO.
- Once the Mail-Contact has been validated, we will rename the log file to start with 'OK-'
- If the process fails on any step, we will rename the log file to start with 'Failed-'

 ## PRE-REQUISITES:

 For the process to work correctly, we need to have the following things in consideration:
- Make sure the DL's you include on the CSV file are present in Exchange On-premises AND NOT SYNCED to Exchange Online anymore (in other words, the DL should not be present in EXO)
- Running this script, needs to be done from the Exchange Management Shell on-premises, with the Exchange Online management module installed (if you need to install the module, running EMS or Powershell as an admin, run 'Install-Module ExchangeOnlineManagement')
- The account running this scripts needs to have at least the 'Recipient Management' Exchange management role assigned on both ends (on-premises and online).
- The CSV file needs to have just one column named 'DL'
- The specified log path should not end with '\'
- To avoid any possible throttling applied to Powershell, I recommend running batches of no more than 100 entries per day.

## PARAMETERS

### CSVfile
    CSV file of the DL's we will be migrating when running this script

### LogPath
	Temp path for storing DL props and logging of the process for each one of the entries listed on the CSV file


## EXAMPLE
    .\MigrateDLs.ps1 -CSV c:\Temp\myCSV.csv -LogPath C:\Temp
    This will import the specified CSV file and migrate the DL's listed there. For every one of them, their properties and the process details will be stores ont he specified path for logging.
