ConvertFrom-StringData @'
###PSLOC
CreatingRemoteSession = Creating an Exchange Online remote session...
FailedToCreateRemoteSession = Unable to create a remote shell session to Exchange Online. The error is as follows: "{0}".
FailedToImportRemoteSession = Exchange Online remote could session not be imported. The error is as follows: "{0}".
RemoteSessionCreatedSuccessfully = Exchange Online remote session created successfully.
LocalMailPublicFolderEnumerationStart = Enumerating local mail enabled public folders...
LocalMailPublicFolderEnumerationCompleted = Mail public folders enumeration completed: {0} local folder(s) found.
RemoteMailPublicFolderEnumerationStart = Enumerating Exchange Online mail enabled public folders...
RemoteMailPublicFolderEnumerationCompleted = Mail public folders enumeration completed: {0} Exchange Online folder(s) found.
FailedToCreateMailPublicFolderEmptyPrimarySmtpAddress = Mail public folder '{0}' could not be created on Exchange Online because its PrimarySmtpAddress is empty.
PrimarySmtpAddressUsedByAnotherFolder = PrimarySmtpAddress '{0}' is already being used by local mail public folder '{1}'.
PrimarySmtpAddressUsedByOtherFolders = PrimarySmtpAddress '{0}' is being used by this and other {1} local mail public folder(s).
SkippingFoldersWithDuplicateAddress = Skipping {0} local mail public folder objects due to duplicate PrimarySmtpAddress: '{1}'.
AmbiguousLocalMailPublicFolderResolution = Local mail public folder '{0}' can be associated to Exchange Online objects '{1}' by OnPremisesObjectId and '{2}' by PrimarySmtpAddress.
CreateOperationName = Create
UpdateOperationName = Update
RemoveOperationName = Remove
ConfirmationTitle = Sync local changes to Exchange Online
ConfirmationQuestion = The following local mail public folder changes were detected and will be applied to Exchange Online: {0} object(s) created, {1} updated and {2} deleted. Do you really want to proceed?
ConfirmationYesOption = &Yes
ConfirmationNoOption = &No
ConfirmationYesOptionHelp = Proceed and sync all mail public folders changes to Exchange Online Active Directory.
ConfirmationNoOptionHelp = STOP! No mail public folders changes will be applied to Exchange Online.
TimestampCsvHeader = Timestamp
IdentityCsvHeader = Identity
OperationCsvHeader = Operation
ResultCsvHeader = Result
CommandCsvHeader = Command text
CsvSuccessResult = Success
ProgressBarActivity = Syncing mail public folders...
ProgressBarStatusRemoving = Removing items from Exchange Online: {0}/{1}.
ProgressBarStatusUpdating = Updating existing items on Exchange Online: {0}/{1}.
ProgressBarStatusCreating = Creating new items on Exchange Online: {0}/{1}.
SyncMailPublicFolderObjectsComplete = Syncing of mail public folder objects into Active Directory completed: {0} objects created, {1} objects updated and {2} objects deleted.
ErrorsFoundDuringImport = Total errors found: {0}. Please, check the error summary at '{1}' for more information.
LocalServerVersionNotSupported = You cannot execute this script from your local Exchange server: "{0}". This script can only be executed from Exchange 2007 Management Shell and above.
ForceParameterRequired = You are about to remove ALL mail-enabled public folders from Exchange Online Active Directory. Only proceed if you do not have any users on Exchange Online already using mail-enabled public folders. Also, make sure your local Exchange deployment doesn't have any mail-enabled public folders by running Get-MailPublicFolder. You can bypass this warning by running the script using the -Force parameter.
SystemFoldersSkipped = The following {0} mail-enabled public folder(s) will not be synced as they are linked to system public folders. These folders are not applicable for Exchange Online.
UnableToDetectSystemMailPublicFolders = The script is unable to determine a list of system public folders while the local public folder deployment is locked for migration. This may cause some mail-enabled system public folders to be synced to Exchange Online Active Directory and cause Public Folder migration to fail. If that happens, you can run "Set-MailPublicFolder -IgnoreMissingFolderLink:$true" for each AD object that is a system folder and resume the migration. Note that these system folders don't need to be mail-enabled on Exchange 2013 or later, so it is completely safe to ignore errors reported while mail-enabling them during migration. To learn more about system public folders, please read the following TechNet article: https://technet.microsoft.com/en-us/library/bb397221(v=exchg.151).aspx#Trees.
ValidateMailEnabledPublicFoldersFailed = Validating Mail Enabled Public Folders failed. Continuing to sync Mail Public Folders to Exchange Online.
DownloadingValidateMEPFScript = Downloading ValidateMailEnabledPublicFolders script...
DownloadValidateMEPFScriptFailed = Unable to download ValidateMailEnabledPublicFolders script. Download it from https://aka.ms/validatemepf to {0} and execute Sync-ModernMailPublicFolders.ps1 again.
FoundInconsistenciesWithMEPFs = Found some inconsistencies with mail-enabled public folders. To fix them run Sync-ModernMailPublicFolders.ps1 script with -FixInconsistencies parameter. 
MailDisablePublicFoldersInFile = Mail disabling public folders mentioned in {0}.
DeleteOrphanedMailPublicFoldersInFile = Deleting orphaned mail public folders mentioned in {0}.
DeleteDuplicateMailPublicFoldersinFile = Deleting duplicate mail public folders mentioned in {0}.
AddAddressesFromDuplicates = Adding email addresses from duplicates...
MailEnablePublicFoldersWithProxyGUIDinFile = Mail-enabling public folders mentioned in {0}.
MailEnablePFAssociatedToDisconnectedMEPFsInFile = Resetting MailEnabled and MailRecipientGuid properties of public folders corresponding to disconnected mepfs mentioned in {0}.
EXOV2ModuleNotInstalled = This script uses modern authenticaion to connect to Exchange Online and requires EXO V2 module to be installed. Please follow the instructions at https://docs.microsoft.com/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-the-exo-v2-module to install EXO V2 module.
###PSLOC
'@