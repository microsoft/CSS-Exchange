ConvertFrom-StringData @'
###PSLOC
FindingPublicFoldersAcceptedDomain = Locating the well-known accepted domain for public folder email routing...
FoundPublicFolderAcceptedDomain = Found '{0}'
EnumeratingMailEnabledPublicFolders = Enumerating mail-enabled public folders...
EnumeratingMailEnabledPublicFoldersComplete = Enumerating mail-enabled public folders completed... {0} folder(s) found
StampingMailEnabledPublicFolders = Stamping ExternalEmailAddress on the mail-enabled public folder(s)...
StampedMailEnabledPublicFolders = Stamped Folder(s) : {0}
AlreadyStampedMailEnabledPublicFolders = Following mail-enabled public folder(s) are skipped as their ExternalEmailAddress property is stamped with a different email address. Please update these manually, if required: \n{0}
MissingExoDomain = Cannot find an accepted domain with the well-known name 'PublicFolderDestination_78c0b207_5ad2_4fee_8cb9_f373175b3f99'. This is created as part of public folders migration and should be present for mail routing to Exchange Online to work correctly
NoMailEnabledPublicFolders = No mail-enabled public folders found
ProgressBarActivity = Stamping external email address on the mail-enabled public folders...
ConfirmationTitle = Stamp ExternalEmailAddress on the mail-enabled public folders
ConfirmationQuestion = Total mail-enabled public folder(s): {0}\nSkipping {1} mail-enabled public folder(s) which are already stamped with their exchange online addresses.\nSkipping {2} mail-enabled public folder(s) which are stamped with a different ExternalEmailAddress.\nThis script will update the remaining {3} mail-enabled public folder(s) without an ExternalEmailAddress.\nDo you really want to proceed?
ConfirmationYesOption = &Yes
ConfirmationNoOption = &No
ConfirmationYesOptionHelp = Proceed and stamp ExternalEmailAddress on mail-enabled public folder(s) which aren't already stamped
ConfirmationNoOptionHelp = STOP! mail-enabled public folders will not be stamped
TitleForListOfMepfsRequireStamping = Following {0} mail-enabled public folder(s) requires stamping:
TitleForListOfMepfsStampedWithValidAddress = Following {0} mail-enabled public folder(s) are already stamped with their exchange online addresses:
TitleForListOfMepfsStampedWithOtherAddress = Following {0} mail-enabled public folder(s) are stamped with different addresses:
NoMailEnabledPublicFoldersRequiresStamping = No mail-enabled public folder requires an ExternalEmailAddress stamping
ExecutionSummaryFile = Execution summary is stored in {0} file
StampingConfirmation = Confirmation for stamping: {0}
RunningWithConfirmation = Running with user confirmation
###PSLOC
'@