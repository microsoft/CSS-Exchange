# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function funcManagedFolderProperties {
    Get-ManagedFolderMailboxPolicy | Select-Object * | Export-Clixml "$Mailbox - MRM Managed Folder Mailbox Policies - All.xml"
    Get-ManagedFolder | Select-Object * | Export-Clixml "$Mailbox - MRM Managed Folders - All.xml"
    Get-ManagedContentSettings | Select-Object * | Export-Clixml "$Mailbox - MRM Managed Content Settings - All.xml"
    $MailboxManagedFolderPolicy = Get-ManagedFolderMailboxPolicy $MailboxProps.ManagedFolderMailboxPolicy
    $msgRetentionProperties = "This Mailbox has the following Retention Policy assigned:"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "##################################################################################################################"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = $MailboxManagedFolderPolicy | Select-Object -ExpandProperty Name
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = ""
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "Here are the Details of the Managed Folders for this Mailbox:"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "##################################################################################################################"
    $msgRetentionProperties >> ($File)
    foreach ($Folder in $MailboxManagedFolderPolicy.ManagedFolderLinks) {
        Get-ManagedFolder $Folder | Format-List Name, Description, Comment, FolderType, FolderName, StorageQuota, LocalizedComment, MustDisplayCommentEnabled, BaseFolderOnly, TemplateIds >> ($File)
    }
    $msgRetentionProperties = "Here are the Details of the Managed Content Settings for this Mailbox:"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "##################################################################################################################"
    $msgRetentionProperties >> ($File)
    foreach ($Folder in $MailboxManagedFolderPolicy.ManagedFolderLinks.FolderType) {
        Get-ManagedContentSettings -Identity $Folder | Format-List Name, Identity, Description, MessageClassDisplayName, MessageClass, RetentionEnabled, RetentionAction, AgeLimitForRetention, MoveToDestinationFolder, TriggerForRetention, MessageFormatForJournaling, JournalingEnabled, AddressForJournaling, LabelForJournaling, ManagedFolder, ManagedFolderName >> ($File)
    }
    return
}
