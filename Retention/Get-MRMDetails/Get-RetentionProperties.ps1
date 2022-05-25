# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-RetentionInformation.ps1

function funcRetentionProperties {
    # Temp actions
    $retentionInformation = Get-RetentionInformation $MailboxProps
    # Export's All Retention Policies and Retention Policy Tags for the entire tenant
    $retentionInformation.RetentionPolicies | Select-Object * | Export-Clixml "$Mailbox - MRM Retention Policies for entire Tenant.xml"
    $retentionInformation.RetentionTags | Select-Object * | Export-Clixml "$Mailbox - MRM Retention Tags for entire Tenant.xml"
    # Export the users mailbox information
    $MailboxProps | Select-Object * | Out-File "$Mailbox - Mailbox Information.txt"

    # Get the Diagnostic Logs for user
    $logProps = Export-MailboxDiagnosticLogs $Mailbox -ExtendedProperties
    $xmlprops = [xml]($logProps.MailboxLog)
    $ELCRunLastData = $xmlprops.Properties.MailboxTable.Property | Where-Object { $_.Name -like "*elc*" }
    [datetime]$ELCLastSuccess = [datetime](($ELCRunLastData | Where-Object { $_.name -eq "ELCLastSuccessTimestamp" }).value)


    # Get the Component Diagnostic Logs for user
    $error.Clear()
    $ELCLastRunFailure = (Export-MailboxDiagnosticLogs $Mailbox -ComponentName MRM).MailboxLog
    ($error[0]).Exception | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt" -Append
    if ($NULL -ne $ELCLastRunFailure) {
        $ELCLastRunFailure | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt"
        [datetime]$ELCLastFailure = [datetime]$ELCLastRunFailure.mailboxlog.split("Exception")[0]
        if ($ELCLastSuccess -gt $ELCLastFailure) {
            "MRM has run successfully since the last failure.  This makes the Component Diagnostic Logs file much less interesting.
		----------------------------------------------------------------------------------------------------------------------
		" | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt"
            $ELCRunLastData | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt" -Append
            "MRM has run successfully since the failure recorded in this file.  This failure is much less interesting.
		----------------------------------------------------------------------------------------------------------------------
		" | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt"
            $ELCLastRunFailure | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt" -Append
        } else {
            "MRM has FAILED recently.  See the Component Diagnostic Logs file for details.
		-----------------------------------------------------------------------------
		" | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt"
            $ELCRunLastData | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt" -Append
            "This log contains an interesting and very recent failure.
		---------------------------------------------------------
		" | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt"
            $ELCLastRunFailure | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt" -Append
        }
    } else {
        "MRM has not encountered a failure.  Component Diagnostic Log is empty." | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt"
        "MRM has never failed for this user.
      -----------------------------------
      " | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt"
        $ELCRunLastData | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt" -Append
    }



    Search-AdminAuditLog -Cmdlets Start-ManagedFolderAssistant, Set-RetentionPolicy, Set-RetentionPolicyTag, Set-MailboxPlan, Set-Mailbox | Export-Csv "$Mailbox - MRM Component Audit Logs.csv" -NoTypeInformation
    # Get the Mailbox Folder Statistics
    $fldrStats = Get-MailboxFolderStatistics $MailboxProps.Identity -IncludeAnalysis -IncludeOldestAndNewestItems
    $fldrStats | Sort-Object FolderPath | Out-File "$Mailbox - Mailbox Folder Statistics.txt"
    $fldrStats | Select-Object FolderPath, ItemsInFolder, ItemsInFolderAndSubfolders, FolderAndSubFolderSize, NewestItemReceivedDate, OldestItemReceivedDate | Sort-Object FolderPath | Format-Table -AutoSize -Wrap | Out-File "$Mailbox - Mailbox Folder Statistics (Summary).txt"
    # Get the MRM 2.0 Policy and Tags Summary
    $MailboxRetentionPolicy = $retentionInformation.MailboxRetentionPolicy
    $mrmPolicy = $MailboxRetentionPolicy | Select-Object -ExpandProperty Name
    $mrmMailboxTags = $retentionInformation.MailboxRetentionTags
    $msgRetentionProperties = "This Mailbox has the following Retention Hold settings assigned:"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "##################################################################################################################"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "Retention Hold is " + ($MailboxProps).RetentionHoldEnabled + " for the mailbox (True is Enabled, False is Disabled)"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "Retention Hold will start on " + ($MailboxProps).StartDateForRetentionHold + " (no value is Disabled)"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "Retention Hold will end on " + ($MailboxProps).EndDateForRetentionHold + " (no value is Disabled)"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = ""
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "This Mailbox has the following Retention Policy assigned:"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "##################################################################################################################"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = $mrmPolicy
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = ""
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "The Retention Policy " + $mrmPolicy + " has the following tags assigned to the mailbox " + $MailboxProps + ":"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "##################################################################################################################"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = ($MailboxRetentionPolicy).RetentionPolicyTagLinks | Sort-Object
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = ""
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "The Mailbox " + $MailboxProps.Identity + " says it has all of the following tags assigned to it (If different than above user added personal tags via OWA):"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "##########################################################################################################################################"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = ($mrmMailboxTags).Name | Sort-Object
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = ""
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "Here are the Details of the Retention Policy Tags for this Mailbox:"
    $msgRetentionProperties >> ($File)
    $msgRetentionProperties = "##################################################################################################################"
    $msgRetentionProperties >> ($File)
    foreach ($Tag in $MailboxRetentionPolicy.RetentionPolicyTagLinks) {
        Get-RetentionPolicyTag $Tag | Format-List Name, Description, Comment, AddressForJournaling, AgeLimitForRetention, LocalizedComment, LocalizedRetentionPolicyTagName, MessageClass, MessageFormatForJournaling, MustDisplayCommentEnabled, RetentionAction, RetentionEnabled, RetentionId, SystemTag, Type >> ($File)
    }
    $msgRetentionProperties = "##################################################################################################################"
    $msgRetentionProperties >> ($File)
    if ($retentionInformation.TotalItemSize -le 10485760 ) {
        #If the Total Item size in the mailbox is less than or equal to 10MB MRM will not run. Both values converted to bytes.
        $msgRetentionProperties = "Primary Mailbox is less than 10MB.  MRM will not run until mailbox exceeds 10MB.  Current Mailbox sixe is " + $retentionInformation.TotalItemSize + " bytes."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "##################################################################################################################"
        $msgRetentionProperties >> ($File)
    } else {
        $msgRetentionProperties = "Primary Mailbox exceeds 10MB.  Minimum mailbox size requirment for MRM has been met.  Current Mailbox sixe is " + $retentionInformation.TotalItemSize + " bytes."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "##################################################################################################################"
        $msgRetentionProperties >> ($File)
    }
    if ($retentionInformation.RecoveryItemFillQuotaPercentage -gt 98) {
        #if Recoverable items in the primary mailbox is more than 98% full highlight it as a problem.
        $msgRetentionProperties = "Primary Mailbox is critically low on free quota for Recoverable Items. "
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.TotalDeletedItemSize) bytes consumed in Recoverable Items."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.RecoverableItemsQuota) bytes is the maximum. "
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "##################################################################################################################"
        $msgRetentionProperties >> ($File)
    } else {
        $msgRetentionProperties = "Primary Mailbox Recoverable Items are not yet at quota."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.TotalItemSize) bytes is the current Recoverable Items size in Primary Mailbox."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.RecoverableItemsQuota) bytes is the maximum."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "##################################################################################################################"
        $msgRetentionProperties >> ($File)
    }
    if ($retentionInformation.ArchiveRecoveryItemFillQuotaPercentage -gt 98) {
        #if Recoverable items in the primary archive mailbox is more than 98% full highlight it as a problem.
        $msgRetentionProperties = "Primary Archive Mailbox is critically low on free quota for Recoverable Items. "
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.ArchiveTotalDeletedItemSize) bytes consumed in Recoverable Items."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.ArchiveRecoverableItemsQuota) bytes is the maximum."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "##################################################################################################################"
        $msgRetentionProperties >> ($File)
    } else {
        $msgRetentionProperties = "Primary Archive Mailbox is not in imminent danger of filling Recoverable Items Quota."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.ArchiveTotalDeletedItemSize) bytes consumed in Recoverable Items."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.ArchiveRecoverableItemsQuota) bytes is the maximum available."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "##################################################################################################################"
        $msgRetentionProperties >> ($File)
    }
    if ($retentionInformation.ArchiveTotalFillPercentage -gt 98) {
        #if Recoverable items in the primary archive mailbox is more than 98% full highlight it as a problem.
        $msgRetentionProperties = "Primary Archive Mailbox is critically low on free quota for Visible Items. "
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.ArchiveTotalItemSize) bytes consumed in Recoverable Items."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.ArchiveQuota) bytes is the maximum."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "##################################################################################################################"
        $msgRetentionProperties >> ($File)
    } else {
        $msgRetentionProperties = "Primary Archive Mailbox is not in imminent danger of filling the mailbox quota."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.ArchiveTotalItemSize) bytes consumed in Recoverable Items."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "$($retentionInformation.ArchiveQuota) bytes is the maximum."
        $msgRetentionProperties >> ($File)
        $msgRetentionProperties = "##################################################################################################################"
        $msgRetentionProperties >> ($File)
    }

    return
}
