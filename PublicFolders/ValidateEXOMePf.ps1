# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [Parameter(Mandatory = $false)]
    [String]$ExportPath,
    [Parameter(Mandatory = $true)]
    [String]$PFolder,
    [Parameter(Mandatory = $false)]
    [String]$AffectedUser)
$Script:ReportName = "ValidateMePfREPORT.txt"
#Requires -Modules @{ModuleName="ExchangeOnlineManagement"; ModuleVersion="3.0.0" }
function LogError {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentStatus,

        [Parameter(Mandatory = $true)]
        [string]$Function,

        [Parameter(Mandatory = $true)]
        [string]$CurrentDescription

    )
    [PSCustomObject]@{
        Function    = $Function
        Description = $CurrentDescription
        Status      = $CurrentStatus
    } | Export-Csv $ExportPath\ValidateMePfREPORTChecksLogging.csv -NoTypeInformation -Append
}
function WriteToScreenAndLog {
    param(
        [Parameter(Mandatory = $true)]
        [String]$Issue,

        [Parameter(Mandatory = $true)]
        [String]$Fix
    )
    Write-Host $Issue -ForegroundColor Red
    $Issue | Out-File $ExportPath\$Script:ReportName -Append
    Write-Host $Fix -ForegroundColor Green
    $Fix+"`n" | Out-File $ExportPath\$Script:ReportName -Append
    Write-Host
}
function Connect2EXO {
    try {

        Write-Host "Connecting to EXO, please enter Global administrator credentials when prompted!" -ForegroundColor Yellow
        Connect-ExchangeOnline -ErrorAction Stop
        $CurrentDescription= "Connecting to EXO"
        $CurrentStatus = "Success"
        LogError -CurrentStatus $CurrentStatus -Function "Connecting to EXO" -CurrentDescription $CurrentDescription
        Write-Host "Connected to EXO successfully" -ForegroundColor Cyan
    } catch {
        $ErrorEncountered=$Global:error[0].Exception
        $CurrentDescription = "Connecting to EXO"
        $CurrentStatus = "Failure"
        LogError -CurrentStatus $CurrentStatus -Function "Connecting to EXO" -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $ErrorEncountered -ForegroundColor Red
        Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        break
    }
}
function QuitEXOSession {
    if ($null -eq $SessionCheck) {
        try {
            Write-Host "Quitting EXO PowerShell session..." -ForegroundColor Yellow
            Disconnect-ExchangeOnline -ErrorAction Stop -Confirm:$false
            $CurrentDescription= "Disconnecting from EXO"
            $CurrentStatus = "Success"
            LogError -CurrentStatus $CurrentStatus -Function "Disconnecting from EXO" -CurrentDescription $CurrentDescription
            Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            break
        } catch {
            $ErrorEncountered=$Global:error[0].Exception
            $CurrentDescription = "Disconnecting from EXO"
            $CurrentStatus = "Failure"
            LogError -CurrentStatus $CurrentStatus -Function "Disconnecting from EXO" -CurrentDescription $CurrentDescription
            Write-Host "Error encountered during executing the script!"-ForegroundColor Red
            Write-Host $ErrorEncountered -ForegroundColor Red
            Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            break
        }
    }
}
function AskForFeedback {
    Write-Host "Please rate the script experience & tell us what you liked or what we can do better over https://aka.ms/MePfHealthFeedback" -ForegroundColor Cyan
    "Please rate the script experience & tell us what you liked or what we can do better over https://aka.ms/MePfHealthFeedback" | Out-File $ExportPath\$Script:ReportName -Append
}
function ValidateMePfMbx {
    param([String]$PublicFolderMbxGuid)

    try {
        $PfMbx=Get-mailbox -PublicFolder $PublicFolderMbxGuid -ErrorAction stop
        return $PfMbx
    } catch {
        $DistinguishedName=(Get-Mailbox -PublicFolder -ResultSize unlimited -SoftDeletedMailbox $PublicFolderMbxGuid -ErrorAction SilentlyContinue).DistinguishedName
        if ($null -ne $DistinguishedName -and $DistinguishedName.contains("OU=Soft Deleted Objects")) {
            $Fix= "FIX -->Please follow the following article https://learn.microsoft.com/en-us/exchange/collaboration-exo/public-folders/recover-deleted-public-folder-mailbox
            to validate if the content public folder mailbox:$PublicFolderMbxGuid was soft-deleted then restore it back"
            $Issue="Public folder content mailbox $PublicFolderMbxGuid is soft deleted which is a blocker for receiving emails over the mail public folder"
            WriteToScreenAndLog -Issue $Issue -Fix $Fix
            AskForFeedback
            QuitEXOSession
        } else {
            #Pfmbx is hard deleted
            $Fix= "FIX -->Please follow the below steps to create a new public folder using below steps:
                            1-Follow the following article https://aka.ms/disablempf to mail disable the affected public folder
                            2-Create public folder using following article https://aka.ms/newpf with same name $($MailPublicFolder.Name)
                            3-Follow the following article https://aka.ms/EnableMPF to mail enable the newly created public folder with the same email address $($MailPublicFolder.PrimarySmtpAddress)"
            $Issue="Public folder mailbox $DistinguishedName is hard deleted(Purged) which is a blocker for receiving emails over the public folder"
            WriteToScreenAndLog -Issue $Issue -Fix $Fix
            AskForFeedback
            QuitEXOSession
        }
    }
}
function CheckMePfHealth {
    param([PSCustomObject]$MailPublicFolder)
    try {
        $LegacyExchangeDN=$MailPublicFolder.LegacyExchangeDN
        $count=$LegacyExchangeDN.split("=").count
        $PublicFolder=Get-PublicFolder $LegacyExchangeDN.split("=")[$count-1] -ErrorAction stop
        if ($PublicFolder.MailEnabled -eq $true) {
            $HasValue=$PublicFolder.MailRecipientGuid.Guid
            if ($null -eq $HasValue -or $HasValue -eq "00000000-0000-0000-0000-000000000000") {
                #MailRecipientGuid is null give action & quit
                $Fix= "FIX --> Please follow the following article https://aka.ms/disablempf to mail disable the affected public folder then follow the following article https://aka.ms/EnableMPF to mail enable the affected public folder to generate a GUID over MailRecipientGuid parameter, validate MailRecipientGuid parameter has a GUID using https://aka.ms/getpf article."
                $Issue="Mail-enabled public folder $($PublicFolderInfo.PublicFolder.Identity) is unhealthy e.g MailRecipientGuid parameter is found empty/null which is a blocker for receiving emails over the public folder"
                WriteToScreenAndLog -Issue $Issue -Fix $Fix
                AskForFeedback
                QuitEXOSession
            }
            if ($HasValue -notlike $MailPublicFolder.guid.guid) {
                #Check if "MailRecipientGuid vs Guid" are not equal
                $Fix= "FIX --> Please follow the following article https://aka.ms/disablempf to mail disable the affected public folder then follow the following article https://aka.ms/EnableMPF to mail enable the affected public folder to generate a unique GUID across public folder MailRecipientGuid & mail-enabled public folder Guid parameter"
                $Issue="Mail-enabled public folder $($PublicFolderInfo.PublicFolder.Identity) is unhealthy e.g discrepancy across MailRecipientGuid & mail-enabled public folder Guid found which is a blocker for receiving emails over the public folder"
                WriteToScreenAndLog -Issue $Issue -Fix $Fix
                AskForFeedback
                QuitEXOSession
            }
            return $PublicFolder
        } else {
            #MailEnabled is false give action & quit
            #Validate if content MBX is soft/hard deleted
            $PfMbx=ValidateMePfMbx($PublicFolder.ContentMailboxGuid.Guid)
            if ($null -ne $PfMbx) {
                $Fix= "FIX -->Please follow the following article https://aka.ms/EnableMPF to mail enable the affected public folder, validate MailEnabled parameter is True using https://aka.ms/getpf article."
                $Issue="Public folder $($PublicFolder.Identity) is either not mail-enabled or unhealthy e.g MailEnabled parameter is set to False which is a blocker for receiving emails over the public folder"
                WriteToScreenAndLog -Issue $Issue -Fix $Fix
                AskForFeedback
                QuitEXOSession
            }
        }
    } catch {
        #Orphaned MePf, on-premises PF scenario
        $OrganizationConfig =Get-OrganizationConfig -ErrorAction stop
        if ($OrganizationConfig.PublicFoldersEnabled -like "Remote") {
            #on-premises PF scenario
            #This script does check only EXO PFs
            $Fix= "FIX -->Please follow following article https://aka.ms/ssv to verify mail public folder health"
            $Issue="Unfortunately public folder $($MailPublicFolder.Identity) is hosted on-premises which the script doesn't support diagnosing for the time being."
            WriteToScreenAndLog -Issue $Issue -Fix $Fix
            QuitEXOSession
        } else {
            #Orphaned MePf
            $Fix= "FIX -->Please follow the following article https://aka.ms/RestorePfeither to validate if the public folder was soft-deleted then restore it back else create a new public folder using below steps:
                            1-Follow the following article https://aka.ms/disablempf to mail disable the affected public folder
                            2-Create public folder using following article https://aka.ms/newpf with same name $($MailPublicFolder.Name)
                            3-Follow the following article https://aka.ms/EnableMPF to mail enable the newly created public folder with the same email  address $($MailPublicFolder.PrimarySmtpAddress)"
            $Issue="Public folder $($MailPublicFolder.Identity) is not existing or might have been purged which is a blocker for receiving emails over the public folder"
            WriteToScreenAndLog -Issue $Issue -Fix $Fix
            AskForFeedback
            QuitEXOSession
        }
    }
}
function GetPublicFolderInfo {
    param([String]$PFolder)
    try {
        $MailPublicFolder=Get-MailPublicFolder $PFolder -ErrorAction stop
        Write-Host "Retrieving PublicFolder $($MailPublicFolder.Identity) information for diagnosing!,please wait as this might take awhile...." -ForegroundColor Yellow
        $PublicFolder=CheckMePfHealth($MailPublicFolder)
        $PublicFolderStats=Get-PublicFolderStatistics $PublicFolder.EntryId -ErrorAction stop
        $PfMbx=ValidateMePfMbx($($PublicFolder.ContentMailboxGuid.Guid))
        $PfMbxStats=Get-mailboxStatistics $PublicFolder.ContentMailboxGuid.Guid -ErrorAction stop
        $OrganizationConfig =Get-OrganizationConfig -ErrorAction stop
        [Int64]$DefaultPublicFolderProhibitPostQuota=[Int64]$OrganizationConfig.DefaultPublicFolderProhibitPostQuota.Split("(")[1].split(" ")[0].Replace(",", "")
        [Int64]$DefaultPublicFolderIssueWarningQuota=[Int64]$OrganizationConfig.DefaultPublicFolderIssueWarningQuota.Split("(")[1].split(" ")[0].Replace(",", "")
        [Int64]$PublicFolderSize=[Int64]$PublicFolderStats.TotalItemSize.Split("(")[1].split(" ")[0].replace(",", "")+[Int64]$PublicFolderStats.TotalDeletedItemSize.Split("(")[1].split(" ")[0].replace(",", "")
        [PSCustomObject]$PublicFolderInfo=@{
            PublicFolder                         = $PublicFolder
            MailPublicFolder                     = $MailPublicFolder
            PfMbx                                = $PfMbx
            PublicFolderStats                    = $PublicFolderStats
            PfMbxStats                           = $PfMbxStats
            PublicFolderSize                     = $PublicFolderSize
            DefaultPublicFolderProhibitPostQuota = $DefaultPublicFolderProhibitPostQuota
            DefaultPublicFolderIssueWarningQuota = $DefaultPublicFolderIssueWarningQuota
            OrganizationConfig                   = $OrganizationConfig
        }
        return $PublicFolderInfo
        $CurrentDescription = "Retrieving: $($PublicFolder.identity) whole information for diagnosing"
        $CurrentStatus = "Success"
        LogError -Function "Retrieve public folder whole information statistics" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    }

    catch {
        $ErrorEncountered=$Global:error[0].Exception
        $CurrentDescription = "Retrieving: $($PublicFolder.identity) whole information for diagnosing"
        $CurrentStatus = "Failure with error: "+$ErrorEncountered
        LogError -Function "Retrieve public folder whole information statistics" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $ErrorEncountered -ForegroundColor Red
        QuitEXOSession
    }
}
function ValidateMePfMapping {
    param([PSCustomObject]$PublicFolderInfo)
    if ($PublicFolderInfo.PublicFolder.EntryId -ne $PublicFolderInfo.MailPublicFolder.EntryID) {
        $Fix= "FIX --> Please follow the following article https://aka.ms/setmepf to set the correct EntryID:$($PublicFolderInfo.PublicFolder.EntryId) over the affected mail-enabled public folder"
        $Issue="Mail-enabled public folder $($PublicFolderInfo.PublicFolder.Identity) is unhealthy e.g EntryID parameter discrepancy is a blocker for receiving mails"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
    }
    if ($PublicFolderInfo.PublicFolder.ContentMailboxName -ne $PublicFolderInfo.MailPublicFolder.ContentMailbox) {
        $Fix= "FIX --> To fix that please modify mail public folder EntryID 'e.g., flip the last number to any number other than the one assigned' stamp it over the mail public folder
        then re-stamp the actual EntryID again on it to solve the issue and correct the ContentMailbox parameter over the affected mail-enabled public folder
        Please follow the below steps:
        ------------------------------
        EntryID for the requested folder is $($PublicFolderInfo.MailPublicFolder.EntryID)
        Set-MailPublicFolder $($MailPublicFolder.PrimarySmtpAddress) -EntryId 'replace with the mail public folder EntryID value and ensure to modify last number on the right'
        Set-MailPublicFolder $($MailPublicFolder.PrimarySmtpAddress) -EntryId 'replace with EntryID for the requested folder value'
        For more information please check the following article https://aka.ms/setmepf"
        $Issue="Mail-enabled public folder $($PublicFolderInfo.PublicFolder.Identity) is unhealthy e.g ContentMailbox parameter discrepancy is a blocker for receiving mails"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
    }
}
function ValidateMePfAddress {
    param([PSCustomObject]$PublicFolderInfo)
    #Validate if routing smtp address is stamped
    if ($OrganizationConfig.PublicFoldersEnabled -like "Remote") {
        $EmailAddresses=$PublicFolderInfo.MailPublicFolder.EmailAddresses
        foreach ($EmailAddress in $EmailAddresses) {
            if ($EmailAddress.ToLower().contains("mail.onmicrosoft.com")) {
                $skip="Enabled"
                break
            }
        }
        if ($skip -ne "Enabled") {
            $FIX="FIX --> Depending on your source on-premises exchange version please re-run mail public folder sync scripts then re-validate if the mail public folder was stamped
            correctly with routing address(domain.mail.onmicrosoft.com) for more information please check https://aka.ms/LegacyPFCoEx for legacy or https://aka.ms/ModernPFCoEx for modern public folders"
            $Issue="Routing address (domain.mail.onmicrosoft.com) is missing from mail public folder $($PublicFolderInfo.PublicFolder.identity) EmailAddresses parameter"
            WriteToScreenAndLog -Issue $Issue -Fix $fix
        }
    }
}
function ValidateContentMBXQuota {
    param([PSCustomObject]$PublicFolderInfo)
    [Int64]$PfMbxProhibitSendReceiveQuotaInB=[Int64]$PublicFolderInfo.PfMbx.ProhibitSendReceiveQuota.Split("(")[1].split(" ")[0].Replace(",", "")
    [Int64]$PfMbxStatsInB=[Int64]$PublicFolderInfo.PfMbxStats.TotalItemSize.Value.ToString().Split("(")[1].split(" ")[0].Replace(",", "")
    if ($PfMbxStatsInB -ge $PfMbxProhibitSendReceiveQuotaInB) {
        if ($PfMbxProhibitSendReceiveQuotaInB -ge 107374182400 ) {
            $article="https://techcommunity.microsoft.com/t5/exchange-team-blog/how-exchange-online-automatically-cares-for-your-public-folder/ba-p/2050019"
            $Fix="FIX --> To resolve a scenario where content public folder mailbox has reached its $PfMbxProhibitSendReceiveQuotaInGB quota value either check,
            1.If you have Giant public folders over that content mailbox
            2.If MovedItemRetention is keeping the mailbox full while AutoSplit occurred successfully
            3.If the AutoSplit status is halted
            For more information on all the above scenarios & HowTo mitigate, please check the following article $article"
            $Issue="Public folder mailbox $($PublicFolderInfo.PfMbx.name) TotalItemSize value has reached its $PfMbxProhibitSendReceiveQuotaInB bytes quota value"
            WriteToScreenAndLog -Issue $Issue -Fix $Fix
        } else {
            $article="https://learn.microsoft.com/en-us/powershell/module/exchange/set-mailbox?view=exchange-ps#-prohibitsendreceivequota"
            $Fix="FIX --> Please modify public folder mailbox:$($PublicFolderInfo.PfMbx.name) ProhibitSendReceiveQuota to its default value(100 GB),for more information please check the following article $article"
            $Issue="Public folder mailbox $($PublicFolderInfo.PfMbx.name) TotalItemSize value has reached its $PfMbxProhibitSendReceiveQuotaInB bytes quota value"
            WriteToScreenAndLog -Issue $Issue -Fix $Fix
        }
    }
}
function ValidateMePfQuota {
    param([PSCustomObject]$PublicFolderInfo)
    #Validate if DefaultPublicFolderProhibitPostQuota at the organization level applies
    if ($PublicFolderInfo.PublicFolder.ProhibitPostQuota -eq "unlimited") {
        #Checking if public folder total size has reached organization public folder DefaultPublicFolderProhibitPostQuota value!"
        if ($PublicFolderInfo.PublicFolderSize -ge $PublicFolderInfo.DefaultPublicFolderProhibitPostQuota) {
            #validate if Giant PF to lower the PF size down else increase Org DefaultPublicFolderProhibitPostQuota
            if ($PublicFolderInfo.DefaultPublicFolderProhibitPostQuota -ge 21474836480) {
                $Fix= "FIX --> Please follow the following article https://aka.ms/Setorgconfig to modify the Organization DefaultPublicFolderProhibitPostQuota:$($PublicFolderInfo.DefaultPublicFolderProhibitPostQuota) Bytes & DefaultPublicFolderIssueWarningQuota:$($PublicFolderInfo.DefaultPublicFolderIssueWarningQuota) Bytes values to avoid having Giant public folders with sizes exceeding 20GB, then delete or move items from that giant folder $($PublicFolderInfo.PublicFolder.Identity) to reduce the size of that public folder to an appropriate size accommodating with newly modified organization values."
                $Issue="Public folder $($PublicFolderInfo.PublicFolder.Identity) size has exceeded Organization DefaultPublicFolderProhibitPostQuota value!"
                WriteToScreenAndLog -Issue $Issue -Fix $Fix
            } else {
                $Fix= "FIX --> Please follow the following article https://aka.ms/Setorgconfig to modify the Organization DefaultPublicFolderProhibitPostQuota:$($PublicFolderInfo.DefaultPublicFolderProhibitPostQuota) Bytes & DefaultPublicFolderIssueWarningQuota:$($PublicFolderInfo.DefaultPublicFolderIssueWarningQuota) Bytes values to accommodate the public folder $($PublicFolderInfo.PublicFolder.Identity) size:$($PublicFolderInfo.PublicFolderSize) Bytes"
                $Issue="Public folder $($PublicFolderInfo.PublicFolder.Identity) size has exceeded Organization DefaultPublicFolderProhibitPostQuota value!"
                WriteToScreenAndLog -Issue $Issue -Fix $Fix
            }
        }
    } else {
        [Int64]$PFProhibitPostQuota=[Int64]$PublicFolderInfo.PublicFolder.ProhibitPostQuota.split("(")[1].split(" ")[0].replace(",", "")
        if ($PublicFolderInfo.PublicFolderSize -ge $PFProhibitPostQuota) {
            #validate if Giant PF to lower the PF size down else increase PFProhibitPostQuota or inherit Org DefaultPublicFolderProhibitPostQuota
            if ($PFProhibitPostQuota -ge 21474836480) {
                $Fix= "FIX --> Please follow the following article https://aka.ms/Setorgconfig to modify the Organization DefaultPublicFolderProhibitPostQuota:$($PublicFolderInfo.DefaultPublicFolderProhibitPostQuota) Bytes & DefaultPublicFolderIssueWarningQuota:$($PublicFolderInfo.DefaultPublicFolderIssueWarningQuota) Bytes values to avoid having Giant public folders with sizes exceeding 20GB, then delete or move items from that giant folder $($PublicFolderInfo.PublicFolder.Identity) to reduce the size of that public folder to an appropriate size accommodating with newly modified organization values."
                $Issue="Public folder $($PublicFolderInfo.PublicFolder.Identity) size has exceeded Individual Public Folder ProhibitPostQuota value"
                WriteToScreenAndLog -Issue $Issue -Fix $Fix
            } else {
                $Fix= "FIX --> Please follow the following article https://aka.ms/setpf to modify the Public Folder ProhibitPostQuota:$PFProhibitPostQuota Bytes value to accommodate the public folder $($PublicFolderInfo.PublicFolder.Identity) size:$($PublicFolderInfo.PublicFolderSize) Bytes"
                $Issue="Public folder $($PublicFolderInfo.PublicFolder.Identity) size has exceeded Individual Public Folder ProhibitPostQuota value"
                WriteToScreenAndLog -Issue $Issue -Fix $Fix
            }
        }
    }
}
function ValidateDbEbDomain {
    param([PSCustomObject]$PublicFolderInfo)
    $MailPublicFolderDomain=$PublicFolderInfo.MailPublicFolder.PrimarySmtpAddress.split("@")[1]
    $AcceptedDomainType=(Get-AcceptedDomain -Identity $MailPublicFolderDomain -ErrorAction stop).DomainType
    if ($AcceptedDomainType -eq "Authoritative") {
        $HostedConnectionFilterPolicy=Get-HostedConnectionFilterPolicy -ErrorAction stop | Where-Object { $_.IsDefault -eq "True" }
        $DirectoryBasedEdgeBlockModeStatus=$HostedConnectionFilterPolicy.DirectoryBasedEdgeBlockMode
        if ($DirectoryBasedEdgeBlockModeStatus -eq "Default") {
            $article="https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-directory-based-edge-blocking"
            $Fix="FIX --> Please file a support case for microsoft to disable DbEb on the whole tenant(Recommended) else please ensure that MePf smtp domain $MailPublicFolderDomain DomainType is set to InternalRelay,for more information please check the following article $article"
            $Issue="DirectoryBasedEdgeBlockMode is activated on the tenant"
            WriteToScreenAndLog -Issue $Issue -Fix $Fix
        }
    }
}
function GetUserPermissions {
    param([PSCustomObject]$Perms)
    $WorkingPermissions=@("CreateItems", "Author", "Contributor", "Editor", "Owner", "PublishingAuthor",
        "PublishingEditor")
    if ($null -ne $Perms) {
        foreach ($perm in $Perms.AccessRights) {
            if ($WorkingPermissions.ToLower().Contains($($perm.ToLower()))) {
                return "user has permission"
            }
        }
        return "user has no permission"
    }

    else {
        return "user has no permission"
    }
}
function ValidateMePfExtRec {
    param([PSCustomObject]$PublicFolderInfo)
    $AnonymousPermsUser=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.Identity -User Anonymous -ErrorAction SilentlyContinue
    $Result=GetUserPermissions($AnonymousPermsUser)
    if ($Result -like "user has no permission") {
        $Fix= "FIX --> Please follow the following article https://aka.ms/addPFperm to grant Anonymous user the least sufficient permission e.g.CreateItems over the requested public folder"
        $Issue="Anonymous user has either no sufficient/existing permissions on Public folder $($PublicFolderInfo.PublicFolder.Identity)"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
    }
}
function ValidateUserPermissions {
    param([PSCustomObject]$Perms, [PSCustomObject]$PermsUserPfMbx)
    if ($Perms.AccessRights.count -eq $PermsUserPfMbx.AccessRights.count) {
        foreach ($Perm in $perms.AccessRights) {
            if (!$PermsUserPfMbx.AccessRights.contains($Perm)) {
                return "sync issue exist"
            }
        }
        return "no sync issue exist"
    }
    return "sync issue exist"
}
function ValidateMePfPermSync {
    param([Parameter(Mandatory = $true)]
        [PSCustomObject]$PublicFolderInfo,
        [Parameter(Mandatory = $true)]
        [string]$AffectedUser)
    #validate explicit permission sync issue
    try {
        $User=Get-Mailbox $AffectedUser -ErrorAction stop
        $UserPfMbx=Get-mailbox -PublicFolder $($User.EffectivePublicFolderMailbox) -ErrorAction stop
        $ExplicitPerms=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.EntryId -User $User.Guid.Guid.ToString() -ErrorAction SilentlyContinue
        #Validate if there's no perm sync issue
        $ExplicitPermsUserPfMbx=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.Identity -User $User.Guid.Guid.ToString() -ErrorAction SilentlyContinue -Mailbox $userPfMbx.ExchangeGuid.Guid
        $UserPermSyncIssue=ValidateUserPermissions -PermsUserPfMbx $ExplicitPermsUserPfMbx -Perms $ExplicitPerms
        $ExplicitPermsResult=GetUserPermissions($ExplicitPerms)
        if ($UserPermSyncIssue -eq "sync issue exist") {
            #ExplicitUser sync perm issue
            #validate that user has sufficient perms
            if ($ExplicitPermsResult -match "user has no permission") {
                #user has no sufficient perm
                $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) has sufficient permissions to delete, for more information please check the following article https://aka.ms/addPFperm"
                $Issue="$($User.PrimarySmtpAddress) has no sufficient permissions to create items inside $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
            #user has sufficient perm
            $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) permissions are synced properly over his EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox), for more information please check the following article https://aka.ms/Fixpfpermissue"
            $Issue="$($User.PrimarySmtpAddress) has permissions sync problems over EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox)!"
            WriteToScreenAndLog -Issue $Issue -Fix $fix
        } else {
            if ($ExplicitPermsResult -match "user has no permission") {
                #user has no sufficient perm
                #Check if default has perm/sync issue
                $DefaultPermsUserPfMbx=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.Identity -User Default -ErrorAction SilentlyContinue -Mailbox $userPfMbx.ExchangeGuid.Guid
                $UserPermSyncIssue=ValidateUserPermissions -PermsUserPfMbx $ExplicitPermsUserPfMbx -Perms $ExplicitPerms
                $DefaultPerms=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.EntryId -User Default -ErrorAction SilentlyContinue
                $DefaultUserPermSyncIssue=ValidateUserPermissions -PermsUserPfMbx $DefaultPermsUserPfMbx -Perms $DefaultPerms
                if ($null -ne $DefaultPerms) {
                    $DefaultPermsResult=GetUserPermissions($DefaultPerms)
                    if ($DefaultPermsResult -like "user has no permission") {
                        #Default user has no sufficient perm
                        $FIX="FIX --> Please ensure that either Sender or Default user has sufficient permissions to create items on the public folder, for more information please check the following article https://aka.ms/addPFperm"
                        $Issue="Neither Sender nor Default user have sufficient permissions to create items inside $($PublicFolderInfo.PublicFolder.identity)"
                        WriteToScreenAndLog -Issue $Issue -Fix $fix
                    } else {
                        #check for sync issue for default
                        if ($DefaultUserPermSyncIssue -eq "sync issue exist" ) {
                            #DefaultUser sync perm issue
                            #Default user has sufficient perm
                            $FIX="FIX --> Please ensure that Default user permissions are synced properly over user EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox), for more information please check the following article https://aka.ms/Fixpfpermissue"
                            $Issue="Default user has permissions sync problems over user EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox)!"
                            WriteToScreenAndLog -Issue $Issue -Fix $fix
                            $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) has sufficient permissions to create items, for more information please check the following article https://aka.ms/addPFperm"
                            $Issue="$($User.PrimarySmtpAddress) has no sufficient permissions to create items inside $($PublicFolderInfo.PublicFolder.identity)"
                            WriteToScreenAndLog -Issue $Issue -Fix $fix
                        } else {
                            $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) has sufficient permissions to create items, for more information please check the following article https://aka.ms/addPFperm"
                            $Issue="$($User.PrimarySmtpAddress) have no sufficient permissions to create items inside $($PublicFolderInfo.PublicFolder.identity)"
                            WriteToScreenAndLog -Issue $Issue -Fix $fix
                        }
                    }
                }
            } else {
                #user has sufficient permission to create but might be corrupted acl
                $FIX="FIX --> Please try to re-grant user $($User.PrimarySmtpAddress) $($ExplicitPerms.AccessRights) permissions over the requested public folder and validate that recent permission changes are synced properly, for more information please check the following articles https://aka.ms/removePFperm, https://aka.ms/addPFperm and https://aka.ms/Fixpfpermissue"
                $Issue="$($User.PrimarySmtpAddress) might have corrupted permissions over public folder $($PublicFolderInfo.PublicFolder.identity) to create items inside"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
        }
    } catch {
        #log the error and quit
        $ErrorEncountered=$Global:error[0].Exception
        $CurrentDescription = "Validating if user has sufficient permissions to create items"
        $CurrentStatus = "Failure with error: "+$ErrorEncountered
        LogError -Function "Validate user permissions" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $ErrorEncountered -ForegroundColor Red
        AskForFeedback
        QuitEXOSession
    }
}

#Intro
$ts = Get-Date -Format yyyyMMdd_HHmmss
Write-Host $ExportPath
if ($null -eq $ExportPath -or $ExportPath -eq "") {
    $ExportPath = "$env:USERPROFILE\Desktop\ValidateEXOMePf\ValidateEXOMePf_$ts"
    mkdir $ExportPath -Force | Out-Null
} else {
    if (!(Test-Path -Path $ExportPath)) {
        Write-Host "The specified folder location $ExportPath is not existing, please re-run the script and ensure to enter a valid path or leave the ExportPath unassigned" -ForegroundColor Red
        exit
    } else {
        $ExportPath = "$ExportPath\ValidateEXOMePf\ValidateEXOMePf_$ts"
        mkdir $ExportPath -Force | Out-Null
    }
}
[string]$Description = "This script illustrates issues related to creating public folder items on PublicFolder $PFolder, BLOCKERS will be reported down, please ensure to mitigate them!`n"
Write-Host $Description -ForegroundColor Cyan
$Description | Out-File $ExportPath\$Script:ReportName -Append
#Connect to EXO PS
$SessionCheck = Get-PSSession | Where-Object { $_.Name -like "*ExchangeOnline*" -and $_.State -match "opened" }
if ($null -eq $SessionCheck) {
    Connect2EXO
}
#Main Function
$PublicFolderInfo=GetPublicFolderInfo($PFolder)
#if the issue is related to an internal user who is not able to create an item inside a public folder
if (![string]::IsNullOrEmpty($AffectedUser)) {
    ValidateMePfPermSync -PublicFolderInfo $PublicFolderInfo -AffectedUser $AffectedUser
    $IgnoreExternal="Enabled"
}
ValidateMePfMapping($PublicFolderInfo)
ValidateMePfAddress($PublicFolderInfo)
ValidateContentMBXQuota($PublicFolderInfo)
ValidateMePfQuota($PublicFolderInfo)
if ($IgnoreExternal -ne "Enabled") {
    ValidateDbEbDomain($PublicFolderInfo)
    ValidateMePfExtRec($PublicFolderInfo)
}
AskForFeedback
QuitEXOSession
# End of the Diag
