# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
param(
    [Parameter(Mandatory = $false)]
    [String]$ExportPath,
    [Parameter(Mandatory = $true)]
    [String]$PFolder,
    [Parameter(Mandatory = $false)]
    [String]$AffectedUser)
$Script:ReportName = "ValidatePFDumpsterREPORT.txt"
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
    } | Export-Csv $ExportPath\ValidatePFDumpsterChecksLogging.csv -NoTypeInformation -Append
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
function ValidateDumpsterExistence {
    param([PSCustomObject]$PublicFolder)
    try {
        $PublicFolderDumpster=Get-PublicFolder $PublicFolder.DumpsterEntryId -ErrorAction stop
        $CurrentDescription = "Retrieving: $($PublicFolder.Identity) dumpster for diagnosing"
        $CurrentStatus = "Success"
        LogError -Function "Retrieve public folder $($PublicFolder.Identity) dumpster" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        return $PublicFolderDumpster
    } catch {
        $Issue="Public folder $($PublicFolder.Identity) Dumpster is not existing!"
        $Fix="FIX --> Please raise a support request for microsoft including the report & logs folder"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
        $ErrorEncountered=$Global:error[0].Exception
        $CurrentDescription = "Retrieving: $($PublicFolder.Identity) dumpster for diagnosing"
        $CurrentStatus = "Failure with error: "+$ErrorEncountered
        LogError -Function "Retrieve public folder $($PublicFolder.Identity) dumpster" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        if (!(Test-Path  "$ExportPath\logs_$ts")) {
            mkdir "$ExportPath\logs_$ts" -Force | Out-Null
        }
        $PublicFolder | Export-Clixml -Path "$ExportPath\logs_$ts\PublicFolderInfo$($PublicFolder.Name).xml"
        AskForFeedback
        QuitEXOSession
    }
}
function GetPublicFolderInfo {
    param([String]$PFolder)
    try {
        $PublicFolder=Get-PublicFolder $PFolder -ErrorAction stop
        Write-Host "Retrieving PublicFolder $($PublicFolder.Identity) information for diagnosing!,please wait as this might take awhile...." -ForegroundColor Yellow
        $PublicFolderDumpster=ValidateDumpsterExistence($PublicFolder)
        $PublicFolderStats=Get-PublicFolderStatistics $PublicFolder.EntryId -ErrorAction stop
        $PfMbx=Get-mailbox -PublicFolder $PublicFolder.ContentMailboxGuid.Guid
        $PfMbxStats=Get-mailboxStatistics $PublicFolder.ContentMailboxGuid.Guid -ErrorAction stop
        $IPM_SUBTREE=Get-PublicFolder \ -ErrorAction stop
        $NON_IPM_SUBTREE=Get-PublicFolder \NON_IPM_SUBTREE -ErrorAction stop
        $DUMPSTER_ROOT=Get-PublicFolder \NON_IPM_SUBTREE\DUMPSTER_ROOT -ErrorAction stop
        $OrganizationConfig =Get-OrganizationConfig -ErrorAction stop
        [Int64]$DefaultPublicFolderProhibitPostQuota=[Int64]$OrganizationConfig.DefaultPublicFolderProhibitPostQuota.Split("(")[1].split(" ")[0].Replace(",", "")
        [Int64]$DefaultPublicFolderIssueWarningQuota=[Int64]$OrganizationConfig.DefaultPublicFolderIssueWarningQuota.Split("(")[1].split(" ")[0].Replace(",", "")
        [Int64]$PublicFolderSize=[Int64]$PublicFolderStats.TotalItemSize.Split("(")[1].split(" ")[0].replace(",", "")+[Int64]$PublicFolderStats.TotalDeletedItemSize.Split("(")[1].split(" ")[0].replace(",", "")
        [PSCustomObject]$PublicFolderInfo=@{
            PublicFolder                         = $PublicFolder
            PublicFolderDumpster                 = $PublicFolderDumpster
            PfMbx                                = $PfMbx
            PublicFolderStats                    = $PublicFolderStats
            PfMbxStats                           = $PfMbxStats
            IPM_SUBTREE                          = $IPM_SUBTREE
            NON_IPM_SUBTREE                      = $NON_IPM_SUBTREE
            DUMPSTER_ROOT                        = $DUMPSTER_ROOT
            PublicFolderSize                     = $PublicFolderSize
            DefaultPublicFolderProhibitPostQuota = $DefaultPublicFolderProhibitPostQuota
            DefaultPublicFolderIssueWarningQuota = $DefaultPublicFolderIssueWarningQuota
        }
        return $PublicFolderInfo
        $CurrentDescription = "Retrieving: $($PublicFolder.identity) & its dumpster for diagnosing"
        $CurrentStatus = "Success"
        LogError -Function "Retrieve public folder & its dumpster statistics" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    }

    catch {
        $ErrorEncountered=$Global:error[0].Exception
        $CurrentDescription = "Retrieving: $($PublicFolder.Identity) & its dumpster for diagnosing"
        $CurrentStatus = "Failure with error: "+$ErrorEncountered
        LogError -Function "Retrieve public folder & its dumpster statistics" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $ErrorEncountered -ForegroundColor Red
        QuitEXOSession
        #write log and exit function
    }
}
function ValidateContentMBXUniqueness {
    param([PSCustomObject]$PublicFolderInfo)
    if ($PublicFolderInfo.PublicFolder.ContentMailboxGuid.Guid -ne $PublicFolderInfo.PublicFolderDumpster.ContentMailboxGuid.Guid) {
        ExtractLog($PublicFolderInfo)
        $Fix= "FIX --> Please raise a support request for microsoft including the report & logs folder"
        $Issue="Public folder $($PublicFolder.Identity) & its dumpster doesn't have the same content public folder mailbox"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
    }
}
function ValidateEntryIDMapping {
    param([PSCustomObject]$PublicFolderInfo)
    if ($PublicFolderInfo.PublicFolder.EntryId -ne $PublicFolderInfo.PublicFolderDumpster.DumpsterEntryID -or $PublicFolderInfo.PublicFolder.DumpsterEntryID -ne $PublicFolderInfo.PublicFolderDumpster.EntryId) {
        if (!(Test-Path -Path "$ExportPath\logs_$ts\$($PublicFolderInfo.PublicFolder.Name).xml")) {
            ExtractLog($PublicFolderInfo)
        }
        $Issue="Public folder $($PublicFolder.Identity) EntryId & DumpsterEntryID values are not mapped properly"
        $Fix="FIX --> Please raise a support request for microsoft including the report & logs folder"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
    }
}
function ValidateContentMBXQuota {
    param([PSCustomObject]$PublicFolderInfo)
    [Int64]$PfMbxRecoverableItemsQuotaInB=[Int64]$PublicFolderInfo.PfMbx.RecoverableItemsQuota.Split("(")[1].split(" ")[0].Replace(",", "")
    [Int64]$PfMbxStatsInB=[Int64]$PublicFolderInfo.PfMbxStats.TotalDeletedItemSize.Value.ToString().Split("(")[1].split(" ")[0].Replace(",", "")
    if ($PfMbxStatsInB -ge $PfMbxRecoverableItemsQuotaInB  ) {
        $article="https://aka.ms/PFrecovery"
        $RecoverDeletedItems="https://aka.ms/cannotdeleteitemsOWA"
        $Fix="FIX --> To resolve a scenario where content public folder mailbox TotalDeletedItemSize value has reached RecoverableItemsQuota value, users could manually clean up the dumpster using:
        ->Outlook $RecoverDeletedItems
        ->MFCMAPI please refer to the following $article to check steps related to get to public folder dumpster using MFCMAPI then select unrequired items to be purged permanently"
        $Issue="Public folder mailbox $($PublicFolderInfo.PfMbx.name) TotalDeletedItemSize value has reached its RecoverableItemsQuota value"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
    }
}
function ValidateParentPublicFolder {
    param([PSCustomObject]$PublicFolderInfo)
    #Validate where is the removal taking place under IPM_Subtree or Non_IPM_Subtree depends on the pf identity e.g \pf1
    if ($PublicFolderInfo.PublicFolder.FolderPath.Contains("DUMPSTER_ROOT")) {
        #Validate till Non_Ipm_Subtree
        if ($PublicFolderInfo.PublicFolder.ParentFolder -ne  $PublicFolderInfo.NON_IPM_SUBTREE.EntryId) {
            $ParentPublicFolderInfo=GetPublicFolderInfo($PublicFolderInfo.PublicFolder.ParentFolder)
            ValidateContentMBXUniqueness($ParentPublicFolderInfo)
            ValidateEntryIDMapping($ParentPublicFolderInfo)
            ValidateContentMBXQuota($ParentPublicFolderInfo)
            ValidateParentPublicFolder($ParentPublicFolderInfo)
        }
    }
    #Validate on IPM_Subtree
    else {
        if (![string]::IsNullOrEmpty($PublicFolderInfo.PublicFolder.ParentFolder)) {
            $ParentPublicFolderInfo=GetPublicFolderInfo($PublicFolderInfo.PublicFolder.ParentFolder)
            ValidateContentMBXUniqueness($ParentPublicFolderInfo)
            ValidateEntryIDMapping($ParentPublicFolderInfo)
            ValidateContentMBXQuota($ParentPublicFolderInfo)
            ValidateParentPublicFolder($ParentPublicFolderInfo)
        }
    }
}
function ValidateDumpsterFlag {
    param([PSCustomObject]$PublicFolderInfo)
    if ($PublicFolderInfo.PublicFolder.AdminFolderFlags -eq "DumpsterFolder") {
        $Issue="Public folder $($PublicFolderInfo.PublicFolder.Identity) is a dumpster folder, content folder and its dumpster are linked to each other, that link cannot be undone, in other words admins cannot delete dumpster only"
        $Fix="FIX --> Please move $($PublicFolderInfo.PublicFolder.Identity) public folder to be under NON_IPM_SUBTREE using Set-PublicFolder command, for more information please check https://aka.ms/setpf"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
        AskForFeedback
        QuitEXOSession
    }
}
function GetUserPermissions {
    param([PSCustomObject]$Perms)
    $WorkingPermissions=@("Editor", "Owner", "PublishingEditor", "DeleteAllItems").ToLower()
    if ($null -ne $Perms) {
        foreach ($perm in $Perms.AccessRights) {
            if ($WorkingPermissions.Contains($($perm.ToLower()))) {
                return "user has permission"
            }
        }
        return "user has no permission"
    }

    else {
        return "user has no permission"
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
function ValidatePublicFolderIssue {
    param([Parameter(Mandatory = $true)]
        [PSCustomObject]$PublicFolderInfo,
        [Parameter(Mandatory = $false)]
        [string]$AffectedUser)
    #validate explicit permission & default permission if item
    try {
        $User=Get-Mailbox $AffectedUser -ErrorAction stop
        $UserPfMbx=Get-mailbox -PublicFolder $($User.EffectivePublicFolderMailbox) -ErrorAction stop
        $ExplicitPerms=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.EntryId -User $User.Guid.Guid.ToString() -ErrorAction SilentlyContinue
        $DefaultPerms=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.EntryId -User Default -ErrorAction SilentlyContinue
        #Validate if there's no perm sync issue
        $ExplicitPermsUserPfMbx=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.Identity -User $User.Guid.Guid.ToString() -ErrorAction SilentlyContinue -Mailbox $userPfMbx.ExchangeGuid.Guid
        $DefaultPermsUserPfMbx=Get-PublicFolderClientPermission $PublicFolderInfo.PublicFolder.Identity -User Default -ErrorAction SilentlyContinue -Mailbox $userPfMbx.ExchangeGuid.Guid
        $UserPermSyncIssue=ValidateUserPermissions -PermsUserPfMbx $ExplicitPermsUserPfMbx -Perms $ExplicitPerms
        $DefaultUserPermSyncIssue=ValidateUserPermissions -PermsUserPfMbx $DefaultPermsUserPfMbx -Perms $DefaultPerms
        $ExplicitPermsResult=GetUserPermissions($ExplicitPerms)
        $DefaultPermsResult=GetUserPermissions($DefaultPerms)
        if ($UserPermSyncIssue -eq "sync issue exist") {
            #ExplicitUser sync perm issue
            #validate that user has sufficient perms
            if ($ExplicitPermsResult -match "user has no permission") {
                #user has no sufficient perm
                $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) has sufficient permissions to delete, for more information please check the following article https://aka.ms/addPFperm"
                $Issue="$($User.PrimarySmtpAddress) have no sufficient permissions to delete items inside $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
            #user has sufficient perm
            $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) permissions are synced properly over his EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox), for more information please check the following article https://aka.ms/Fixpfpermissue"
            $Issue="$($User.PrimarySmtpAddress) has permissions sync problems over EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox)!"
            WriteToScreenAndLog -Issue $Issue -Fix $fix
        }
        if ($DefaultUserPermSyncIssue -eq "sync issue exist" ) {
            #DefaultUser sync perm issue
            #validate that Default has sufficient perms
            if ($DefaultPermsResult -match "user has no permission" -and $ExplicitPermsResult -match "user has no permission") {
                #Default user has no sufficient perm
                $FIX="FIX --> Please ensure that either $($User.PrimarySmtpAddress) or Default user has sufficient permissions to delete, for more information please check the following article https://aka.ms/addPFperm"
                $Issue="Neither $($User.PrimarySmtpAddress) nor Default user have sufficient permissions to delete items inside $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
            #Default user has sufficient perm
            if ($DefaultPermsResult -match "user has permission" -and $ExplicitPermsResult -match "user has no permission") {
                $FIX="FIX --> Please ensure that Default user permissions are synced properly over user EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox), for more information please check the following article https://aka.ms/Fixpfpermissue"
                $Issue="Default user has permissions sync problems over user EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox)!"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
                $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) has sufficient permissions to delete, for more information please check the following article https://aka.ms/addPFperm"
                $Issue="$($User.PrimarySmtpAddress) have no sufficient permissions to delete items inside $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
            if ($DefaultPermsResult -match "user has permission" -and $ExplicitPermsResult -match "user has permission") {
                $FIX="FIX --> Please re-grant user $($User.PrimarySmtpAddress) permissions over the affected public folder, for more information please check the following articles https://aka.ms/removePFperm, https://aka.ms/addPFperm"
                $Issue="$($User.PrimarySmtpAddress) user has corrupted permission over public folder $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
            if ($DefaultPermsResult -match "user has no permission" -and $ExplicitPermsResult -match "user has permission") {
                $FIX="FIX --> Please re-grant user $($User.PrimarySmtpAddress) permissions over the affected public folder, for more information please check the following articles https://aka.ms/removePFperm, https://aka.ms/addPFperm"
                $Issue="$($User.PrimarySmtpAddress) user has corrupted permission over public folder $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
        }
        if ($UserPermSyncIssue -eq "no sync issue exist" -and $DefaultUserPermSyncIssue -eq "no sync issue exist") {
            if ($ExplicitPermsResult -match "user has no permission" -and $DefaultPermsResult -match "user has no permission") {
                #user has no permission to delete
                $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) has sufficient permissions to delete, for more information please check the following article https://aka.ms/addPFperm"
                $Issue="Neither $($User.PrimarySmtpAddress) nor Default user have sufficient permissions to delete items inside $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
            #if Default/user has sufficient permission might be perm is corrupted, we might need to re-add default/user permission again
            if ($ExplicitPermsResult -match "user has permission") {
                #user has sufficient permission to delete but might be corrupted acl
                $FIX="FIX --> Please re-grant user $($User.PrimarySmtpAddress) permissions over the affected public folder, for more information please check the following articles https://aka.ms/removePFperm, https://aka.ms/addPFperm"
                $Issue="$($User.PrimarySmtpAddress) user has corrupted permission over public folder $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
            if ($DefaultPermsResult -match "user has permission" -and $ExplicitPermsResult -match "user has no permission") {
                #user has sufficient permission to delete but might be corrupted acl
                $FIX="FIX --> Please re-grant Default user permissions over the affected public folder or add the permission for the affected user explicitly, for more information please check the following articles https://aka.ms/removePFperm, https://aka.ms/addPFperm"
                $Issue="Default user has corrupted permission over public folder $($PublicFolderInfo.PublicFolder.identity)"
                WriteToScreenAndLog -Issue $Issue -Fix $fix
            }
        }
    } catch {
        #log the error and quit
        $ErrorEncountered=$Global:error[0].Exception
        $CurrentDescription = "Validating if user has sufficient permissions to delete"
        $CurrentStatus = "Failure with error: "+$ErrorEncountered
        LogError -Function "Validate user permissions" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $ErrorEncountered -ForegroundColor Red
        Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        break
    }
}

function ValidatePublicFolderQuota {
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
function ValidateDumpsterChildren {
    param([PSCustomObject]$PublicFolderInfo)
    try {
        $HasChildren= Get-PublicFolder $PublicFolderInfo.PublicFolderDumpster.EntryId -ErrorAction stop -GetChildren
        $CurrentDescription = "Validating if dumpster folder:$($PublicFolderInfo.PublicFolderDumpster.EntryId) has children"
        $CurrentStatus = "Success"
        LogError -Function "Validate if dumpster folder has children" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    } catch {
        $ErrorEncountered=$Global:error[0].Exception
        $CurrentDescription = "Validating if dumpster folder:$($PublicFolderInfo.PublicFolderDumpster.EntryId) has children"
        $CurrentStatus = "Failure with error: "+$ErrorEncountered
        LogError -Function "Validate if dumpster folder has children" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $ErrorEncountered -ForegroundColor Red
        Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        break
    }
    if ($null -ne $HasChildren) {
        $Fix= "FIX --> Please follow the following article https://aka.ms/setpf to move $($PublicFolderInfo.PublicFolder.Identity) dumpster children found to under NON_IPM_SUBTREE scope e.g. \NON_IPM_SUBTREE\DUMPSTER_ROOT\DUMPSTER_EXTEND\RESERVED_1\RESERVED_1"
        $Issue="Public folder $($PublicFolderInfo.PublicFolder.Identity) dumpster has $($HasChildren.Name.count) subfolder(s) which is a blocker for deletion operations over the public folder!`nDumpster subfolder(s) found:`n----------------------------`n$($HasChildren.identity)"
        WriteToScreenAndLog -Issue $Issue -Fix $Fix
    }
}
#MePf=Mail Enabled Public Folder
function ValidateMePfGuid {
    param([PSCustomObject]$PublicFolderInfo)
    #validate if MailRecipientGuid parameter is found empty/null
    if ($PublicFolderInfo.PublicFolder.MailEnabled -eq $true) {
        $HasValue=$PublicFolderInfo.PublicFolder.MailRecipientGuid.Guid
        if ($null -eq $HasValue -or $HasValue -eq "00000000-0000-0000-0000-000000000000") {
            $Fix= "FIX --> Please follow the following article https://aka.ms/EnableMPF to mail enable the affected public folder to generate a GUID over MailRecipientGuid parameter, validate MailRecipientGuid parameter has a GUID using https://aka.ms/getpf article then mail disable the affected public folder back again using https://aka.ms/disablempf article to be able to remove the public folder as requested."
            $Issue="Mail-enabled public folder $($PublicFolderInfo.PublicFolder.Identity) is unhealthy e.g MailRecipientGuid parameter is found empty/null which is a blocker for deletion operations over the public folder"
            WriteToScreenAndLog -Issue $Issue -Fix $Fix
        }
    }
}
function ExtractLog {
    param([PSCustomObject]$PublicFolderInfo)
    #create zip file for logs folder
    if (!(Test-Path  "$ExportPath\logs_$ts")) {
        mkdir "$ExportPath\logs_$ts" -Force | Out-Null
    }
    $PublicFolderInfo | Export-Clixml -Path "$ExportPath\logs_$ts\PublicFolderInfo$($PublicFolderInfo.PublicFolder.Name).xml"
}
function AskForFeedback {
    $Feedback="Please rate the script experience & tell us what you liked or what we can do better over https://aka.ms/PFDumpsterFeedback!"
    Write-Host $Feedback -ForegroundColor Cyan
    $Feedback | Out-File $ExportPath\$Script:ReportName -Append
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
            exit
        } catch {
            $ErrorEncountered=$Global:error[0].Exception
            $CurrentDescription = "Disconnecting from EXO"
            $CurrentStatus = "Failure"
            LogError -CurrentStatus $CurrentStatus -Function "Disconnecting from EXO" -CurrentDescription $CurrentDescription
            Write-Host "Error encountered during executing the script!"-ForegroundColor Red
            Write-Host $ErrorEncountered -ForegroundColor Red
            Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            exit
        }
    }
}
#Intro
$ts = Get-Date -Format yyyyMMdd_HHmmss
Write-Host $ExportPath
if ($null -eq $ExportPath -or $ExportPath -eq "") {
    $ExportPath = "$env:USERPROFILE\Desktop\ValidatePFDumpster\ValidatePFDumpster_$ts"
    mkdir $ExportPath -Force | Out-Null
} else {
    if (!(Test-Path -Path $ExportPath)) {
        Write-Host "The specified folder location $ExportPath is not existing, please re-run the script and ensure to enter a valid path or leave the ExportPath unassigned" -ForegroundColor Red
        exit
    } else {
        $ExportPath = "$ExportPath\ValidatePFDumpster\ValidatePFDumpster_$ts"
        mkdir $ExportPath -Force | Out-Null
    }
}
[string]$Description = "This script illustrates issues related to deleting public folder items or removing the public folder on PublicFolder $PFolder, BLOCKERS will be reported down, please ensure to mitigate them!`n"
Write-Host $Description -ForegroundColor Cyan
$Description | Out-File $ExportPath\$Script:ReportName -Append
#Connect to EXO PS
$SessionCheck = Get-PSSession | Where-Object { $_.Name -like "*ExchangeOnline*" -and $_.State -match "opened" }
if ($null -eq $SessionCheck) {
    Connect2EXO
}
#Main Function
$PublicFolderInfo=GetPublicFolderInfo($PFolder)
#if the issue is related to a user who is not able to delete an item inside a public folder
if (![string]::IsNullOrEmpty($AffectedUser)) {
    ValidatePublicFolderIssue -PublicFolderInfo $PublicFolderInfo -AffectedUser $AffectedUser
}
ValidateDumpsterFlag($PublicFolderInfo)
ValidateContentMBXUniqueness($PublicFolderInfo)
ValidateEntryIDMapping($PublicFolderInfo)
ValidateContentMBXQuota($PublicFolderInfo)
ValidatePublicFolderQuota($PublicFolderInfo)
ValidateDumpsterChildren($PublicFolderInfo)
ValidateMePfGuid($PublicFolderInfo)
ValidateParentPublicFolder($PublicFolderInfo)
AskForFeedback
QuitEXOSession
# End of the Diag

