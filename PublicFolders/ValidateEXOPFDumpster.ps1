# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
param(
    [Parameter(Mandatory = $false)]
    [String]$ExportPath,
    [Parameter(Mandatory = $true)]
    [String]$Pfolder,
    [Parameter(Mandatory = $false)]
    [String]$Affecteduser)
$Script:ReportName = "ValidatePFDumpsterREPORT.txt"
#Requires -Modules @{ModuleName="ExchangeOnlineManagement"; ModuleVersion="2.0.0" }
function logerror {
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
    } | Export-Csv $ExportPath\ValidatePFDumpsterCheckslogging.csv -NoTypeInformation -Append
}
function WritetoScreenANDlog {
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

        Write-Host "Connecting to EXO V2, please enter Global administrator credentials when prompted!" -ForegroundColor Yellow
        Connect-ExchangeOnline -ErrorAction Stop
        $CurrentDescription= "Connecting to EXO V2"
        $CurrentStatus = "Success"
        logerror -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
        Write-Host "Connected to EXO V2 successfully" -ForegroundColor Cyan
    } catch {
        $Errorencountered=$Global:error[0].Exception
        $CurrentDescription = "Connecting to EXO V2"
        $CurrentStatus = "Failure"
        logerror -CurrentStatus $CurrentStatus -Function "Connecting to EXO V2" -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $Errorencountered -ForegroundColor Red
        Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        break
    }
}
function GetPublicFolderInfo {
    param([String]$Pfolder)
    Write-Host "Retrieving Publicfolder information for diagnosing!,please wait as this might take awhile...." -ForegroundColor Yellow
    try {
        $Publicfolder=Get-PublicFolder $Pfolder -ErrorAction stop
        $Publicfolderdumpster=Get-PublicFolder $Publicfolder.DumpsterEntryId -ErrorAction stop
        $Publicfolderstats=Get-PublicFolderStatistics $Publicfolder.EntryId -ErrorAction stop
        $pfmbx=Get-mailbox -PublicFolder $Publicfolder.ContentMailboxGuid.Guid
        $PfMBXstats=Get-mailboxStatistics $Publicfolder.ContentMailboxGuid.Guid -ErrorAction stop
        $IPM_SUBTREE=Get-PublicFolder \ -ErrorAction stop
        $NON_IPM_SUBTREE=Get-PublicFolder \NON_IPM_SUBTREE -ErrorAction stop
        $DUMPSTER_ROOT=Get-PublicFolder \NON_IPM_SUBTREE\DUMPSTER_ROOT -ErrorAction stop
        $OrganizationConfig =Get-OrganizationConfig -ErrorAction stop
        [Int64]$DefaultPublicFolderProhibitPostQuota=[Int64]$OrganizationConfig.DefaultPublicFolderProhibitPostQuota.Split("(")[1].split(" ")[0].Replace(",", "")
        [Int64]$DefaultPublicFolderIssueWarningQuota=[Int64]$OrganizationConfig.DefaultPublicFolderIssueWarningQuota.Split("(")[1].split(" ")[0].Replace(",", "")
        [Int64]$Publicfoldersize=[Int64]$Publicfolderstats.TotalItemSize.Split("(")[1].split("")[0].replace(",", "")+[Int64]$Publicfolderstats.TotaldeletedItemSize.Split("(")[1].split("")[0].replace(",", "")
        [PSCustomObject]$PublicFolderInfo=@{
            Publicfolder                         = $Publicfolder
            Publicfolderdumpster                 = $Publicfolderdumpster
            pfmbx                                = $pfmbx
            Publicfolderstats                    = $Publicfolderstats
            PfMBXstats                           = $PfMBXstats
            IPM_SUBTREE                          = $IPM_SUBTREE
            NON_IPM_SUBTREE                      = $NON_IPM_SUBTREE
            DUMPSTER_ROOT                        = $DUMPSTER_ROOT
            Publicfoldersize                     = $Publicfoldersize
            DefaultPublicFolderProhibitPostQuota = $DefaultPublicFolderProhibitPostQuota
            DefaultPublicFolderIssueWarningQuota = $DefaultPublicFolderIssueWarningQuota
        }
        return $PublicFolderInfo
        $CurrentDescription = "Retrieving: $($Publicfolder.identity) & its dumpster for diagnosing"
        $CurrentStatus = "Success"
        logerror -Function "Retrieve public folder & its dumpster statistics" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    }

    catch {
        $Errorencountered=$Global:error[0].Exception
        $CurrentDescription = "Retrieving: $($Pfolder) & its dumpster for diagnosing"
        $CurrentStatus = "Failure with error: "+$Errorencountered
        logerror -Function "Retrieve public folder & its dumpster statistics" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $Errorencountered -ForegroundColor Red
        Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        break
        #write log and exit function
    }
}
function ValidateContentMBXUniqueness {
    param([PSCustomObject]$PublicFolderInfo)
    if ($PublicFolderInfo.Publicfolder.ContentMailboxGuid.Guid -ne $PublicFolderInfo.Publicfolderdumpster.ContentMailboxGuid.Guid) {
        ExtractLog($PublicFolderInfo)
        $Fix= "FIX --> Please raise a support request for microsoft including the report & logs folder"
        $Issue="Public folder $($Publicfolder.Identity) & its dumpster doesn't have the same content public folder mailbox"
        WritetoScreenANDlog -Issue $Issue -Fix $Fix
    }
}
function ValidateEntryIDMapping {
    param([PSCustomObject]$PublicFolderInfo)
    if ($PublicFolderInfo.Publicfolder.EntryId -ne $PublicFolderInfo.Publicfolderdumpster.DumpsterEntryID -or $PublicFolderInfo.Publicfolder.DumpsterEntryID -ne $PublicFolderInfo.Publicfolderdumpster.EntryId) {
        if (!(Test-Path -Path "$ExportPath\logs_$tstamp\PublicFolderInfo.xml")) {
            ExtractLog($PublicFolderInfo)
        }
        $Issue="Public folder $($Publicfolder.Identity) EntryId & DumpsterEntryID values are not mapped properly"
        $Fix="FIX --> Please raise a support request for microsoft including the report & logs folder"
        WritetoScreenANDlog -Issue $Issue -Fix $Fix
    }
}
function ValidateContentMBXQuota {
    param([PSCustomObject]$PublicFolderInfo)
    [Int64]$pfmbxRecoverableItemsQuotainB=[Int64]$PublicFolderInfo.pfmbx.RecoverableItemsQuota.Split("(")[1].split(" ")[0].Replace(",", "")
    [Int64]$PfMBXstatsinB=[Int64]$PublicFolderInfo.PfMBXstats.TotalDeletedItemSize.Value.tostring().Split("(")[1].split(" ")[0].Replace(",", "")
    if ($PfMBXstatsinB -ge $pfmbxRecoverableItemsQuotainB  ) {
        $article="https://aka.ms/PFrecovery"
        $RecoverDeletedItems="https://aka.ms/cannotdeleteitemsOWA"
        $Fix="FIX --> To resolve a scenario where content public folder mailbox TotalDeletedItemSize value has reached RecoverableItemsQuota value, users could manually clean up the dumpster using:
        ->Outlook $RecoverDeletedItems
        ->MFCMAPI please refer to the following $article to check steps related to get to public folder dumpster using MFCMAPI then select unrequired items to be purged permanently"
        $Issue="Public folder mailbox $($PublicFolderInfo.pfmbx.name) TotalDeletedItemSize value has reached its RecoverableItemsQuota value"
        WritetoScreenANDlog -Issue $Issue -Fix $Fix
    }
}
function ValidateParentPublicFolder {
    param([PSCustomObject]$PublicFolderInfo)
    #Validate where is the removal taking place under IPM_Subtree or Non_IPM_Subtree depends on the pf identity e.g \pf1
    if ($PublicFolderInfo.Publicfolder.FolderPath.Contains("DUMPSTER_ROOT")) {
        #Validate till Non_Ipm_Subtree
        if ($PublicFolderInfo.Publicfolder.ParentFolder -ne  $PublicFolderInfo.NON_IPM_SUBTREE.EntryId) {
            $ParentPublicFolderInfo=GetPublicFolderInfo($PublicFolderInfo.Publicfolder.ParentFolder)
            ValidateContentMBXUniqueness($ParentPublicFolderInfo)
            ValidateEntryIDMapping($ParentPublicFolderInfo)
            ValidateContentMBXQuota($ParentPublicFolderInfo)
            ValidateParentPublicFolder($ParentPublicFolderInfo)
        }
    }
    #Validate on IPM_Subtree
    else {
        if ($PublicFolderInfo.Publicfolder.ParentFolder -ne  $PublicFolderInfo.IPM_SUBTREE.EntryId) {
            $ParentPublicFolderInfo=GetPublicFolderInfo($PublicFolderInfo.Publicfolder.ParentFolder)
            ValidateContentMBXUniqueness($ParentPublicFolderInfo)
            ValidateEntryIDMapping($ParentPublicFolderInfo)
            ValidateContentMBXQuota($ParentPublicFolderInfo)
            ValidateParentPublicFolder($ParentPublicFolderInfo)
        }
    }
}
function ValidateDumpsterFlag {
    param([PSCustomObject]$PublicFolderInfo)
    if ($PublicFolderInfo.Publicfolder.AdminFolderFlags -eq "DumpsterFolder") {
        $Issue="Public folder $($PublicFolderInfo.Publicfolder.Identity) is a dumpster folder, content folder and its dumpster are linked to each other, that link cannot be undone, in other words admins cannot delete dumpster only"
        $Fix="FIX --> Please move $($PublicFolderInfo.Publicfolder.Identity) public folder to be under NON_IPM_SUBTREE using Set-PublicFolder command, for more information please check https://aka.ms/setpf"
        WritetoScreenANDlog -Issue $Issue -Fix $Fix
    }
}
function GetUserPermissions {
    param([PSCustomObject]$Perms)
    $workingpermissions=@("editor", "owner", "publishingeditor", "deleteallitems")
    if ($null -ne $Perms) {
        foreach ($perm in $Perms.AccessRights) {
            if ($workingpermissions.Contains($($perm.ToLower()))) {
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
    param([PSCustomObject]$Perms, [PSCustomObject]$Permsuserpfmbx)
    if ($Perms.AccessRights.count -eq $Permsuserpfmbx.AccessRights.count) {
        foreach ($Perm in $perms.AccessRights) {
            if (!$Permsuserpfmbx.AccessRights.contains($Perm)) {
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
        [string]$Affecteduser)
    #validate explict permission & default permission if item
    try {
        $User=Get-Mailbox $Affecteduser -ErrorAction stop
        $Userpfmbx=Get-mailbox -PublicFolder $($User.EffectivePublicFolderMailbox) -ErrorAction stop
        $Explicitperms=Get-PublicFolderClientPermission $PublicFolderInfo.Publicfolder.EntryId -User $User.Guid.Guid.tostring() -ErrorAction SilentlyContinue
        $Defaultperms=Get-PublicFolderClientPermission $PublicFolderInfo.Publicfolder.EntryId -User Default -ErrorAction SilentlyContinue
        #Validate if there's no perm sync issue
        $Explicitpermsuserpfmbx=Get-PublicFolderClientPermission $PublicFolderInfo.Publicfolder.Identity -User $User.Guid.Guid.tostring() -ErrorAction SilentlyContinue -Mailbox $userpfmbx.ExchangeGuid.Guid
        $Defaultpermsuserpfmbx=Get-PublicFolderClientPermission $PublicFolderInfo.Publicfolder.Identity -User Default -ErrorAction SilentlyContinue -Mailbox $userpfmbx.ExchangeGuid.Guid
        $Userpermsyncissue=ValidateUserPermissions -Permsuserpfmbx $Explicitpermsuserpfmbx -Perms $Explicitperms
        $Defaultuserpermsyncissue=ValidateUserPermissions -Permsuserpfmbx $Defaultpermsuserpfmbx -Perms $Defaultperms
        $Explicitpermsresult=GetUserPermissions($Explicitperms)
        $Defaultpermsresult=GetUserPermissions($Defaultperms)
        if ($Userpermsyncissue -eq "sync issue exist") {
            #explicituser sync perm issue
            #validate that user has sufficient perms
            if ($Explicitpermsresult -match "user has no permission") {
                #user has no sufficient perm
                $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) has sufficient permissions to delete, for more information please check the following article https://aka.ms/addPFperm"
                $Issue="$($User.PrimarySmtpAddress) have no sufficient permissions to delete items inside $($PublicFolderInfo.publicfolder.identity)"
                WritetoScreenANDlog -Issue $Issue -Fix $fix
            }
            #user has sufficient perm
            $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) permissions are synced properly over his EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox), for more information please check the following article https://aka.ms/Fixpfpermissue"
            $Issue="$($User.PrimarySmtpAddress) has permissions sync problems over EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox)!"
            WritetoScreenANDlog -Issue $Issue -Fix $fix
        }
        if ($Defaultuserpermsyncissue -eq "sync issue exist" -and $Explicitpermsresult -match "user has no permission") {
            #Defaultuser sync perm issue
            #validate that Default has sufficient perms
            if ($Defaultpermsresult -match "user has no permission") {
                #Default user has no sufficient perm
                $FIX="FIX --> Please ensure that either $($User.PrimarySmtpAddress) or Default user has sufficient permissions to delete, for more information please check the following article https://aka.ms/addPFperm"
                $Issue="Neither $($User.PrimarySmtpAddress) nor Default user have sufficient permissions to delete items inside $($PublicFolderInfo.publicfolder.identity)"
                WritetoScreenANDlog -Issue $Issue -Fix $fix
            }
            #Default user has sufficient perm
            $FIX="FIX --> Please ensure that Default user permissions are synced properly over user EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox), for more information please check the following article https://aka.ms/Fixpfpermissue"
            $Issue="Default user has permissions sync problems over user EffectivePublicFolderMailbox $($User.EffectivePublicFolderMailbox)!"
            WritetoScreenANDlog -Issue $Issue -Fix $fix
        }
        if ($Userpermsyncissue -eq "no sync issue exist" -or $Defaultuserpermsyncissue -eq "no sync issue exist") {
            #No sync issue found
            #if Default/user has sufficient permission might be perm is corrupted, we might need to re-add default/user permission again
            if ($Explicitpermsresult -match "user has permission") {
                #user has sufficient permission to delete but might be corrupted acl
                $FIX="FIX --> Please re-grant user $($User.PrimarySmtpAddress) permissions over the affected public folder, for more information please check the following articles https://aka.ms/removePFperm, https://aka.ms/addPFperm"
                $Issue="$($User.PrimarySmtpAddress) user has corrupted permission over public folder $($PublicFolderInfo.publicfolder.identity)"
                WritetoScreenANDlog -Issue $Issue -Fix $fix
            }
            if ($Defaultpermsresult -match "user has permission" -and $Explicitpermsresult -match "user has no permission") {
                #user has sufficient permission to delete but might be corrupted acl
                $FIX="FIX --> Please re-grant Default user permissions over the affected public folder or add the permission for the affected user explicitly, for more information please check the following articles https://aka.ms/removePFperm, https://aka.ms/addPFperm"
                $Issue="Default user has corrupted permission over public folder $($PublicFolderInfo.publicfolder.identity)"
                WritetoScreenANDlog -Issue $Issue -Fix $fix
            }
        }
        if ($Userpermsyncissue -eq "no sync issue exist" -and $Defaultuserpermsyncissue -eq "no sync issue exist") {
            if ($Explicitpermsresult -match "user has no permission" -and $Defaultpermsresult -match "user has no permission") {
                #user has no permission to delete
                $FIX="FIX --> Please ensure that user $($User.PrimarySmtpAddress) has sufficient permissions to delete, for more information please check the following article https://aka.ms/addPFperm"
                $Issue="Neither $($User.PrimarySmtpAddress) nor Default user have sufficient permissions to delete items inside $($PublicFolderInfo.publicfolder.identity)"
                WritetoScreenANDlog -Issue $Issue -Fix $fix
            }
        }
    } catch {
        #log the error and quit
        $Errorencountered=$Global:error[0].Exception
        $CurrentDescription = "Validating if user has sufficient permissions to delete"
        $CurrentStatus = "Failure with error: "+$Errorencountered
        logerror -Function "Validate user permissions" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $Errorencountered -ForegroundColor Red
        Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        break
    }
}

function ValidatePublicFolderQuota {
    param([PSCustomObject]$PublicFolderInfo)
    #Validate if DefaultPublicFolderProhibitPostQuota at the organization level applies
    if ($PublicFolderInfo.Publicfolder.ProhibitPostQuota -eq "unlimited") {
        #Checking if public folder total size has reached organization public folder DefaultPublicFolderProhibitPostQuota value!"
        if ($PublicFolderInfo.Publicfoldersize -ge $PublicFolderInfo.DefaultPublicFolderProhibitPostQuota) {
            #validate if Giant PF to lower the PF size down else increase Org DefaultPublicFolderProhibitPostQuota
            if ($PublicFolderInfo.DefaultPublicFolderProhibitPostQuota -ge 21474836480) {
                $Fix= "FIX --> Please follow the following article https://aka.ms/Setorgconfig to modify the Organization DefaultPublicFolderProhibitPostQuota:$($PublicFolderInfo.DefaultPublicFolderProhibitPostQuota) Bytes & DefaultPublicFolderIssueWarningQuota:$($PublicFolderInfo.DefaultPublicFolderIssueWarningQuota) Bytes values to avoid having Giant public folders with sizes exceeding 20GB, then delete or move items from that giant folder $($PublicFolderInfo.Publicfolder.Identity) to reduce the size of that public folder to an appropriate size accomadating with newly modified organization values."
                $Issue="Public folder $($PublicFolderInfo.Publicfolder.Identity) size has exceeded Organization DefaultPublicFolderProhibitPostQuota value!"
                WritetoScreenANDlog -Issue $Issue -Fix $Fix
            } else {
                $Fix= "FIX --> Please follow the following article https://aka.ms/Setorgconfig to modify the Organization DefaultPublicFolderProhibitPostQuota:$($PublicFolderInfo.DefaultPublicFolderProhibitPostQuota) Bytes & DefaultPublicFolderIssueWarningQuota:$($PublicFolderInfo.DefaultPublicFolderIssueWarningQuota) Bytes values to accomodate the public folder $($PublicFolderInfo.Publicfolder.Identity) size:$($PublicFolderInfo.Publicfoldersize) Bytes"
                $Issue="Public folder $($PublicFolderInfo.Publicfolder.Identity) size has exceeded Organization DefaultPublicFolderProhibitPostQuota value!"
                WritetoScreenANDlog -Issue $Issue -Fix $Fix
            }
        }
    } else {
        [Int64]$PFProhibitPostQuota=[Int64]$PublicFolderInfo.Publicfolder.ProhibitPostQuota.split("(")[1].split(" ")[0].replace(",", "")
        if ($PublicFolderInfo.Publicfoldersize -ge $PFProhibitPostQuota) {
            #validate if Giant PF to lower the PF size down else increase PFProhibitPostQuota or inhertit Org DefaultPublicFolderProhibitPostQuota
            if ($PFProhibitPostQuota -ge 21474836480) {
                $Fix= "FIX --> Please follow the following article https://aka.ms/Setorgconfig to modify the Organization DefaultPublicFolderProhibitPostQuota:$($PublicFolderInfo.DefaultPublicFolderProhibitPostQuota) Bytes & DefaultPublicFolderIssueWarningQuota:$($PublicFolderInfo.DefaultPublicFolderIssueWarningQuota) Bytes values to avoid having Giant public folders with sizes exceeding 20GB, then delete or move items from that giant folder $($PublicFolderInfo.Publicfolder.Identity) to reduce the size of that public folder to an appropriate size accomadating with newly modified organization values."
                $Issue="Public folder $($PublicFolderInfo.Publicfolder.Identity) size has exceeded Individual Public Folder ProhibitPostQuota value"
                WritetoScreenANDlog -Issue $Issue -Fix $Fix
            } else {
                $Fix= "FIX --> Please follow the following article https://aka.ms/setpf to modify the Public Folder ProhibitPostQuota:$PFProhibitPostQuota Bytes value to accomodate the public folder $($PublicFolderInfo.Publicfolder.Identity) size:$($PublicFolderInfo.Publicfoldersize) Bytes"
                $Issue="Public folder $($PublicFolderInfo.Publicfolder.Identity) size has exceeded Individual Public Folder ProhibitPostQuota value"
                WritetoScreenANDlog -Issue $Issue -Fix $Fix
            }
        }
    }
}
function ValidateDumpsterChildren {
    param([PSCustomObject]$PublicFolderInfo)
    try {
        $Haschildren= Get-PublicFolder $PublicFolderInfo.Publicfolderdumpster.EntryId -ErrorAction stop -GetChildren
        $CurrentDescription = "Validating if dumpster folder:$($PublicFolderInfo.Publicfolderdumpster.EntryId)"
        $CurrentStatus = "Success"
        logerror -Function "Validate if dumpster folder has children" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
    } catch {
        $Errorencountered=$Global:error[0].Exception
        $CurrentDescription = "Validating if dumpster folder:$($PublicFolderInfo.Publicfolderdumpster.EntryId) has children"
        $CurrentStatus = "Failure with error: "+$Errorencountered
        logerror -Function "Validate if dumpster folder has children" -CurrentStatus $CurrentStatus -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $Errorencountered -ForegroundColor Red
        Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        break
    }
    if ($null -ne $Haschildren) {
        $Fix= "FIX --> Please follow the following article https://aka.ms/setpf to move $($PublicFolderInfo.Publicfolder.Identity) dumpster children found to under NON_IPM_SUBTREE scope e.g. \NON_IPM_SUBTREE\DUMPSTER_ROOT\DUMPSTER_EXTEND\RESERVED_1\RESERVED_1"
        $Issue="Public folder $($PublicFolderInfo.Publicfolder.Identity) dumpster has $($Haschildren.Name.count) subfolder(s) which is a blocker for deletion operations over the public folder!`nDumpster subfolder(s) found:`n----------------------------`n$($Haschildren.identity)"
        WritetoScreenANDlog -Issue $Issue -Fix $Fix
    }
}
function ValidateMEPFGuid {
    param([PSCustomObject]$PublicFolderInfo)
    #validate if MailRecipientGuid parameter is found empty/null
    if ($PublicFolderInfo.Publicfolder.MailEnabled -eq $true) {
        $Hasvalue=$PublicFolderInfo.Publicfolder.MailRecipientGuid.Guid
        if ($null -eq $Hasvalue -or $Hasvalue -eq "00000000-0000-0000-0000-000000000000") {
            $Fix= "FIX --> Please follow the following article https://aka.ms/EnableMPF to mail enable the affected public folder to generate a GUID over MailRecipientGuid parameter, validate MailRecipientGuid parameter has a GUID using https://aka.ms/getpf article then mail disable the affected public folder back again using https://aka.ms/disablempf article to be able to remove the public folder as requested."
            $Issue="Mail-enabled public folder $($PublicFolderInfo.Publicfolder.Identity) is unhealthy e.g MailRecipientGuid parameter is found empty/null which is a blocker for deletion operations over the public folder"
            WritetoScreenANDlogDlog -Issue $Issue -Fix $Fix
        }
    }
}
function ExtractLog {
    param([PSCustomObject]$PublicFolderInfo)
    #create zip file for logs folder
    if (!(Test-Path  "$ExportPath\logs_$ts")) {
        mkdir "$ExportPath\logs_$ts" -Force | Out-Null
    }
    $PublicFolderInfo | Export-Clixml -Path "$ExportPath\logs_$ts\PublicFolderInfo.xml"
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


[string]$Description = "This script illustrates issues related to deleting public folder items or removing the public folder on Publicfolder $Pfolder, BLOCKERS will be reported down, please ensure to mitigate them!`n"
Write-Host $Description -ForegroundColor Cyan
$Description | Out-File $ExportPath\$Script:ReportName -Append

#Connect to EXO PS
$Sessioncheck = Get-PSSession | Where-Object { $_.Name -like "*Exchangeonline*" -and $_.State -match "opened" }
if ($null -eq $Sessioncheck) {
    Connect2EXO
}

#Main Function
$PublicFolderInfo=GetPublicFolderInfo($Pfolder)
#if the issue is related to a user who is not able to delete an item inside a public folder
if ($Affecteduser -notlike "" -or $Affecteduser -notlike $null) {
    ValidatePublicFolderIssue -PublicFolderInfo $PublicFolderInfo -Affecteduser $Affecteduser
}
ValidateContentMBXUniqueness($PublicFolderInfo)
ValidateEntryIDMapping($PublicFolderInfo)
ValidateContentMBXQuota($PublicFolderInfo)
ValidatePublicFolderQuota($PublicFolderInfo)
ValidateDumpsterFlag($PublicFolderInfo)
ValidateDumpsterChildren($PublicFolderInfo)
ValidateMEPFGuid($PublicFolderInfo)
ValidateParentPublicFolder($PublicFolderInfo)


#Ask for feedback
Write-Host "Please rate the script experience & tell us what you liked or what we can do better over https://aka.ms/PFDumpsterFeedback!" -ForegroundColor Cyan
"Please rate the script experience & tell us what you liked or what we can do better over https://aka.ms/PFDumpsterFeedback!" | Out-File $ExportPath\$Script:ReportName -Append

#Quit EXO session

if ($null -eq $Sessioncheck) {
    try {
        Write-Host "Quiting EXO PowerShell session..." -ForegroundColor Yellow
        Disconnect-ExchangeOnline -ErrorAction Stop -Confirm:$false
        $CurrentDescription= "Disconnecting from EXO V2"
        $CurrentStatus = "Success"
        logerror -CurrentStatus $CurrentStatus -Function "Disconnecting from EXO V2" -CurrentDescription $CurrentDescription
    } catch {
        $Errorencountered=$Global:error[0].Exception
        $CurrentDescription = "Disconnecting from EXO V2"
        $CurrentStatus = "Failure"
        logerror -CurrentStatus $CurrentStatus -Function "Disconnecting from EXO V2" -CurrentDescription $CurrentDescription
        Write-Host "Error encountered during executing the script!"-ForegroundColor Red
        Write-Host $Errorencountered -ForegroundColor Red
        Write-Host "`nOutput was exported in the following location: $ExportPath" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        break
    }
}
# End of the Diag
Write-Host "`nlog file was exported in the following location: $ExportPath" -ForegroundColor Yellow
Start-Sleep -Seconds 3
