#############################################################################################################
#.SYNOPSIS
#   Updates client permissions of several users to a public folder
#
#.DESCRIPTION
#   Updates the client permissions of a public folder (and its children if -recurse
#	is provided) clearing the permissions a set of users have on the folder and setting
#	the provided access rights
#
#	Copyright (c) 2014 Microsoft Corporation. All rights reserved.
#
#	THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
#	OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
#
#.PARAMETER  IncludeFolders
#   Identities of the Public Folders that will be updated
#
#.PARAMETER  Users
#   List of users whose current access rights to the folder will be overriten
#
#.PARAMETER  AccessRights
#   List of permissions to assign to the users
#
#.PARAMETER  Recurse
#   If provided the permission changes will also be applied to the children of the folders.
#
#.PARAMETER  ExcludeFolderEntryIds
#   List of EntryIds of the folders that should be ignored from the update. Notice however
#   that if you use the Recurse option the children of these folders won't be ignored unless
#   their EntryIds are also provided in this list.
#
#.PARAMETER  SkipCurrentAccessCheck
#   If provided the right access updates will be performed in the folder regardless of whether
#   the current folder has the same permissions already applied.
#
#.PARAMETER  Confirm
#   If this switch parameter is set to $false all operations on the public folder will be
#   performed without requesting confirmation from the user.
#
#.PARAMETER  WhatIf
#   If this switch parameter is present the operations on the public folder will not be
#   performed but information on what task would be performed are printed to the console.
#
#.PARAMETER  ProgressLogFile
#   File to log EntryIds of folders that were successfully updated. The content of this file may
#   become handy to save time if the previous execution of the script was aborted and you want to restart
#   from the point the script stopped. To do this simply get the contents of the file (get-content) and
#   provide the data to the ExcludeFolderEntryIds parameter.
#
#   The default path is UpdatePublicFolderPermission.[yyyyMMdd_HHmm].log where the portion in square brackets
#   gets replaced with the current date and time at the moment of execution of the script.
#
#.EXAMPLE
#    .\Update-PublicFolderPermissions.ps1 -IncludeFolders "\MyFolder" -AccessRights "Owner" -Users "John", "Administrator" -Recurse -Confirm:$false
#
#	This command replaces the current client permissions for users "John" and "Administrator" on the "\MyFolder"
#   Public Folder and all its children. The users will be granted "Owner" access rights. These actions will be
#	performed without requesting confirmation to the user.
#
#.EXAMPLE
#    $foldersProcessed = get-content .\UpdatePublicFolderPermission.20141031_1820.log
#    .\Update-PublicFolderPermissions.ps1 -IncludeFolders "\MyFolder" -AccessRights "Owner" -Users "John", "Administrator" -Recurse -ExcludeFolderEntryIds $foldersProcessed -Confirm:$false
#
#	These commands replace the current client permissions for users "John" and "Administrator" on the "\MyFolder"
#   Public Folder and all its children but skips those folders that were completd in the execution of Oct 30th 2014 at 6:20 pm.
#   The users will be granted "Owner" access rights. These actions will be performed without requesting confirmation to the user.
#############################################################################################################

param (
    [Parameter(Mandatory=$True)]
    [string[]]$IncludeFolders,
    [Parameter(Mandatory=$True)]
    [string[]]$Users,
    [Parameter(Mandatory=$True)]
    [string[]]$AccessRights,
    [switch]$Recurse,
    [string[]]$ExcludeFolderEntryIds = @(),
    [switch]$SkipCurrentAccessCheck,
    [string]$ProgressLogFile = ".\UpdatePublicFolderPermission.$((Get-Date).ToString('yyyyMMdd_HHmm')).log",
    [switch]$confirm,
    [switch]$whatIf
)

#############################################################################################################
#   Returns the list of public folders to process ignoring duplicates and folders in the exclude list
#############################################################################################################
function FindFoldersToUpdate([string[]]$includeFolders, [bool]$recurseOnFolders, [string[]]$excludeFolderEntryIds)
{
    $folderToSkip = new-object 'System.Collections.Generic.HashSet[string]' -ArgumentList @(,$excludeFolderEntryIds)
    $currentIncludeFolder=0;
    foreach($includeFolder in $includeFolders)
    {
        $progress = 100 * $currentIncludeFolder / $includeFolders.Count;
        Write-Progress -Activity "Retrieving folders to update" -Status $includeFolder -PercentComplete $progress

        $foldersFound = Get-PublicFolder -Recurse:$recurseOnFolders $includeFolder -ResultSize Unlimited

        if ($foldersFound -eq $null)
        {
            continue;
        }

        foreach($foundFolder in $foldersFound)
        {
            if ($foundFolder -eq $null)
            {
                continue;
            }

            if ($folderToSkip -notContains $foundFolder.EntryId)
            {
                #Return found folder
                $foundFolder;
            }

            $folderToSkip.Add($foundFolder.EntryId) > $null;
        }

        $currentIncludeFolder++;
    }
}

#############################################################################################################
#   Returns the Identity of the users that need processing.
#############################################################################################################
function GetUserIdentities([string[]]$Users)
{
    $userIdentities = new-object 'System.Collections.Generic.HashSet[object]'
    $currentUserNumber=0;
    foreach($user in $Users)
    {
        $progress = 100 * $currentUserNumber / $Users.Count;
        Write-Progress -Activity "Retrieving users" -Status $user -PercentComplete $progress
        $id = (Get-Recipient $user).Identity

        if ($id -ne $null)
        {
            $userIdentities.Add($id) > $null
        }

        $currentUserNumber++;
    }

    $userIdentities
}

#############################################################################################################
#   Returns whether all the elements of a collection are present in a reference collection.
#############################################################################################################
function CollectionContains($referenceCollection, $otherCollection)
{
    foreach($item in $otherCollection)
    {
        if ($referenceCollection -notcontains $item)
        {
            return $false
        }
    }

    return $true
}

#############################################################################################################
#   Verifies whether there is a mismatch between the desired and found permissions.
#############################################################################################################
function IsUpdateRequired ($currentAccessRights, $desiredAccessRights)
{
    $allDesiredPermissionsWhereFound = CollectionContains $currentAccessRights $desiredAccessRights
    $allFoundPermissionsAreDesired = CollectionContains $desiredAccessRights $currentAccessRights

    return -not ($allDesiredPermissionsWhereFound -and $allFoundPermissionsAreDesired)
}

#############################################################################################################
#   Gets the list of users whose access right to a folder don't match the desired ones.
#############################################################################################################
function GetUsersToUpdate($currentFolder, [Array]$usersToUpdate, [string[]]$accessRights)
{
    Write-Progress -Id 1 -Activity "Querying current permissions" -Status "Processing";

    $existingPermissions = [Array](Get-PublicFolderClientPermission $currentFolder.Identity);
    $existingPermissionsPerUser = @{}

    $permissionCount = 0;
    foreach($permission in $existingPermissions)
    {
        $progress = 100 * $permissionCount / $existingPermissions.Count;
        Write-Progress -Id 1 -Activity "Processing current permissions" -PercentComplete $progress -Status "Processing";

        $adIdentity = $permission.User.ADRecipient.Identity;

        if ($adIdentity -ne $null)
        {
            $existingPermissionsPerUser[$adIdentity] = $permission;
        }
    }

    $permissionCount = 0;
    foreach($user in $usersToUpdate)
    {
        $progress = 100 * $permissionCount / $usersToUpdate.Count;
        Write-Progress -Id 1 -Activity "Comparing permissions" -PercentComplete $progress -Status "Processing";

        if (-not $existingPermissionsPerUser.ContainsKey($user))
        {
            $user;
        }
        else
        {
            if (IsUpdateRequired $existingPermissionsPerUser[$user].AccessRights $AccessRights)
            {
                $user;
            }
        }

        $permissionCount++;
    }
}

#############################################################################################################
#   Script logic.
#############################################################################################################

$foldersToUpdate=[Array](FindFoldersToUpdate $IncludeFolders $Recurse $ExcludeFolderEntryIds);
$usersToUpdate=[Array](GetUserIdentities $Users)

$foldersProcessed=0;
foreach($currentFolder in $foldersToUpdate)
{
    $percentFoldersProcessed = 100 * $foldersProcessed/($foldersToUpdate.Count);
    Write-Progress -Activity "Processing folders" -Status $currentFolder.Identity -PercentComplete $percentFoldersProcessed

    $usersToUpdateForFolder = @()
    if (-not $SkipCurrentAccessCheck)
    {
        $usersToUpdateForFolder =  [Array](GetUsersToUpdate $currentFolder $usersToUpdate $AccessRights)
    }
    else
    {
        $usersToUpdateForFolder = $usersToUpdate;
    }

    $folderOperationFailed=$false;
    $usersProcessed=0;

    if (($usersToUpdateForFolder -eq $null) -or ($usersToUpdateForFolder.Count -eq 0))
    {
        Write-Warning "Couldn't find any changes to perform for folder $($currentFolder.Identity)"
        continue;
    }

    foreach($user in $usersToUpdateForFolder)
    {
        $percentUsersProcessed = 100 * $usersProcessed/($usersToUpdateForFolder.Count)

        Write-Progress -Id 1 -Activity "Processing User" -Status $user -CurrentOperation "Removing exisitng permission" -PercentComplete $percentUsersProcessed
        Remove-PublicFolderClientPermission -User $user $currentFolder.Identity -ErrorAction SilentlyContinue -Confirm:$confirm -WhatIf:$whatIf

        Write-Progress -Id 1 -Activity "Processing User" -Status $user -CurrentOperation "Adding permission" -PercentComplete $percentUsersProcessed

        try
        {
            Add-PublicFolderClientPermission -AccessRights $accessRights -User $user $currentFolder.Identity -ErrorAction Stop -Confirm:$confirm -WhatIf:$whatIf
        }
        catch
        {
            Write-Error $_
            $folderOperationFailed=$true;
        }

        $usersProcessed++;
    }

    if (-not $folderOperationFailed)
    {
        Add-Content $ProgressLogFile "$($currentFolder.EntryId)`n" -Confirm:$confirm -WhatIf:$whatIf
    }

    $foldersProcessed++;
}
