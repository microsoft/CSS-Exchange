# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

#############################################################################################################
#.SYNOPSIS
#   Updates client permissions of several users to a public folder
#
#.DESCRIPTION
#   Updates the client permissions of a public folder (and its children if -recurse
#	is provided) clearing the permissions a set of users have on the folder and setting
#	the provided access rights
#
#.PARAMETER  IncludeFolders
#   Identities of the Public Folders that will be updated
#
#.PARAMETER  Users
#   List of users whose current access rights to the folder will be overwritten
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
#   Public Folder and all its children but skips those folders that were completed in the execution of Oct 30th 2014 at 6:20 pm.
#   The users will be granted "Owner" access rights. These actions will be performed without requesting confirmation to the user.
#############################################################################################################

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory=$True, ParameterSetName='Default')]
    [Parameter(Mandatory=$True, ParameterSetName='PropagateAll')]
    [string[]]$IncludeFolders,
    [Parameter(Mandatory=$True, ParameterSetName='Default')]
    [string[]]$Users,
    [Parameter(Mandatory=$True, ParameterSetName='Default')]
    [string[]]$AccessRights,
    [Parameter(Mandatory=$True, ParameterSetName='PropagateAll')]
    [switch]$PropagateAll,
    [Parameter(Mandatory=$False, ParameterSetName='Default')]
    [Parameter(Mandatory=$False, ParameterSetName='PropagateAll')]
    [switch]$Recurse,
    [Parameter(Mandatory=$False, ParameterSetName='Default')]
    [Parameter(Mandatory=$False, ParameterSetName='PropagateAll')]
    [string[]]$ExcludeFolderEntryIds = @(),
    [Parameter(Mandatory=$False, ParameterSetName='Default')]
    [Parameter(Mandatory=$False, ParameterSetName='PropagateAll')]
    [switch]$SkipCurrentAccessCheck,
    [Parameter(Mandatory=$False, ParameterSetName='Default')]
    [Parameter(Mandatory=$False, ParameterSetName='PropagateAll')]
    [string]$ProgressLogFile = ".\UpdatePublicFolderPermission.$((Get-Date).ToString('yyyyMMdd_HHmm')).log"
)

#############################################################################################################
#   Returns the list of public folders to process ignoring duplicates and folders in the exclude list
#############################################################################################################
function FindFoldersToUpdate([string[]]$includeFolders, [bool]$recurseOnFolders, [string[]]$excludeFolderEntryIds) {
    Write-Verbose "$($MyInvocation.MyCommand): excludeFolderEntryIds.Count $($excludeFolderEntryIds.Count)"
    if ($excludeFolderEntryIds.Count -gt 0) {
        $excludeFolderEntryIds | ForEach-Object { Write-Verbose "$($MyInvocation.MyCommand): excluded EntryID $_" }
    }

    $folderToSkip = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList @(, $excludeFolderEntryIds)
    $currentIncludeFolder=0
    foreach ($includeFolder in $includeFolders) {
        $progress = 100 * $currentIncludeFolder / $includeFolders.Count
        Write-Progress -Activity "Retrieving folders to update" -Status $includeFolder -PercentComplete $progress

        $foldersFound = @(Get-PublicFolder -Recurse:$recurseOnFolders $includeFolder -ResultSize Unlimited | Sort-Object Identity)

        if ($null -eq $foldersFound) {
            continue
        }

        foreach ($foundFolder in $foldersFound) {
            if ($null -eq $foundFolder) {
                continue
            }

            if ($folderToSkip -notcontains $foundFolder.EntryId) {
                Write-Verbose "$($MyInvocation.MyCommand): Returning found folder $($foundFolder.Identity) with EntryId $($foundFolder.EntryID)"
                #Return found folder
                $foundFolder
            } else {
                Write-Verbose "$($MyInvocation.MyCommand): Skipping excluded folder $($foundFolder.Identity) with EntryId $($foundFolder.EntryID)"
            }

            $folderToSkip.Add($foundFolder.EntryId) > $null
        }

        $currentIncludeFolder++
    }
}

#############################################################################################################
#   Returns the Identity of the users that need processing.
#############################################################################################################
function GetUserIdentities([string[]]$Users) {
    $userIdentities = New-Object 'System.Collections.Generic.HashSet[object]'
    $currentUserNumber=0
    foreach ($user in $Users) {
        $progress = 100 * $currentUserNumber / $Users.Count
        Write-Progress -Activity "Retrieving users" -Status $user -PercentComplete $progress
        $id = (Get-Recipient $user).PrimarySmtpAddress

        if ($null -ne $id) {
            $userIdentities.Add($id) > $null
        }

        $currentUserNumber++
    }

    $userIdentities
}

#############################################################################################################
#   Returns whether all the elements of a collection are present in a reference collection.
#############################################################################################################
function CollectionContains($referenceCollection, $otherCollection) {
    foreach ($item in $otherCollection) {
        if ($referenceCollection -notcontains $item) {
            return $false
        }
    }

    return $true
}

#############################################################################################################
#   Verifies whether there is a mismatch between the desired and found permissions.
#############################################################################################################
function IsUpdateRequired ($currentAccessRights, $desiredAccessRights) {
    $allDesiredPermissionsWhereFound = CollectionContains $currentAccessRights $desiredAccessRights
    $allFoundPermissionsAreDesired = CollectionContains $desiredAccessRights $currentAccessRights

    return -not ($allDesiredPermissionsWhereFound -and $allFoundPermissionsAreDesired)
}

#############################################################################################################
#   Gets the value we should use as the user's identity, which may be Default or Anonymous
#############################################################################################################
function GetPermissionUserIdentity($permissionUser) {
    if ($permissionUser.UserType.ToString() -eq 'Default' -or $permissionUser.UserType.ToString() -eq 'Anonymous') {
        $permissionUser.UserType.ToString()
    } else {
        $permissionUser.RecipientPrincipal.PrimarySmtpAddress
    }
}

#############################################################################################################
#   Gets the list of users whose access right to a folder don't match the desired ones.
#############################################################################################################
function GetUsersToUpdate($currentFolder, [Array]$permissionsToPropagate) {
    Write-Progress -Id 1 -Activity "Querying current permissions" -Status "Processing"

    $existingPermissions = [Array](Get-PublicFolderClientPermission $currentFolder.Identity)
    Write-Verbose "$($MyInvocation.MyCommand): Found $($existingPermissions.Count) existing permissions"
    Write-Verbose ($existingPermissions | Format-Table Identity, User, AccessRights | Out-String)
    $existingPermissionsPerUser = @{}

    $permissionCount = 0
    foreach ($permission in $existingPermissions) {
        $progress = 100 * $permissionCount / $existingPermissions.Count
        Write-Progress -Id 1 -Activity "Processing current permissions" -PercentComplete $progress -Status "Processing"

        $principalIdentity = GetPermissionUserIdentity $permission.User

        if ($null -ne $principalIdentity) {
            $existingPermissionsPerUser[$principalIdentity] = $permission
        }
    }

    $permissionCount = 0
    foreach ($permission in $permissionsToPropagate) {
        $progress = 100 * $permissionCount / $permissionsToPropagate.Count
        Write-Progress -Id 1 -Activity "Comparing permissions" -PercentComplete $progress -Status "Processing"

        if (-not $existingPermissionsPerUser.ContainsKey($permission.User)) {
            Write-Verbose "$($MyInvocation.MyCommand): No existing permission for $($permission.User)"
            $permission
        } else {
            if (IsUpdateRequired $existingPermissionsPerUser[$permission.User].AccessRights $permission.AccessRights) {
                Write-Verbose "$($MyInvocation.MyCommand): Existing permission for $($permission.User) doesn't match desired permissions"
                $permission
            } else {
                Write-Verbose "$($MyInvocation.MyCommand): Existing permission for $($permission.User) matches desired permissions"
            }
        }

        $permissionCount++
    }
}

#############################################################################################################
#   Script logic.
#############################################################################################################

if ($PropagateAll -and $IncludeFolders.Count -gt 1) {
    Write-Host "When -PropagateAll is used, -IncludeFolders is limited to one folder."
    return
}

# We want to pass these to the cmdlets that we call
$script:CommonParams = @{}
foreach ($p in "Confirm", "WhatIf", "Verbose") {
    if ($null -ne $PSBoundParameters[$p]) {
        $script:CommonParams[$p] = $PSBoundParameters[$p].IsPresent
    }
}

$permissionsToPropagate = @()
if ($PropagateAll) {
    $topLevelPermissions = Get-PublicFolderClientPermission $IncludeFolders[0]
    if ($null -eq $topLevelPermissions) {
        Write-Host "Unable to retrieve permissions from folder $($IncludeFolders[0])"
        return
    }

    foreach ($permission in $topLevelPermissions) {
        $principal = GetPermissionUserIdentity $permission.User
        if ($null -eq $principal) {
            Write-Warning "Permission exists for $($permission.User), but this user appears to be invalid. Permissions cannot be propagated."
            exit
        }

        $permissionsToPropagate += [PSCustomObject]@{
            User         = $principal
            AccessRights = $permission.AccessRights
        }
    }
} else {
    $usersToUpdate=[Array](GetUserIdentities $Users)
    foreach ($principal in $usersToUpdate) {
        $permissionsToPropagate += [PSCustomObject]@{
            User         = $principal
            AccessRights = $AccessRights
        }
    }
}

Write-Host "The following permissions will be set:"
$permissionsToPropagate | Out-Host

Write-Host "The following folders will be included. Recurse: $Recurse"
$IncludeFolders | Out-Host
Write-Host

$foldersToUpdate=[Array](FindFoldersToUpdate -includeFolders $IncludeFolders -recurseOnFolders $Recurse -excludeFolderEntryIds $ExcludeFolderEntryIds)

if ($PropagateAll) {
    $foldersToUpdate = @($foldersToUpdate | Select-Object -Skip 1)
}

Write-Host "Found $($foldersToUpdate.Count) folders to update."

$foldersProcessed=0
foreach ($currentFolder in $foldersToUpdate) {
    $percentFoldersProcessed = 100 * $foldersProcessed/($foldersToUpdate.Count)
    Write-Progress -Activity "Processing folders" -Status $currentFolder.Identity -PercentComplete $percentFoldersProcessed

    $permissionsToUpdateForFolder = @()
    if (-not $SkipCurrentAccessCheck) {
        $permissionsToUpdateForFolder =  [Array](GetUsersToUpdate $currentFolder $permissionsToPropagate)
    } else {
        $permissionsToUpdateForFolder = $permissionsToPropagate
    }

    Write-Verbose "$($MyInvocation.MyCommand): $($permissionsToUpdateForFolder.Count) permissions to apply for folder $($currentFolder.Identity)"

    $folderOperationFailed=$false
    $usersProcessed=0

    if (($null -eq $permissionsToUpdateForFolder) -or ($permissionsToUpdateForFolder.Count -eq 0)) {
        Write-Warning "Couldn't find any changes to perform for folder $($currentFolder.Identity)"
        $foldersProcessed++
        continue
    }

    foreach ($permission in $permissionsToUpdateForFolder) {
        $percentUsersProcessed = 100 * $usersProcessed/($permissionsToUpdateForFolder.Count)

        Write-Progress -Id 1 -Activity "Processing User" -Status $permission.User -CurrentOperation "Removing existing permission" -PercentComplete $percentUsersProcessed
        Remove-PublicFolderClientPermission -User $permission.User $currentFolder.Identity -ErrorAction SilentlyContinue @script:CommonParams

        Write-Progress -Id 1 -Activity "Processing User" -Status $permission.User -CurrentOperation "Adding permission" -PercentComplete $percentUsersProcessed

        try {
            Add-PublicFolderClientPermission -AccessRights $permission.AccessRights -User $permission.User $currentFolder.Identity -ErrorAction Stop @script:CommonParams
        } catch {
            Write-Error $_
            $folderOperationFailed=$true
        }

        $usersProcessed++
    }

    if (-not $folderOperationFailed) {
        Add-Content $ProgressLogFile "$($currentFolder.EntryId)`n"
    }

    $foldersProcessed++
}
