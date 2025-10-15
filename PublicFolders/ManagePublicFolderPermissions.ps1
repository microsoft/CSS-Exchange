# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Export')]
    [switch]
    $Export,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'Export')]
    [object[]]
    $Folder,

    [Parameter(Mandatory = $false, ParameterSetName = 'Export')]
    [string]
    $Mailbox,

    [Parameter(Mandatory = $true, ParameterSetName = 'Import')]
    [switch]
    $Import,

    [Parameter(Mandatory = $false, ParameterSetName = 'Import')]
    [switch]
    $ReplaceExisting,

    [Parameter(Mandatory = $false, ParameterSetName = 'Export')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Import')]
    [string]
    $File
)

begin {
    $foldersToProcess = [System.Collections.ArrayList]::new()

    function GetUserStringFromUser($User) {
        if ($user.UserType -eq 'Default') {
            return 'Default'
        } elseif ($user.UserType -eq 'Anonymous') {
            return 'Anonymous'
        } else {
            return $user.RecipientPrincipal
        }
    }

    function GetMatchingPermission($CurrentPermissions, $ImportedPermission) {
        if ($importedPermission.UserType -eq 'Default' -or $importedPermission.UserType -eq 'Anonymous') {
            return $currentPermissions | Where-Object { $_.User.UserType.Value -eq $importedPermission.UserType }
        } else {
            return $currentPermissions | Where-Object { $_.User.RecipientPrincipal.Guid -eq $importedPermission.RecipientPrincipal }
        }
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'Export' -and $null -ne $Folder) {
        $foldersToProcess.AddRange($Folder) | Out-Null
    }
}

end {
    if ($Export) {
        if (-not $File) {
            $timestamp = Get-Date -Format "yyMMdd-HHmm"
            $File = "PublicFolderPermissions_$timestamp.csv"
        }

        if (Test-Path -Path $File) {
            Write-Error "The specified file '$File' already exists. Please specify a different file name or delete the existing file."
            exit 1
        }

        if (-not $Mailbox) {
            Write-Host "No mailbox specified. Using the root public folder mailbox."
            $Mailbox = Get-Mailbox -PublicFolder (Get-OrganizationConfig -ErrorAction Stop).RootPublicFolderMailbox -ErrorAction Stop
        } else {
            $Mailbox = Get-Mailbox -PublicFolder -Identity $Mailbox -ErrorAction Stop
        }

        if ($foldersToProcess.Count -lt 1) {
            Write-Host "Retrieving all public folders..."
            $foldersToProcess = Get-PublicFolder -Recurse -ResultSize Unlimited | Select-Object -Skip 1
            Write-Host "Retrieved $($foldersToProcess.Count) public folders."
        } else {
            Write-Host "Exporting permissions for $($foldersToProcess.Count) specified public folders."
        }

        Write-Host "Exporting public folder permissions to $File."
        Write-Host "Retrieving permissions..."

        $permissionsList = @()
        $progressCount = 0

        foreach ($folder in $foldersToProcess) {
            $progressCount++
            Write-Progress -Activity "Processing public folders" -Status "Folder $progressCount of $($foldersToProcess.Count)" -PercentComplete (($progressCount / $foldersToProcess.Count) * 100)

            if ($folder.Identity -eq "\" -or $folder.Identity -eq "\non_ipm_subtree") {
                continue
            }

            $permissions = Get-PublicFolderClientPermission -Identity $folder.Identity -Mailbox $mailbox
            foreach ($perm in $permissions) {
                $permissionsList += [PSCustomObject]@{
                    FolderPath         = $folder.Identity
                    ContentMailboxName = $folder.ContentMailboxName
                    ExportedFrom       = $Mailbox.ToString()
                    DisplayName        = $perm.User.DisplayName
                    RecipientPrincipal = $perm.User.RecipientPrincipal.Guid
                    UserType           = $perm.User.UserType
                    AccessRights       = ($perm.AccessRights -join ';')
                }
            }
        }

        Write-Host "Writing CSV file..."

        $permissionsList | Export-Csv -Path $File -NoTypeInformation -Encoding UTF8

        Write-Host "Export completed."
    }

    if ($Import) {
        if (-not (Test-Path -Path $File)) {
            Write-Error "The specified file '$File' does not exist."
            exit 1
        }

        Write-Host "Importing public folder permissions from $File."
        $permissionsList = Import-Csv -Path $File

        $totalPermissions = $permissionsList.Count
        $progressCount = 0
        $currentFolderIdentity = $null
        $currentFolderPermissions = @()

        foreach ($perm in $permissionsList) {
            $progressCount++
            Write-Progress -Activity "Applying public folder permissions" -Status "Permission $progressCount of $totalPermissions" -PercentComplete (($progressCount / $totalPermissions) * 100)

            try {
                if ($currentFolderIdentity -ne $perm.FolderPath) {
                    try {
                        $currentFolderPermissions = Get-PublicFolderClientPermission -Identity $perm.FolderPath
                        $currentFolderIdentity = $perm.FolderPath
                    } catch {
                        Write-Warning "Could not retrieve permissions for folder '$($perm.FolderPath)'. Error:`n$_"
                    }
                }

                if ($null -eq $currentFolderPermissions -or $currentFolderPermissions.Count -lt 1) {
                    Write-Warning "Public folder '$($perm.FolderPath)' permissions could not be retrieved. Skipping."
                    continue
                }

                $existingPermission = GetMatchingPermission -CurrentPermissions $currentFolderPermissions -ImportedPermission $perm

                if ($null -ne $existingPermission) {
                    if (-not $ReplaceExisting) {
                        Write-Host "Permission for user '$($existingPermission.User.DisplayName)' on folder '$($perm.FolderPath)' already exists. Skipping."
                        continue
                    }

                    if ($existingPermission.AccessRights -join ';' -eq $perm.AccessRights) {
                        Write-Host "Permission for user '$($existingPermission.User.DisplayName)' on folder '$($perm.FolderPath)' is already correct. Skipping."
                        continue
                    } else {
                        Write-Host "Permission for user '$($existingPermission.User.DisplayName)' on folder '$($perm.FolderPath)' exists but differs. Removing."
                        Remove-PublicFolderClientPermission -Identity $perm.FolderPath -User (GetUserStringFromUser $perm) -Confirm:$false
                    }
                }

                Write-Host "Adding permission for user '$($perm.DisplayName)' on folder '$($perm.FolderPath)'."
                Add-PublicFolderClientPermission -Identity $perm.FolderPath -User (GetUserStringFromUser $perm) -AccessRights ($perm.AccessRights -split ';') -Confirm:$false
            } catch {
                Write-Warning "Failed to import permissions for user '$($perm.DisplayName)' on folder '$($perm.FolderPath)': $_"
            }
        }

        Write-Host "Import completed."
    }
}
