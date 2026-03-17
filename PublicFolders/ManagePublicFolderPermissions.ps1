# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Exports or imports public folder client permissions to/from a CSV file.

.DESCRIPTION
`ManagePublicFolderPermissions.ps1` exports client permissions from public folders to a CSV file, or imports and applies permissions from a CSV file. Use `-Export` to write permissions and `-Import` to apply them. The script supports piping folder objects to the `-Export` parameter, uses the root public folder mailbox by default, and can optionally replace existing permissions during import.

.PARAMETER Export
Switch. Export permissions to a CSV file. When used with pipeline input, accepts folder objects to export only those folders.

.PARAMETER Folder
Array of public folder objects or identities to export when used with `-Export`. Accepts pipeline input.

.PARAMETER Mailbox
Public folder mailbox identity to retrieve permissions from when exporting. Defaults to the organization root public folder mailbox if not specified.

.PARAMETER Import
Switch. Import permissions from the CSV file specified by `-File` and apply them to public folders.

.PARAMETER ReplaceExisting
Switch. When importing, remove and re-add permissions that already exist but differ from the CSV.

.PARAMETER OnlyModifyEmptyACLs
Switch. When importing, skip folders that already have any permission entries other than Default and Anonymous.

.PARAMETER File
Path to the CSV file to read (for import) or write (for export). If not specified during export, a timestamped file name is generated.

.EXAMPLE
.
    .\ManagePublicFolderPermissions.ps1 -Export -Mailbox "PublicFolders" -File PFPerms.csv

.DESCRIPTION
Exports permissions for all public folders in the specified mailbox to `PFPerms.csv`.

.EXAMPLE
    Get-PublicFolder -Identity "\\MyFolder" | .\ManagePublicFolderPermissions.ps1 -Export -File PFPerms.csv

.DESCRIPTION
Exports permissions for the provided folder to `PFPerms.csv`.

.EXAMPLE
    .\ManagePublicFolderPermissions.ps1 -Import -File PFPerms.csv -ReplaceExisting

.DESCRIPTION
Imports permissions from `PFPerms.csv` and replaces differing existing permissions.

.NOTES
Requires PowerShell 5.1 and the ExchangeOnlineManagement module.
Documentation: docs/PublicFolders/ManagePublicFolderPermissions.md
#>

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
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

    [Parameter(Mandatory = $false, ParameterSetName = 'Import')]
    [switch]
    $OnlyModifyEmptyACLs,

    [Parameter(Mandatory = $false, ParameterSetName = 'Export')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Import')]
    [string]
    $File,

    [Parameter(Mandatory = $false, ParameterSetName = 'Export')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Import')]
    [ValidateRange(1, [int]::MaxValue)]
    [int]
    $BatchSize = 100
)

begin {
    $foldersToProcess = [System.Collections.ArrayList]::new()

    $ProgressPreference = 'Continue'

    function GetUserStringFromPermissionImportLine($Line) {
        if ($Line.UserType -eq 'Default') {
            return 'Default'
        } elseif ($Line.UserType -eq 'Anonymous') {
            return 'Anonymous'
        } else {
            if (-not [string]::IsNullOrWhiteSpace($Line.Guid)) {
                return $Line.Guid
            } elseif (-not [string]::IsNullOrWhiteSpace($Line.PrimarySmtpAddress)) {
                return $Line.PrimarySmtpAddress
            } elseif (-not [string]::IsNullOrEmpty($Line.DisplayName)) {
                return $Line.DisplayName
            } else {
                throw "Unable to determine user string for permission entry with UserType '$($Line.UserType)' and no identifiable properties."
            }
        }
    }

    function GetNormalizedAccessRights([string[]]$AccessRights) {
        if ($null -eq $AccessRights) {
            return @()
        }

        return @($AccessRights | ForEach-Object { $_.ToString().Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    }

    function GetMatchingPermission($CurrentPermissions, $ImportedPermission) {
        if ($importedPermission.UserType -eq 'Default' -or $importedPermission.UserType -eq 'Anonymous') {
            return $currentPermissions | Where-Object { $_.User.UserType.Value -eq $importedPermission.UserType }
        } else {
            if (-not [string]::IsNullOrEmpty($importedPermission.Guid)) {
                return $currentPermissions | Where-Object { $null -ne $_.User.RecipientPrincipal -and $null -ne $_.User.RecipientPrincipal.Guid -and $_.User.RecipientPrincipal.Guid.ToString() -eq $importedPermission.Guid }
            } elseif (-not [string]::IsNullOrEmpty($importedPermission.PrimarySmtpAddress)) {
                return $currentPermissions | Where-Object { $null -ne $_.User.RecipientPrincipal -and $null -ne $_.User.RecipientPrincipal.PrimarySmtpAddress -and $_.User.RecipientPrincipal.PrimarySmtpAddress -eq $importedPermission.PrimarySmtpAddress }
            } else {
                return $currentPermissions | Where-Object { $_.User.DisplayName -eq $importedPermission.DisplayName }
            }
        }
    }

    function GetImportProgressKey($PermissionRow) {
        $folderIdentityForKey = if ($PermissionRow.PSObject.Properties.Name -contains 'EntryId' -and -not [string]::IsNullOrWhiteSpace($PermissionRow.EntryId)) {
            $PermissionRow.EntryId
        } else {
            $PermissionRow.FolderPath
        }

        $userKey = if ($PermissionRow.UserType -eq 'Default' -or $PermissionRow.UserType -eq 'Anonymous') {
            $PermissionRow.UserType
        } elseif (-not [string]::IsNullOrEmpty($PermissionRow.Guid)) {
            $PermissionRow.Guid
        } elseif (-not [string]::IsNullOrEmpty($PermissionRow.PrimarySmtpAddress)) {
            $PermissionRow.PrimarySmtpAddress
        } else {
            $PermissionRow.DisplayName
        }

        [string[]]$importedAccessRightsFromCsv = @($PermissionRow.AccessRights -split '[,; ]+' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $normalizedAccessRights = (GetNormalizedAccessRights -AccessRights $importedAccessRightsFromCsv) -join ';'
        return "{0}|{1}|{2}" -f $folderIdentityForKey, $userKey, $normalizedAccessRights
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

        $alreadyExported = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if (Test-Path -Path $File) {
            Write-Host "Output file '$File' exists. Attempting to resume export and append to it."
            $existing = Import-Csv -Path $File -ErrorAction Stop
            foreach ($e in $existing) {
                if ($null -ne $e.FolderPath) { $alreadyExported.Add($e.FolderPath) | Out-Null }
            }
            Write-Host "Found $($alreadyExported.Count) folders already exported. These will be skipped."
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

        $exportBatch = New-Object System.Collections.ArrayList
        $progressCount = 0

        foreach ($folder in $foldersToProcess) {
            $progressCount++

            if ($folder.Identity -eq "\" -or $folder.Identity -eq "\non_ipm_subtree") {
                continue
            }

            if ($alreadyExported.Contains($folder.Identity.ToString())) {
                continue
            }

            Write-Progress -Activity "Processing public folders" -Status "Folder $progressCount of $($foldersToProcess.Count)" -PercentComplete (($progressCount / $foldersToProcess.Count) * 100)

            $permissions = Get-PublicFolderClientPermission -Identity "$($folder.Identity)" -Mailbox $mailbox
            foreach ($perm in $permissions) {
                $exportBatch.Add([PSCustomObject]@{
                        EntryId            = $folder.EntryId
                        FolderPath         = $folder.Identity
                        ContentMailboxName = $folder.ContentMailboxName
                        ExportedFrom       = $Mailbox.ToString()
                        DisplayName        = $perm.User.DisplayName
                        PrimarySmtpAddress = $perm.User.RecipientPrincipal.PrimarySmtpAddress
                        Guid               = $perm.User.RecipientPrincipal.Guid
                        UserType           = $perm.User.UserType
                        AccessRights       = ($perm.AccessRights -join ';')
                    }) | Out-Null
            }

            if ($exportBatch.Count -ge $BatchSize) {
                Write-Host "Writing batch of $($exportBatch.Count) permissions to CSV file..."
                $exportBatch | Export-Csv -Path $File -NoTypeInformation -Encoding UTF8 -Append
                $exportBatch.Clear()
            }
        }

        if ($exportBatch.Count -gt 0) {
            Write-Host "Writing final batch of $($exportBatch.Count) permissions to CSV file..."
            $exportBatch | Export-Csv -Path $File -NoTypeInformation -Encoding UTF8 -Append
            $exportBatch.Clear()
        }

        Write-Host "Export completed."
    }

    if ($Import) {
        if (-not (Test-Path -Path $File)) {
            Write-Error "The specified file '$File' does not exist."
            exit 1
        }

        Write-Host "Importing public folder permissions from $File."
        $permissionsList = Import-Csv -Path $File

        $progressFile = "$File.import.progress.csv"
        $processedRows = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $progressBatch = New-Object System.Collections.ArrayList
        if (Test-Path -Path $progressFile) {
            try {
                $existingProgress = Import-Csv -Path $progressFile -ErrorAction Stop
                foreach ($row in $existingProgress) {
                    if ($null -ne $row.ProgressKey -and -not [string]::IsNullOrWhiteSpace($row.ProgressKey)) {
                        $processedRows.Add($row.ProgressKey) | Out-Null
                    }
                }
                Write-Host "Found $($processedRows.Count) previously imported permission entries. These will be skipped."
            } catch {
                Write-Warning "Unable to read import progress file '$progressFile'. Import will continue without resume state. Error:`n$_"
            }
        }

        $totalPermissions = $permissionsList.Count
        $progressCount = 0
        $currentFolderIdentity = $null
        $currentFolderPermissions = @()
        $skipCurrentFolder = $false

        foreach ($perm in $permissionsList) {
            if ($progressBatch.Count -ge $BatchSize) {
                $progressBatch | Export-Csv -Path $progressFile -Append -NoTypeInformation -Encoding UTF8
                $progressBatch.Clear()
            }

            # Hack to work around import files with this value
            $perm.AccessRights = $perm.AccessRights -replace "AvailabilityOnly", "FolderVisible"

            $progressCount++
            Write-Progress -Activity "Applying public folder permissions" -Status "Permission $progressCount of $totalPermissions" -PercentComplete (($progressCount / $totalPermissions) * 100)

            try {
                $progressKey = GetImportProgressKey -PermissionRow $perm
                if ($processedRows.Contains($progressKey)) {
                    continue
                }

                $folderIdentityForCmdlets = if ($perm.PSObject.Properties.Name -contains 'EntryId' -and -not [string]::IsNullOrWhiteSpace($perm.EntryId)) {
                    $perm.EntryId
                } else {
                    $perm.FolderPath
                }

                if ($currentFolderIdentity -ne $folderIdentityForCmdlets) {
                    $skipCurrentFolder = $false
                    $currentFolderPermissions = @()
                    try {
                        $currentFolderPermissions = Get-PublicFolderClientPermission -Identity $folderIdentityForCmdlets
                        $currentFolderIdentity = $folderIdentityForCmdlets

                        if ($OnlyModifyEmptyACLs) {
                            $existingNonDefaultAnonymous = @($currentFolderPermissions | Where-Object {
                                    $_.User.UserType.Value -ne 'Default' -and $_.User.UserType.Value -ne 'Anonymous'
                                })

                            if ($existingNonDefaultAnonymous.Count -gt 0) {
                                Write-Host "Skipping folder '$($perm.FolderPath)' because -OnlyModifyEmptyACLs was specified and it already has non-Default/Anonymous permissions."
                                $skipCurrentFolder = $true
                            }
                        }
                    } catch {
                        $currentFolderPermissions = @()
                        Write-Warning "Could not retrieve permissions for folder '$($perm.FolderPath)'. Error:`n$_"
                    }
                }

                if ($skipCurrentFolder) {
                    $processedRows.Add($progressKey) | Out-Null
                    $progressBatch.Add([PSCustomObject]@{ ProgressKey = $progressKey }) | Out-Null
                    continue
                }

                if ($null -eq $currentFolderPermissions -or $currentFolderPermissions.Count -lt 1) {
                    Write-Warning "Public folder '$($perm.FolderPath)' permissions could not be retrieved. Skipping."
                    continue
                }

                $existingPermission = GetMatchingPermission -CurrentPermissions $currentFolderPermissions -ImportedPermission $perm
                [string[]]$importedAccessRightsFromCsv = @($perm.AccessRights -split '[,; ]+' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                $importedAccessRights = GetNormalizedAccessRights -AccessRights $importedAccessRightsFromCsv

                if ($null -ne $existingPermission) {
                    if (-not $ReplaceExisting) {
                        Write-Host "Permission for user '$($existingPermission.User.DisplayName)' on folder '$($perm.FolderPath)' already exists. Skipping."
                        $processedRows.Add($progressKey) | Out-Null
                        $progressBatch.Add([PSCustomObject]@{ ProgressKey = $progressKey }) | Out-Null
                        continue
                    }

                    [string[]]$existingAccessRightsFromService = @($existingPermission.AccessRights)
                    $existingAccessRights = GetNormalizedAccessRights -AccessRights $existingAccessRightsFromService
                    $rightsDiff = Compare-Object -ReferenceObject $existingAccessRights -DifferenceObject $importedAccessRights

                    if ($existingAccessRights.Count -eq $importedAccessRights.Count -and -not $rightsDiff) {
                        Write-Host "Permission for user '$($existingPermission.User.DisplayName)' on folder '$($perm.FolderPath)' is already correct. Skipping."
                        $processedRows.Add($progressKey) | Out-Null
                        $progressBatch.Add([PSCustomObject]@{ ProgressKey = $progressKey }) | Out-Null
                        continue
                    } else {
                        Write-Host "Permission for user '$($existingPermission.User.DisplayName)' on folder '$($perm.FolderPath)' exists but differs. Removing."
                        $targetUser = GetUserStringFromPermissionImportLine $perm
                        if ($PSCmdlet.ShouldProcess("$($perm.FolderPath) [$targetUser]", 'Remove public folder client permission')) {
                            Remove-PublicFolderClientPermission -Identity $folderIdentityForCmdlets -User $targetUser -Confirm:$false
                        }
                    }
                }

                Write-Host "Adding permission for user '$($perm.DisplayName)' on folder '$($perm.FolderPath)'."
                $targetUser = GetUserStringFromPermissionImportLine $perm
                if ($PSCmdlet.ShouldProcess("$($perm.FolderPath) [$targetUser]", "Add public folder client permission ($($importedAccessRights -join ', '))")) {
                    Add-PublicFolderClientPermission -Identity $folderIdentityForCmdlets -User $targetUser -AccessRights $importedAccessRights -Confirm:$false
                }

                $processedRows.Add($progressKey) | Out-Null
                $progressBatch.Add([PSCustomObject]@{ ProgressKey = $progressKey }) | Out-Null

                if ($progressBatch.Count -ge $BatchSize) {
                    $progressBatch | Export-Csv -Path $progressFile -Append -NoTypeInformation -Encoding UTF8
                    $progressBatch.Clear()
                }
            } catch {
                Write-Warning "Failed to import permissions for user '$($perm.DisplayName)' on folder '$($perm.FolderPath)': $_"
            }
        }

        if ($progressBatch.Count -gt 0) {
            $progressBatch | Export-Csv -Path $progressFile -Append -NoTypeInformation -Encoding UTF8
            $progressBatch.Clear()
        }

        Write-Host "Import completed."
    }
}
