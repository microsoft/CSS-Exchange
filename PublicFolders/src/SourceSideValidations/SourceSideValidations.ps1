# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [bool]
    $StartFresh = $true,

    [Parameter(Mandatory = $true, ParameterSetName = "RemoveInvalidPermissions")]
    [Switch]
    $RemoveInvalidPermissions,

    [Parameter(ParameterSetName = "RemoveInvalidPermissions")]
    [string]
    $CsvFile = (Join-Path $PSScriptRoot "InvalidPermissions.csv"),

    [Parameter()]
    [switch]
    $SkipVersionCheck
)

. $PSScriptRoot\Get-FolderData.ps1
. $PSScriptRoot\Get-LimitsExceeded.ps1
. $PSScriptRoot\Get-BadDumpsterMappings.ps1
. $PSScriptRoot\Get-BadPermission.ps1
. $PSScriptRoot\Get-BadPermissionJob.ps1
. $PSScriptRoot\JobQueue.ps1
. $PSScriptRoot\Remove-InvalidPermission.ps1
. $PSScriptRoot\Get-BadMailEnabledFolder.ps1
. $PSScriptRoot\..\..\..\Shared\Test-ScriptVersion.ps1

if (-not $SkipVersionCheck) {
    if (Test-ScriptVersion -AutoUpdate) {
        # Update was downloaded, so stop here.
        Write-Host "Script was updated. Please rerun the command."
        return
    }
}

if ($RemoveInvalidPermissions) {
    if (-not (Test-Path $CsvFile)) {
        Write-Error "File not found: $CsvFile"
    } else {
        Remove-InvalidPermission -CsvFile $CsvFile
    }
    return
}

$startTime = Get-Date

$startingErrorCount = $Error.Count

Set-ADServerSettings -ViewEntireForest $true

if ($Error.Count -gt $startingErrorCount) {
    # If we already have errors, we're not running from the right shell.
    return
}

$progressParams = @{
    Activity = "Validating public folders"
    Id       = 1
}

Write-Progress @progressParams -Status "Step 1 of 5"

$folderData = Get-FolderData -StartFresh $StartFresh

if ($folderData.IpmSubtree.Count -lt 1) {
    return
}

$script:anyDatabaseDown = $false
Get-Mailbox -PublicFolder | ForEach-Object {
    try {
        $db = Get-MailboxDatabase $_.Database -Status
        if ($db.Mounted) {
            $folderData.MailboxToServerMap[$_.DisplayName] = $db.Server
        } else {
            Write-Error "Database $db is not mounted. This database holds PF mailbox $_ and must be mounted."
            $script:anyDatabaseDown = $true
        }
    } catch {
        Write-Error $_
        $script:anyDatabaseDown = $true
    }
}

if ($script:anyDatabaseDown) {
    Write-Host "One or more PF mailboxes cannot be reached. Unable to proceed."
    return
}

# Now we're ready to do the checks

Write-Progress @progressParams -Status "Step 2 of 5"

$badDumpsters = @(Get-BadDumpsterMappings -FolderData $folderData)

Write-Progress @progressParams -Status "Step 3 of 5"

$limitsExceeded = Get-LimitsExceeded -FolderData $folderData

Write-Progress @progressParams -Status "Step 4 of 5"

$badMailEnabled = Get-BadMailEnabledFolder -FolderData $folderData

Write-Progress @progressParams -Status "Step 5 of 5"

$badPermissions = @(Get-BadPermission -FolderData $folderData)

# Output the results

if ($badMailEnabled.FoldersToMailDisable.Count -gt 0) {
    $foldersToMailDisableFile = Join-Path $PSScriptRoot "FoldersToMailDisable.txt"
    Set-Content -Path $foldersToMailDisableFile -Value $badMailEnabled.FoldersToMailDisable

    Write-Host
    Write-Host $badMailEnabled.FoldersToMailDisable.Count "folders should be mail-disabled, either because the MailRecipientGuid"
    Write-Host "does not exist, or because they are system folders. These are listed in the file called:"
    Write-Host $foldersToMailDisableFile -ForegroundColor Green
    Write-Host "After confirming the accuracy of the results, you can mail-disable them with the following command:"
    Write-Host "Get-Content `"$foldersToMailDisableFile`" | % { Set-PublicFolder `$_ -MailEnabled `$false }" -ForegroundColor Green
}

if ($badMailEnabled.MailPublicFoldersToDelete.Count -gt 0) {
    $mailPublicFoldersToDeleteFile = Join-Path $PSScriptRoot "MailPublicFolderOrphans.txt"
    Set-Content -Path $mailPublicFoldersToDeleteFile -Value $badMailEnabled.MailPublicFoldersToDelete

    Write-Host
    Write-Host $badMailEnabled.MailPublicFoldersToDelete.Count "MailPublicFolders are orphans and should be deleted. They exist in Active Directory"
    Write-Host "but are not linked to any public folder. These are listed in a file called:"
    Write-Host $mailPublicFoldersToDeleteFile -ForegroundColor Green
    Write-Host "After confirming the accuracy of the results, you can delete them with the following command:"
    Write-Host "Get-Content `"$mailPublicFoldersToDeleteFile`" | % { `$folder = ([ADSI](`"LDAP://`$_`")); `$parent = ([ADSI]`"`$(`$folder.Parent)`"); `$parent.Children.Remove(`$folder) }" -ForegroundColor Green
}

if ($badMailEnabled.MailPublicFolderDuplicates.Count -gt 0) {
    $mailPublicFolderDuplicatesFile = Join-Path $PSScriptRoot "MailPublicFolderDuplicates.txt"
    Set-Content -Path $mailPublicFolderDuplicatesFile -Value $badMailEnabled.MailPublicFolderDuplicates

    Write-Host
    Write-Host $badMailEnabled.MailPublicFolderDuplicates.Count "MailPublicFolders are duplicates and should be deleted. They exist in Active Directory"
    Write-Host "and point to a valid folder, but that folder points to some other directory object."
    Write-Host "These are listed in a file called:"
    Write-Host $mailPublicFolderDuplicatesFile -ForegroundColor Green
    Write-Host "After confirming the accuracy of the results, you can delete them with the following command:"
    Write-Host "Get-Content `"$mailPublicFolderDuplicatesFile`" | % { `$folder = ([ADSI](`"LDAP://`$_`")); `$parent = ([ADSI]`"`$(`$folder.Parent)`"); `$parent.Children.Remove(`$folder) }" -ForegroundColor Green

    if ($badMailEnabled.EmailAddressMergeCommands.Count -gt 0) {
        $emailAddressMergeScriptFile = Join-Path $PSScriptRoot "AddAddressesFromDuplicates.ps1"
        Set-Content -Path $emailAddressMergeScriptFile -Value $badMailEnabled.EmailAddressMergeCommands
        Write-Host "The duplicates we are deleting contain email addresses that might still be in use."
        Write-Host "To preserve these, we generated a script that will add these to the linked objects for those folders."
        Write-Host "After deleting the duplicate objects using the command above, run the script as follows to"
        Write-Host "populate these addresses:"
        Write-Host ".\$emailAddressMergeScriptFile" -ForegroundColor Green
    }
}

if ($badMailEnabled.MailDisabledWithProxyGuid.Count -gt 0) {
    $mailDisabledWithProxyGuidFile = Join-Path $PSScriptRoot "MailDisabledWithProxyGuid.txt"
    Set-Content -Path $mailDisabledWithProxyGuidFile -Value $badMailEnabled.MailDisabledWithProxyGuid

    Write-Host
    Write-Host $badMailEnabled.MailDisabledWithProxyGuid.Count "public folders have proxy GUIDs even though the folders are mail-disabled."
    Write-Host "These folders should be mail-enabled. They can be mail-disabled again afterwards if desired."
    Write-Host "To mail-enable these folders, run:"
    Write-Host "Get-Content `"$mailDisabledWithProxyGuidFile`" | % { Enable-MailPublicFolder `$_ }" -ForegroundColor Green
}

if ($badMailEnabled.MailPublicFoldersDisconnected.Count -gt 0) {
    $mailPublicFoldersDisconnectedFile = Join-Path $PSScriptRoot "MailPublicFoldersDisconnected.txt"
    Set-Content -Path $mailPublicFoldersDisconnectedFile -Value $badMailEnabled.MailPublicFoldersDisconnected

    Write-Host
    Write-Host $badMailEnabled.MailPublicFoldersDisconnected.Count "MailPublicFolders are disconnected from their folders. This means they exist in"
    Write-Host "Active Directory and the folders are probably functioning as mail-enabled folders,"
    Write-Host "even while the properties of the public folders themselves say they are not mail-enabled."
    Write-Host "This can be complex to fix. Either the directory object should be deleted, or the public folder"
    Write-Host "should be mail-enabled, or both. These directory objects are listed in a file called:"
    Write-Host $mailPublicFoldersDisconnectedFile -ForegroundColor Green
}

if ($badDumpsters.Count -gt 0) {
    $badDumpsterFile = Join-Path $PSScriptRoot "BadDumpsterMappings.txt"
    Set-Content -Path $badDumpsterFile -Value $badDumpsters

    Write-Host
    Write-Host $badDumpsters.Count "folders have invalid dumpster mappings. These folders are listed in"
    Write-Host "the following file:"
    Write-Host $badDumpsterFile -ForegroundColor Green
    Write-Host "The -ExcludeDumpsters switch can be used to skip these folders during migration, or the"
    Write-Host "folders can be deleted."
}

if ($limitsExceeded.ChildCount.Count -gt 0) {
    $tooManyChildFoldersFile = Join-Path $PSScriptRoot "TooManyChildFolders.txt"
    Set-Content -Path $tooManyChildFoldersFile -Value $limitsExceeded.ChildCount

    Write-Host
    Write-Host $limitsExceeded.ChildCount.Count "folders have exceeded the child folder limit of 10,000. These folders are"
    Write-Host "listed in the following file:"
    Write-Host $tooManyChildFoldersFile -ForegroundColor Green
    Write-Host "Under each of the listed folders, child folders should be relocated or deleted to reduce this number."
}

if ($limitsExceeded.FolderPathDepth.Count -gt 0) {
    $pathTooDeepFile = Join-Path $PSScriptRoot "PathTooDeep.txt"
    Set-Content -Path $pathTooDeepFile -Value $limitsExceeded.FolderPathDepth

    Write-Host
    Write-Host $limitsExceeded.FolderPathDepth.Count "folders have exceeded the path depth limit of 299. These folders are"
    Write-Host "listed in the following file:"
    Write-Host $pathTooDeepFile -ForegroundColor Green
    Write-Host "These folders should be relocated to reduce the path depth, or deleted."
}

if ($limitsExceeded.ItemCount.Count -gt 0) {
    $tooManyItemsFile = Join-Path $PSScriptRoot "TooManyItems.txt"
    Set-Content -Path $tooManyItemsFile -Value $limitsExceeded.ItemCount

    Write-Host
    Write-Host $limitsExceeded.ItemCount.Count "folders exceed the maximum of 1 million items. These folders are listed"
    Write-Host "in the following file:"
    Write-Host $tooManyItemsFile
    Write-Host "In each of these folders, items should be deleted to reduce the item count."
}

if ($badPermissions.Count -gt 0) {
    $badPermissionsFile = Join-Path $PSScriptRoot "InvalidPermissions.csv"
    $badPermissions | Export-Csv -Path $badPermissionsFile -NoTypeInformation

    Write-Host
    Write-Host $badPermissions.Count "invalid permissions were found. These are listed in the following CSV file:"
    Write-Host $badPermissionsFile -ForegroundColor Green
    Write-Host "The invalid permissions can be removed using the RemoveInvalidPermissions switch as follows:"
    Write-Host ".\SourceSideValidations.ps1 -RemoveInvalidPermissions" -ForegroundColor Green
}

$folderCountMigrationLimit = 250000

if ($folderData.IpmSubtree.Count -gt $folderCountMigrationLimit) {
    Write-Host
    Write-Host "There are $($folderData.IpmSubtree.Count) public folders in the hierarchy. This exceeds"
    Write-Host "the supported migration limit of $folderCountMigrationLimit for Exchange Online. The number"
    Write-Host "of public folders must be reduced prior to migrating to Exchange Online."
} elseif ($folderData.IpmSubtree.Count * 2 -gt $folderCountMigrationLimit) {
    Write-Host
    Write-Host "There are $($folderData.IpmSubtree.Count) public folders in the hierarchy. Because each of these"
    Write-Host "has a dumpster folder, the total number of folders to migrate will be $($folderData.IpmSubtree.Count * 2)."
    Write-Host "This exceeds the supported migration limit of $folderCountMigrationLimit for Exchange Online."
    Write-Host "New-MigrationBatch can be run with the -ExcludeDumpsters switch to skip the dumpster"
    Write-Host "folders, or public folders may be deleted to reduce the number of folders."
}

$private:endTime = Get-Date

Write-Host
Write-Host "SourceSideValidations complete. Total duration" ($endTime - $startTime)
