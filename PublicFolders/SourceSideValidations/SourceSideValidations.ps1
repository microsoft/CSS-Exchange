[CmdletBinding()]
param (
    [Parameter()]
    [bool]
    $StartFresh = $true
)

. .\Get-IpmSubtree.ps1
. .\Get-NonIpmSubtree.ps1
. .\Get-ItemCount.ps1
. .\Get-LimitsExceeded.ps1
. .\Get-BadDumpsterMappings.ps1
. .\Get-BadPermission.ps1
. .\Get-BadPermissionJob.ps1
. .\JobQueue.ps1

$startTime = Get-Date

Set-ADServerSettings -ViewEntireForest $true

$ipmSubtree = Get-IpmSubtree -startFresh $StartFresh

if ($ipmSubtree.Count -lt 1) {
    return
}

$nonIpmSubtree = Get-NonIpmSubtree -startFresh $StartFresh

Write-Progress -Activity "Populating hashtables"

$folderData = [PSCustomObject]@{
    IpmSubtree              = $ipmSubtree
    IpmSubtreeByMailbox     = $ipmSubtree | Group-Object ContentMailbox
    ParentEntryIdCounts     = @{}
    EntryIdDictionary       = @{}
    NonIpmSubtree           = $nonIpmSubtree
    NonIpmEntryIdDictionary = @{}
    MailboxToServerMap      = @{}
}

$ipmSubtree | ForEach-Object { $folderData.ParentEntryIdCounts[$_.ParentEntryId] += 1 }
$ipmSubtree | ForEach-Object { $folderData.EntryIdDictionary[$_.EntryId] = $_ }
$nonIpmSubtree | ForEach-Object { $folderData.NonIpmEntryIdDictionary[$_.EntryId] = $_ }
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

Get-ItemCount -FolderData $FolderData

# Now we're ready to do the checks

$badDumpsters = @(Get-BadDumpsterMappings -FolderData $folderData)

$limitsExceeded = Get-LimitsExceeded -FolderData $folderData

$badPermissions = @(Get-BadPermission -FolderData $folderData)

# Output the results

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
    Write-Host "The invalid permissions can be removed using the RemoveInvalidPermissions script as follows:"
    Write-Host ".\RemoveInvalidPermissions.ps1 $badPermissionsFile"
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
