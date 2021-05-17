[CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [bool]
    $StartFresh = $true,

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [switch]
    $SlowTraversal,

    [Parameter(Mandatory = $true, ParameterSetName = "Repair")]
    [Switch]
    $Repair,

    [Parameter(Mandatory = $true, ParameterSetName = "ShowPreviousResults")]
    [Switch]
    $ShowPreviousResults,

    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "Repair")]
    [Parameter(ParameterSetName = "ShowPreviousResults")]
    [string]
    $ResultsFile = (Join-Path $PSScriptRoot "ValidationResults.csv"),

    [Parameter()]
    [switch]
    $SkipVersionCheck
)

. $PSScriptRoot\Tests\DumpsterMapping\AllFunctions.ps1
. $PSScriptRoot\Tests\Limit\AllFunctions.ps1
. $PSScriptRoot\Tests\MailEnabledFolder\AllFunctions.ps1
. $PSScriptRoot\Tests\Permission\AllFunctions.ps1
. $PSScriptRoot\Get-FolderData.ps1
. $PSScriptRoot\JobQueue.ps1
. $PSScriptRoot\..\..\..\Shared\Test-ScriptVersion.ps1

if (-not $SkipVersionCheck) {
    if (Test-ScriptVersion -AutoUpdate) {
        # Update was downloaded, so stop here.
        Write-Host "Script was updated. Please rerun the command."
        return
    }
}

if ($ShowPreviousResults) {
    $results = Import-Csv $ResultsFile
    $results | Format-Table TestName, ResultType, Severity, FolderIdentity, ResultData -AutoSize
    $results | Write-TestDumpsterMappingResult
    $results | Write-TestFolderLimitResult
    $results | Write-TestMailEnabledFolderResult
    $results | Write-TestBadPermissionResult
    return
}

if ($Repair) {
    if (-not (Test-Path $ResultsFile)) {
        Write-Error "File not found: $ResultsFile. Please run without -Repair to generate a results file."
    } else {
        Import-Csv $ResultsFile | Repair-FolderPermission
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

$folderData = Get-FolderData -StartFresh $StartFresh -SlowTraversal $SlowTraversal

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

$badDumpsters = Test-DumpsterMapping -FolderData $folderData
$badDumpsters | Export-Csv $ResultsFile -NoTypeInformation

Write-Progress @progressParams -Status "Step 3 of 5"

$limitsExceeded = Test-FolderLimit -FolderData $folderData
$limitsExceeded | Export-Csv $ResultsFile -NoTypeInformation -Append

Write-Progress @progressParams -Status "Step 4 of 5"

$badMailEnabled = Test-MailEnabledFolder -FolderData $folderData
$badMailEnabled | Export-Csv $ResultsFile -NoTypeInformation -Append

Write-Progress @progressParams -Status "Step 5 of 5"

$badPermissions = Test-Permission -FolderData $folderData
$badPermissions | Export-Csv $ResultsFile -NoTypeInformation -Append

# Output the results

$badDumpsters | Write-TestDumpsterMappingResult
$limitsExceeded | Write-TestFolderLimitResult
$badMailEnabled | Write-TestMailEnabledFolderResult
$badPermissions | Write-TestBadPermissionResult

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

Write-Host
Write-Host "Validation results were written to file:"
Write-Host $ResultsFile -ForegroundColor Green

$private:endTime = Get-Date

Write-Host
Write-Host "SourceSideValidations complete. Total duration" ($endTime - $startTime)
