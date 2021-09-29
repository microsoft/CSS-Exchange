# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-ResultSummary.ps1

function Write-TestFolderLimitResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $childCountResults = New-Object System.Collections.ArrayList
        $folderPathDepthResults = New-Object System.Collections.ArrayList
        $itemCountResults = New-Object System.Collections.ArrayList
        $totalItemSizeResults = New-Object System.Collections.ArrayList
        $emptyFolderResults = New-Object System.Collections.ArrayList
        $hierarchyCountResult = $null
        $hierarchyAndDumpsterCountResult = $null
        $folderCountMigrationLimit = 250000
    }

    process {
        if ($TestResult.TestName -eq "Limit") {
            switch ($TestResult.ResultType) {
                "EmptyFolder" { [void]$emptyFolderResults.Add($TestResult) }
                "ChildCount" { [void]$childCountResults.Add($TestResult) }
                "FolderPathDepth" { [void]$folderPathDepthResults.Add($TestResult) }
                "ItemCount" { [void]$itemCountResults.Add($TestResult) }
                "TotalItemSize" { [void]$totalItemSizeResults.Add($TestResult) }
                "HierarchyCount" { $hierarchyCountResult = $TestResult }
                "HierarchyAndDumpsterCount" { $hierarchyAndDumpsterCountResult = $TestResult }
            }
        }
    }

    end {
        if ($childCountResults.Count -gt 0) {
            Get-ResultSummary -ResultType $childCountResults[0].ResultType -Severity $childCountResults[0].Severity -Count $childCountResults.Count -Action (
                "Under each of the listed folders, child folders should be relocated or deleted to reduce " +
                "the number of child folders to 10,000 or less.")
        }

        if ($folderPathDepthResults.Count -gt 0) {
            Get-ResultSummary -ResultType $folderPathDepthResults[0].ResultType -Severity $folderPathDepthResults[0].Severity -Count $folderPathDepthResults.Count -Action (
                "These folders should be relocated to reduce the path depth to 299 or less.")
        }

        if ($itemCountResults.Count -gt 0) {
            Get-ResultSummary -ResultType $itemCountResults[0].ResultType -Severity $itemCountResults[0].Severity -Count $itemCountResults.Count -Action (
                "Items should be deleted from these folders to reduce the item count in each folder to 1 million items or less.")
        }

        if ($totalItemSizeResults.Count -gt 0) {
            Get-ResultSummary -ResultType $totalItemSizeResults[0].ResultType -Severity $totalItemSizeResults[0].Severity -Count $totalItemSizeResults.Count -Action (
                "Items should be deleted from these folders until the folder size is less than 25 GB.")
        }

        if ($null -ne $hierarchyCountResult) {
            Get-ResultSummary -ResultType $hierarchyCountResult.ResultType -Severity $hierarchyCountResult.Severity -Count 1 -Action (
                "There are $($hierarchyCountResult.ResultData) public folders in the hierarchy. This exceeds " +
                "the supported migration limit of $folderCountMigrationLimit for Exchange Online. The number " +
                "of public folders must be reduced prior to migrating to Exchange Online.")
        }

        if ($null -ne $hierarchyAndDumpsterCountResult) {
            Get-ResultSummary -ResultType $hierarchyAndDumpsterCountResult.ResultType -Severity $hierarchyAndDumpsterCountResult.Severity -Count 1 -Action (
                "There are $($hierarchyAndDumpsterCountResult.ResultData) public folders in the hierarchy. Because each of these " +
                "has a dumpster folder, the total number of folders to migrate will be twice as many. " +
                "This exceeds the supported migration limit of $folderCountMigrationLimit for Exchange Online. " +
                "New-MigrationBatch can be run with the -ExcludeDumpsters switch to skip the dumpster " +
                "folders, or public folders may be deleted to reduce the number of folders.")
        }

        if ($emptyFolderResults.Count -gt 0) {
            Get-ResultSummary -ResultType $emptyFolderResults[0].ResultType -Severity $emptyFolderResults[0].Severity -Count $emptyFolderResults.Count -Action (
                "Folders contain no items and have only empty subfolders. " +
                "These will not cause a migration issue, but they may be pruned if desired.")
        }
    }
}
