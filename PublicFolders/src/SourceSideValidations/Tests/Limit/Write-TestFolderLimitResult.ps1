function Write-TestFolderLimitResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $childCount = 0
        $folderPathDepth = 0
        $itemCount = 0
        $hierarchyCount = $null
        $hierarchyAndDumpsterCount = $null
        $folderCountMigrationLimit = 250000
    }

    process {
        if ($TestResult.TestName -eq "Limit") {
            switch ($TestResult.ResultType) {
                "ChildCount" { $childCount++ }
                "FolderPathDepth" { $folderPathDepth++ }
                "ItemCount" { $itemCount++ }
                "HierarchyCount" { $hierarchyCount = $TestResult.ResultData }
                "HierarchyAndDumpsterCount" { $hierarchyAndDumpsterCount = $TestResult.ResultData }
            }
        }
    }

    end {
        if ($childCount -gt 0) {
            Write-Host
            Write-Host $childCount "folders have exceeded the child folder limit of 10,000."
            Write-Host "These folders are shown in the results CSV with a result type of ChildCount."
            Write-Host "Under each of the listed folders, child folders should be relocated or deleted to reduce this number."
        }

        if ($folderPathDepth -gt 0) {
            Write-Host
            Write-Host $folderPathDepth "folders have exceeded the path depth limit of 299."
            Write-Host "These folders are shown in the results CSV with a result type of FolderPathDepth."
            Write-Host "These folders should be relocated to reduce the path depth, or deleted."
        }

        if ($itemCount -gt 0) {
            Write-Host
            Write-Host $itemCount "folders exceed the maximum of 1 million items."
            Write-Host "These folders are shown in the results CSV with a result type of ItemCount."
            Write-Host "In each of these folders, items should be deleted to reduce the item count."
        }

        if ($null -ne $hierarchyCount) {
            Write-Host
            Write-Host "There are $hierarchyCount public folders in the hierarchy. This exceeds"
            Write-Host "the supported migration limit of $folderCountMigrationLimit for Exchange Online. The number"
            Write-Host "of public folders must be reduced prior to migrating to Exchange Online."
        }

        if ($null -ne $hierarchyAndDumpsterCount) {
            Write-Host
            Write-Host "There are $hierarchyAndDumpsterCount public folders in the hierarchy. Because each of these"
            Write-Host "has a dumpster folder, the total number of folders to migrate will be twice as many."
            Write-Host "This exceeds the supported migration limit of $folderCountMigrationLimit for Exchange Online."
            Write-Host "New-MigrationBatch can be run with the -ExcludeDumpsters switch to skip the dumpster"
            Write-Host "folders, or public folders may be deleted to reduce the number of folders."
        }
    }
}