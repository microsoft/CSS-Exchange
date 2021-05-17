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
    }

    process {
        if ($TestResult.TestName -eq "Limit") {
            switch ($TestResult.ResultType) {
                "ChildCount" { $childCount++ }
                "FolderPathDepth" { $folderPathDepth++ }
                "ItemCount" { $itemCount++ }
            }
        }
    }

    end {
        if ($childCount -gt 0) {
            Write-Host
            Write-Host $childCount "folders have exceeded the child folder limit of 10,000."
            Write-Host "Under each of the listed folders, child folders should be relocated or deleted to reduce this number."
        }

        if ($folderPathDepth -gt 0) {
            Write-Host
            Write-Host $folderPathDepth "folders have exceeded the path depth limit of 299. These folders are"
            Write-Host "These folders should be relocated to reduce the path depth, or deleted."
        }

        if ($itemCount -gt 0) {
            Write-Host
            Write-Host $itemCount "folders exceed the maximum of 1 million items."
            Write-Host "In each of these folders, items should be deleted to reduce the item count."
        }
    }
}