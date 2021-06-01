. $PSScriptRoot\..\New-TestResult.ps1

function Test-FolderLimit {
    <#
    .SYNOPSIS
        Flags folders that exceed the child count limit, depth limit,
        or item limit.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSObject]
        $FolderData
    )

    begin {
        $startTime = Get-Date
        $progressCount = 0
        $limitsExceeded = [PSCustomObject]@{
            ChildCount      = @()
            FolderPathDepth = @()
            ItemCount       = @()
        }
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Checking limits"
            Id       = 2
            ParentId = 1
        }
        $testResultParams = @{
            TestName = "Limit"
            Severity = "Error"
        }
        $folderCountMigrationLimit = 250000
    }

    process {
        $FolderData.IpmSubtree | ForEach-Object {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount -PercentComplete ($progressCount * 100 / $FolderData.IpmSubtree.Count)
            }

            if ($FolderData.ParentEntryIdCounts[$_.EntryId] -gt 10000) {
                $testResultParams.ResultType = "ChildCount"
                $testResultParams.FolderIdentity = $_.Identity.ToString()
                $testResultParams.FolderEntryId = $_.EntryId.ToString()
                New-TestResult @testResultParams
            }

            if ([int]$_.FolderPathDepth -gt 299) {
                $testResultParams.ResultType = "FolderPathDepth"
                $testResultParams.FolderIdentity = $_.Identity.ToString()
                $testResultParams.FolderEntryId = $_.EntryId.ToString()
                New-TestResult @testResultParams
            }

            if ($FolderData.ItemCountDictionary[$_.EntryId] -gt 1000000) {
                $testResultParams.ResultType = "ItemCount"
                $testResultParams.FolderIdentity = $_.Identity.ToString()
                $testResultParams.FolderEntryId = $_.EntryId.ToString()
                New-TestResult @testResultParams
            }
        }

        if ($folderData.IpmSubtree.Count -gt $folderCountMigrationLimit) {
            $testResultParams.ResultType = "HierarchyCount"
            $testResultParams.FolderIdentity = ""
            $testResultParams.FolderEntryId = ""
            $testResultParams.ResultData = $folderData.IpmSubtree.Count
            New-TestResult @testResultParams
        } elseif ($folderData.IpmSubtree.Count * 2 -gt $folderCountMigrationLimit) {
            $testResultParams.ResultType = "HierarchyAndDumpsterCount"
            $testResultParams.FolderIdentity = ""
            $testResultParams.FolderEntryId = ""
            $testResultParams.ResultData = $folderData.IpmSubtree.Count
            New-TestResult @testResultParams
        }
    }

    end {
        Write-Progress @progressParams -Completed

        $params = @{
            TestName       = $testResultParams.TestName
            ResultType     = "Duration"
            Severity       = "Information"
            FolderIdentity = ""
            FolderEntryId  = ""
            ResultData     = ((Get-Date) - $startTime)
        }

        New-TestResult @params
    }
}
