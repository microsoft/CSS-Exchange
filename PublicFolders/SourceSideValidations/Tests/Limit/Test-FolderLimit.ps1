# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Checking limits in IPM_SUBTREE"
            Id       = 2
            ParentId = 1
        }
        $testResultParams = @{
            TestName = "Limit"
            Severity = "Error"
        }
        $folderCountMigrationLimit = 250000
        $aggregateChildItemCounts = @{}
    }

    process {
        # We start from the deepest folders and work upwards so we can calculate the aggregate child
        # counts in one pass
        foreach ($folder in ($FolderData.IpmSubtree | Sort-Object FolderPathDepth -Descending)) {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount -PercentComplete ($progressCount * 100 / $FolderData.IpmSubtree.Count)
            }

            # If we failed to get statistics for some reason, assume we have content
            [int]$itemCount = 1
            [Int64]$totalItemSize = 0
            $aggregateChildItemCount = $aggregateChildItemCounts[$folder.EntryId]

            $stats = $FolderData.StatisticsDictionary[$folder.EntryId]
            if ($null -ne $stats) {
                [int]$itemCount = $stats.ItemCount
                [Int64]$totalItemSize = $stats.TotalItemSize
            } else {
                $noStatisticsResult = @{
                    TestName       = "Limit"
                    Severity       = "Warning"
                    ResultType     = "NoStatistics"
                    FolderIdentity = $folder.Identity.ToString()
                    FolderEntryId  = $folder.EntryId.ToString()
                }
                New-TestResult @noStatisticsResult
            }

            $parent = $FolderData.EntryIdDictionary[$folder.ParentEntryId]
            if ($null -ne $parent) {
                $aggregateChildItemCounts[$parent.EntryId] += $itemCount
                if ($null -ne $aggregateChildItemCount) {
                    $aggregateChildItemCounts[$parent.EntryId] += $aggregateChildItemCount
                }
            }

            if ($itemCount -lt 1 -and $aggregateChildItemCounts[$folder.EntryId] -lt 1 -and $folder.FolderPathDepth -gt 0) {
                $emptyFolderInformation = @{
                    TestName       = "Limit"
                    Severity       = "Information"
                    ResultType     = "EmptyFolder"
                    FolderIdentity = $folder.Identity.ToString()
                    FolderEntryId  = $folder.EntryId.ToString()
                }
                New-TestResult @emptyFolderInformation
            }

            if ($FolderData.ParentEntryIdCounts[$folder.EntryId] -gt 10000) {
                $testResultParams.ResultType = "ChildCount"
                $testResultParams.FolderIdentity = $folder.Identity.ToString()
                $testResultParams.FolderEntryId = $folder.EntryId.ToString()
                New-TestResult @testResultParams
            }

            if ($folder.FolderPathDepth -gt 299) {
                $testResultParams.ResultType = "FolderPathDepth"
                $testResultParams.FolderIdentity = $folder.Identity.ToString()
                $testResultParams.FolderEntryId = $folder.EntryId.ToString()
                New-TestResult @testResultParams
            }

            if ($itemCount -gt 1000000) {
                $testResultParams.ResultType = "ItemCount"
                $testResultParams.FolderIdentity = $folder.Identity.ToString()
                $testResultParams.FolderEntryId = $folder.EntryId.ToString()
                New-TestResult @testResultParams
            }

            if ($totalItemSize -gt 25000000000) {
                $testResultParams.ResultType = "TotalItemSize"
                $testResultParams.FolderIdentity = $folder.Identity.ToString()
                $testResultParams.FolderEntryId = $folder.EntryId.ToString()
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

        $progressParams.Activity = "Checking limits in NON_IPM_SUBTREE"
        $progressCount = 0

        foreach ($folder in ($FolderData.NonIpmSubtree | Sort-Object FolderPathDepth -Descending)) {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount -PercentComplete ($progressCount * 100 / $FolderData.NonIpmSubtree.Count)
            }

            if ($FolderData.ParentEntryIdCounts[$folder.EntryId] -gt 10000) {
                $testResultParams.ResultType = "ChildCount"
                $testResultParams.FolderIdentity = $folder.Identity.ToString()
                $testResultParams.FolderEntryId = $folder.EntryId.ToString()
                New-TestResult @testResultParams
            }
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
