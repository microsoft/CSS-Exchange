# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-FolderData {
    [CmdletBinding()]
    param (
        [Parameter()]
        [bool]
        $StartFresh = $true
    )

    begin {
        $startTime = Get-Date
        $serverName = (Get-Mailbox -PublicFolder (Get-OrganizationConfig).RootPublicFolderMailbox.HierarchyMailboxGuid.ToString()).ServerName
        $folderData = [PSCustomObject]@{
            IpmSubtree              = $null
            IpmSubtreeByMailbox     = $null
            ParentEntryIdCounts     = @{}
            EntryIdDictionary       = @{}
            NonIpmSubtree           = $null
            NonIpmEntryIdDictionary = @{}
            MailboxToServerMap      = @{}
            ItemCounts              = @()
        }
    }

    process {
        if (-not $StartFresh -and (Test-Path $PSScriptRoot\IpmSubtree.csv)) {
            $folderData.IpmSubtree = Import-Csv $PSScriptRoot\IpmSubtree.csv
            $folderData.NonIpmSubtree = Import-Csv $PSScriptRoot\NonIpmSubtree.csv
            $folderData.ItemCounts = Import-Csv $PSScriptRoot\ItemCounts.csv
        } else {
            Add-JobQueueJob @{
                ArgumentList = $serverName
                Name         = "Get-IpmSubtree"
                ScriptBlock  = ${Function:Get-IpmSubtree}
            }

            Add-JobQueueJob @{
                ArgumentList = $serverName
                Name         = "Get-NonIpmSubtree"
                ScriptBlock  = ${Function:Get-NonIpmSubtree}
            }

            Add-JobQueueJob @{
                ArgumentList = $serverName
                Name         = "Get-ItemCount"
                ScriptBlock  = ${Function:Get-ItemCount}
            }

            $completedJobs = Wait-QueuedJob

            foreach ($job in $completedJobs) {
                if ($null -ne $job.IpmSubtree) {
                    $folderData.IpmSubtree = $job.IpmSubtree
                    $folderData.IpmSubtree | Export-Csv $PSScriptRoot\IpmSubtree.csv
                }

                if ($null -ne $job.NonIpmSubtree) {
                    $folderData.NonIpmSubtree = $job.NonIpmSubtree
                    $folderData.NonIpmSubtree | Export-Csv $PSScriptRoot\NonIpmSubtree.csv
                }

                if ($null -ne $job.ItemCounts) {
                    $folderData.ItemCounts = $job.ItemCounts
                    $folderData.ItemCounts | Export-Csv $PSScriptRoot\ItemCounts.csv
                }
            }
        }

        $folderData.IpmSubtreeByMailbox = $folderData.IpmSubtree | Group-Object ContentMailbox
        $folderData.IpmSubtree | ForEach-Object { $folderData.ParentEntryIdCounts[$_.ParentEntryId] += 1 }
        $folderData.IpmSubtree | ForEach-Object { $folderData.EntryIdDictionary[$_.EntryId] = $_ }
        $folderData.NonIpmSubtree | ForEach-Object { $folderData.NonIpmEntryIdDictionary[$_.EntryId] = $_ }
        $folderData.ItemCounts | ForEach-Object {
            if ($_.ItemCount -gt 0) {
                $folder = $folderData.EntryIdDictionary[$_.EntryId.ToString()]

                if ($null -ne $folder) {
                    $folder.ItemCount = $_.ItemCount
                }
            }
        }
    }

    end {
        Write-Host "Get-FolderData duration $((Get-Date) - $startTime)"
        Write-Host "    IPM_SUBTREE folder count: $($folderData.IpmSubtree.Count)"
        Write-Host "    NON_IPM_SUBTREE folder count: $($folderData.NonIpmSubtree.Count)"

        return $folderData
    }
}

. $PSScriptRoot\Get-IpmSubtree.ps1
. $PSScriptRoot\Get-NonIpmSubtree.ps1
. $PSScriptRoot\Get-ItemCount.ps1
