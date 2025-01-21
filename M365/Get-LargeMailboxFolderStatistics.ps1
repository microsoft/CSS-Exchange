# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Modules @{ ModuleName="ExchangeOnlineManagement"; ModuleVersion="3.4.0" }

<#
.SYNOPSIS
    Retrieves folder statistics for mailboxes with large numbers of folders.

.DESCRIPTION
    This script retrieves folder statistics for large mailboxes or a specified user identity.
    It can target either primary or archive mailboxes and processes the data in batches.

.PARAMETER Identity
    The identity of the user whose mailbox folder statistics are to be retrieved.

.PARAMETER MailboxType
    Specifies the type of mailbox to target. Valid values are "Primary" and "Archive".
    Default is "Archive".

.PARAMETER BatchSize
    Specifies the number of items to process in each batch. Default is 5000.

.PARAMETER Properties
    Specifies the properties to include in the output. Default is "Name, FolderPath, ItemsInFolder, FolderSize, FolderAndSubfolderSize".

.EXAMPLE
    $folderStats = .\Get-LargeMailboxFolderStatistics.ps1 -Identity fred@contoso.com
    $folderStats = .\Get-LargeMailboxFolderStatistics.ps1 -Identity fred@contoso.com -MailboxType Primary
    $folderStats = .\Get-LargeMailboxFolderStatistics.ps1 -Identity fred@contoso.com -MailboxType Archive -BatchSize 5000 -Properties @("Name", "FolderPath")
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    $Identity,
    [Parameter(Mandatory = $false, Position = 1)]
    [ValidateSet("Primary", "Archive")]
    $MailboxType = "Archive",
    [Parameter(Mandatory = $false, Position = 2)]
    $BatchSize = 5000,
    [Parameter(Mandatory = $false, Position = 3)]
    [string[]]$Properties = @("Name", "FolderPath", "ItemsInFolder", "FolderSize", "FolderAndSubfolderSize")
)

process {
    $allContentFolders = New-Object System.Collections.Generic.List[object]
    $start = Get-Date
    Write-Host "$start Running Get-MailboxFolderStatistics for $Identity $MailboxType locations, in batches of $BatchSize"

    $mailboxLocations = Get-MailboxLocation -User $Identity

    foreach ($location in $mailboxLocations) {
        if (($location.MailboxLocationType -like '*Archive' -and $MailboxType -like 'Archive') -or ($location.MailboxLocationType -like '*Primary' -and $MailboxType -like 'Primary')) {
            $loopCount = 0
            do {
                $skipCount = $BatchSize * $loopCount
                $batch = Get-MailboxFolderStatistics -Identity $($location.Identity) -ResultSize $batchSize -SkipCount $skipCount
                [System.Array]$contentFolders = $batch | Where-Object { $_.ContentFolder -eq "TRUE" } | Select-Object -Property $Properties
                if ($contentFolders.Count -gt 0) {
                    $allContentFolders.AddRange($contentFolders)
                }
                Write-Host "$(Get-Date):$loopCount Found $($batch.Count) content folders from $($location.MailboxLocationType):$($location.MailboxGuid)"
                $loopCount += 1
            }
            while ($($batch.Count) -eq $BatchSize)
        }
    }

    $end = Get-Date
    Write-Host "$end Found $($allContentFolders.Count) total content folders in $(($end-$start).ToString()) duration"

    $allContentFolders
}
