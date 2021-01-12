# This script compares two sets of mailbox statistics from the same database and highlights mailbox growth
# that occurred between the two snapshots.
#
# For a growing database, a typical approach would be to start by exporting the statistics for the database:
#
# Get-MailboxStatistics -Database DB1 | Export-CliXML C:\stats-before.xml
#
# After the initial export is obtained, wait until significant growth is observed. That could mean
# waiting an hour, or a day, depending on the scenario. At that point, compare the stats-before.xml
# with the live data by using this script as follows:
#
# .\Compare-MailboxStatistics.ps1 -Before (Import-CliXml C:\stats-before.xml) -After (Get-MailboxStatistics -Database DB1)
#
# This makes it easy to see which mailboxes grew the most.
[CmdletBinding()]
param($Before, $After)

$numberOfTopResults = 100

function GetBytesFromSizeString($sizeString) {
    $s = ($sizeString | Select-String "\(([\d|\,]+) bytes").Matches.Groups[1].Value
    return [long]::Parse($s, "AllowThousands")
}

function GetComparableObjectFromStatistics($stats) {
    return [PSCustomObject]@{
        DisplayName              = $stats.DisplayName
        MailboxGuid              = $stats.MailboxGuid.ToString()
        ItemCount                = $stats.ItemCount
        TotalDeletedItemSize     = GetBytesFromSizeString $stats.TotalDeletedItemSize
        TotalItemSize            = GetBytesFromSizeString $stats.TotalItemSize
        MessageTableTotalSize    = GetBytesFromSizeString $stats.MessageTableTotalSize
        AttachmentTableTotalSize = GetBytesFromSizeString $stats.AttachmentTableTotalSize
        OtherTablesTotalSize     = GetBytesFromSizeString $stats.OtherTablesTotalSize
    }
}

function GetComparisonResult($beforeComparable, $afterComparable) {
    return [PSCustomObject]@{
        DisplayName                   = $afterComparable.DisplayName # We're assuming the caller did the right thing
        MailboxGuid                   = $afterComparable.MailboxGuid # and passed matching objects here.
        ItemCountDelta                = $afterComparable.ItemCount - $beforeComparable.ItemCount
        TotalDeletedItemSizeDelta     = $afterComparable.TotalDeletedItemSize - $beforeComparable.TotalDeletedItemSize
        TotalItemSizeDelta            = $afterComparable.TotalItemSize - $beforeComparable.TotalItemSize
        MessageTableTotalSizeDelta    = $afterComparable.MessageTableTotalSize - $beforeComparable.MessageTableTotalSize
        AttachmentTableTotalSizeDelta = $afterComparable.AttachmentTableTotalSize - $beforeComparable.AttachmentTableTotalSize
        OtherTablesTotalSizeDelta     = $afterComparable.OtherTablesTotalSize - $beforeComparable.OtherTablesTotalSize
    }
}

$beforeComparables = $Before | ForEach-Object { GetComparableObjectFromStatistics $_ }
$afterComparables = $After | ForEach-Object { GetComparableObjectFromStatistics $_ }

$beforeHash = @{}
$beforeComparables | ForEach-Object { $beforeHash[$_.MailboxGuid] = $_ }

$afterHash = @{}
$afterComparables | ForEach-Object { $afterHash[$_.MailboxGuid] = $_ }

$comparisonResults = @()

$afterComparables | ForEach-Object {
    $beforeComparable = $beforeHash[$_.MailboxGuid]
    if ($null -ne $beforeComparable) {
        $comparisonResults += GetComparisonResult $beforeComparable $_
    }
}

$totalSizeBefore = 0
$totalDeletedSizeBefore = 0
$beforeComparables | ForEach-Object { $totalSizeBefore += $_.TotalItemSize; $totalDeletedSizeBefore += $_.TotalDeletedItemSize }

$totalSizeAfter = 0
$totalDeletedSizeAfter = 0
$afterComparables | ForEach-Object { $totalSizeAfter += $_.TotalItemSize; $totalDeletedSizeAfter += $_.TotalDeletedItemSize }

Write-Host "Totals Comparison" -ForegroundColor Green
Write-Host "=================" -ForegroundColor Green
@(
    [PSCustomObject]@{
        Name   = "TotalItemSize Sum (MB)"
        Before = ([long]($totalSizeBefore / 1024 / 1024))
        After  = ([long]($totalSizeAfter / 1024 / 1024))
        Delta  = ([long](($totalSizeAfter - $totalSizeBefore) / 1024 / 1024))
    },
    [PSCustomObject]@{
        Name   = "TotalDeletedItemSize Sum (MB)"
        Before = ([long]($totalDeletedSizeBefore / 1024 / 1024))
        After  = ([long]($totalDeletedSizeAfter / 1024 / 1024))
        Delta  = ([long](($totalDeletedSizeAfter - $totalDeletedSizeBefore) / 1024 / 1024))
    }
) | Out-Host


$created = $afterComparables | Where-Object { $beforeHash[$_.MailboxGuid] -eq $null }
$createdSizeSum = 0
$createdDeletedSum = 0
$created | ForEach-Object { $createdSizeSum += $_.TotalItemSize; $createdDeletedSum += $_.TotalDeletedItemSize }

Write-Host "New Mailboxes" -ForegroundColor Green
Write-Host "=============" -ForegroundColor Green
Write-Host "The following $($created.Count) mailboxes are present after that were not present before. These may be new, or may have been moved to this database." -ForegroundColor Green
Write-Host "These account for $([long]($createdSizeSum / 1024 / 1024)) MB item size and $([long]($createdDeletedSum / 1024 / 1024)) MB deleted item size." -ForegroundColor Green

$created | Sort-Object TotalItemSize -Descending | Select-Object -First $numberOfTopResults | Format-Table -a DisplayName, MailboxGuid, TotalItemSize, TotalDeletedItemSize

$deleted = $beforeComparables | Where-Object { $afterHash[$_.MailboxGuid] -eq $null }
$deletedSizeSum = 0
$deletedDeletedSum = 0
$deleted | ForEach-Object { $deletedSizeSum += $_.TotalItemSize; $deletedDeletedSum += $_.TotalDeletedItemSize }

Write-Host "Deleted Mailboxes" -ForegroundColor Green
Write-Host "=================" -ForegroundColor Green
Write-Host "The following $($deleted.Count) mailboxes are no longer present in the database. These may have been deleted or moved off." -ForegroundColor Green
Write-Host "These accounted for $([long]($deletedSizeSum / 1024 / 1024)) MB item size and $([long]($deletedDeletedSum / 1024 / 1024)) MB deleted item size in the `"before`" data." -ForegroundColor Green

$deleted | Sort-Object TotalItemSize -Descending | Select-Object -First $numberOfTopResults | Format-Table -a DisplayName, MailboxGuid, TotalItemSize, TotalDeletedItemSize

Write-Host "Most growth by TotalItemSize" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green

$comparisonResults | Sort-Object TotalItemSizeDelta -Descending | Select-Object -First $numberOfTopResults | Format-Table DisplayName, MailboxGuid, TotalItemSizeDelta | Out-Host

Write-Host "Most growth by TotalDeletedItemSize" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green

$comparisonResults | Sort-Object TotalDeletedItemSizeDelta -Descending | Select-Object -First $numberOfTopResults | Format-Table DisplayName, MailboxGuid, TotalDeletedItemSizeDelta | Out-Host

Write-Host "Most growth by MessageTableTotalSize" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green

$comparisonResults | Sort-Object MessageTableTotalSizeDelta -Descending | Select-Object -First $numberOfTopResults | Format-Table DisplayName, MailboxGuid, MessageTableTotalSizeDelta | Out-Host

Write-Host "Most growth by AttachmentTableTotalSize" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green

$comparisonResults | Sort-Object AttachmentTableTotalSizeDelta -Descending | Select-Object -First $numberOfTopResults | Format-Table DisplayName, MailboxGuid, AttachmentTableTotalSizeDelta | Out-Host

$totalOtherTablesTotalSize = ($comparisonResults | ForEach-Object { $_.OtherTablesTotalSizeDelta } | Measure-Object -Sum).Sum
Write-Host "Most growth by OtherTablesTotalSize ( $totalOtherTablesTotalSize bytes total growth )" -ForegroundColor Green
Write-Host "=====================================================================================" -ForegroundColor Green

$comparisonResults | Sort-Object OtherTablesTotalSizeDelta -Descending | Select-Object -First $numberOfTopResults | Format-Table DisplayName, MailboxGuid, OtherTablesTotalSizeDelta | Out-Host
