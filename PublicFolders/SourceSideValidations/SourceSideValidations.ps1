. .\Get-IpmSubtree.ps1
. .\Get-NonIpmSubtree.ps1
. .\Get-ItemCounts.ps1
. .\Get-LimitsExceeded.ps1
. .\Get-BadDumpsterMappings.ps1
. .\Get-BadPermissions.ps1

$private:startTime = Get-Date

$private:ipmSubtree = Get-IpmSubtree

if ($ipmSubtree.Count -lt 1) {
    return
}

$private:nonIpmSubtree = Get-NonIpmSubtree

Write-Progress -Activity "Populating hashtables"

$private:folderData = [PSCustomObject]@{
    IpmSubtree              = $ipmSubtree
    ParentEntryIdCounts     = @{}
    EntryIdDictionary       = @{}
    NonIpmSubtree           = $nonIpmSubtree
    NonIpmEntryIdDictionary = @{}
}

$ipmSubtree | ForEach-Object { $folderData.ParentEntryIdCounts[$_.ParentEntryId] += 1 }
$ipmSubtree | ForEach-Object { $folderData.EntryIdDictionary[$_.EntryId] = $_ }
$nonIpmSubtree | ForEach-Object { $folderData.NonIpmEntryIdDictionary[$_.EntryId] = $_ }

Get-ItemCounts -FolderData $folderData

$private:limitsExceeded = Get-LimitsExceeded -FolderData $folderData

$private:badDumpsters = Get-BadDumpsterMappings -FolderData $folderData

$private:badPermissions = Get-BadPermissions -FolderData $folderData

$private:endTime = Get-Date

Write-Host "Duration" ($endTime - $startTime)
