param($csvFile)

$badPermissions = Import-Csv $csvFile
$byEntryId = $badPermissions | Group-Object EntryId
$progressCount = 0
$badPermissions | Select-Object -Unique EntryId | ForEach-Object {
    $progressCount++
    Write-Progress -Activity "Removing invalid permissions" -Status "$progressCount / $($byEntryId.Count)" -PercentComplete ($progressCount * 100 / $byEntryId.Count) -CurrentOperation $_.Identity
    $folder = $_
    Get-PublicFolderClientPermission -Identity $folder.EntryId | ForEach-Object {
        if (
            ($_.User.DisplayName -ne "Default") -and
            ($_.User.DisplayName -ne "Anonymous") -and
            ($null -eq $_.User.ADRecipient) -and
            ($_.User.UserType -eq "Unknown")
        ) {
            Write-Host "Removing $($_.User.DisplayName) from folder $($_.Identity.ToString())"
            $_ | Remove-PublicFolderClientPermission -Confirm:$false
        }
    }
}