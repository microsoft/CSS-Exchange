# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\New-Folder.ps1
. $PSScriptRoot\..\Get-StringDataForNotEnoughFreeSpace.ps1
. $PSScriptRoot\..\Test-FreeSpace.ps1
Function Copy-BulkItems {
    param(
        [string]$CopyToLocation,
        [Array]$ItemsToCopyLocation
    )
    if (-not(Test-Path $CopyToLocation)) {
        New-Folder -NewFolder $CopyToLocation -IncludeDisplayCreate $true
    }

    if (Test-FreeSpace -FilePaths $ItemsToCopyLocation) {
        foreach ($item in $ItemsToCopyLocation) {
            Copy-Item -Path $item -Destination $CopyToLocation -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "Not enough free space to copy over this data set."
        New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -hasher $Script:ItemSizesHashed) | Out-Null
    }
}
