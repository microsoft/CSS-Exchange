# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-StringDataForNotEnoughFreeSpace.ps1
. $PSScriptRoot\..\Test-FreeSpace.ps1
function Copy-BulkItems {
    param(
        [string]$CopyToLocation,
        [Array]$ItemsToCopyLocation
    )

    New-Item -ItemType Directory -Path $CopyToLocation -Force | Out-Null

    if (Test-FreeSpace -FilePaths $ItemsToCopyLocation) {
        foreach ($item in $ItemsToCopyLocation) {
            Copy-Item -Path $item -Destination $CopyToLocation -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "Not enough free space to copy over this data set."
        New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -FileSizes $Script:ItemSizesHashed) | Out-Null
    }
}
