# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-StringDataForNotEnoughFreeSpace.ps1
. $PSScriptRoot\..\Test-FreeSpace.ps1
function Copy-FullLogFullPathRecurse {
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$CopyToThisLocation
    )
    Write-Verbose("Function Enter: Copy-FullLogFullPathRecurse")
    Write-Verbose("Passed: [string]LogPath: {0} | [string]CopyToThisLocation: {1}" -f $LogPath, $CopyToThisLocation)
    New-Item -ItemType Directory -Path $CopyToThisLocation -Force | Out-Null
    if (Test-Path $LogPath) {
        $childItems = Get-ChildItem $LogPath -Recurse
        $items = @()
        foreach ($childItem in $childItems) {
            if (!($childItem.Mode.StartsWith("d-"))) {
                $items += $childItem.VersionInfo.FileName
            }
        }

        if ($null -ne $items -and
            $items.Count -gt 0) {
            if (Test-FreeSpace -FilePaths $items) {
                Copy-Item $LogPath\* $CopyToThisLocation -Recurse -ErrorAction SilentlyContinue
                Invoke-ZipFolder $CopyToThisLocation
            } else {
                Write-Verbose("Not going to copy over this set of data due to size restrictions.")
                New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToThisLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -FileSizes $Script:ItemSizesHashed) | Out-Null
            }
        } else {
            Write-Host "No data at path '$LogPath'. Unable to copy this data."
            New-Item -Path ("{0}\NoDataDetected.txt" -f $CopyToThisLocation) -ItemType File -Value $LogPath | Out-Null
        }
    } else {
        Write-Host "No Folder at $LogPath. Unable to copy this data."
        New-Item -Path ("{0}\NoFolderDetected.txt" -f $CopyToThisLocation) -ItemType File -Value $LogPath | Out-Null
    }
    Write-Verbose("Function Exit: Copy-FullLogFullPathRecurse")
}
