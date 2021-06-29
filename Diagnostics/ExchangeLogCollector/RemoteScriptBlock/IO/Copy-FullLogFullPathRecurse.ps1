# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Copy-FullLogFullPathRecurse {
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$CopyToThisLocation
    )
    Write-ScriptDebug("Function Enter: Copy-FullLogFullPathRecurse")
    Write-ScriptDebug("Passed: [string]LogPath: {0} | [string]CopyToThisLocation: {1}" -f $LogPath, $CopyToThisLocation)
    New-Folder -NewFolder $CopyToThisLocation -IncludeDisplayCreate $true
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
                Write-ScriptDebug("Not going to copy over this set of data due to size restrictions.")
                New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToThisLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -hasher $Script:ItemSizesHashed) | Out-Null
            }
        } else {
            Write-ScriptHost("No data at path '{0}'. Unable to copy this data." -f $LogPath)
            New-Item -Path ("{0}\NoDataDetected.txt" -f $CopyToThisLocation) -ItemType File -Value $LogPath | Out-Null
        }
    } else {
        Write-ScriptHost("No Folder at {0}. Unable to copy this data." -f $LogPath)
        New-Item -Path ("{0}\NoFolderDetected.txt" -f $CopyToThisLocation) -ItemType File -Value $LogPath | Out-Null
    }
    Write-ScriptDebug("Function Exit: Copy-FullLogFullPathRecurse")
}
