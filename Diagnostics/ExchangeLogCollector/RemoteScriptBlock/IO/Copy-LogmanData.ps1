# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Copy-BulkItems.ps1
Function Copy-LogmanData {
    param(
        [Parameter(Mandatory = $true)]$ObjLogman
    )

    if ($PassedInfo.ExperfwizLogmanName -contains $ObjLogman.LogmanName) {
        $folderName = "ExPerfWiz_Data"
    } elseif ($PassedInfo.ExmonLogmanName -contains $ObjLogman.LogmanName) {
        $folderName = "ExmonTrace_Data"
    } else {
        $folderName = "Logman_Data"
    }

    $strDirectory = $ObjLogman.RootPath
    $copyTo = $Script:RootCopyToDirectory + "\" + $folderName
    New-Item -ItemType Directory -Path $copyTo -Force | Out-Null
    if (Test-Path $strDirectory) {
        $wildExt = "*" + $objLogman.Ext
        $filterDate = $objLogman.StartDate

        $copyFromDate = [DateTime]::Now - $PassedInfo.TimeSpan
        Write-Verbose("Copy From Date: {0}" -f $filterDate)

        if ([DateTime]$filterDate -lt [DateTime]$copyFromDate) {
            $filterDate = $copyFromDate
            Write-Verbose("Updating Copy From Date to: '{0}'" -f $filterDate)
        }

        $childItems = Get-ChildItem $strDirectory -Recurse | Where-Object { ($_.Name -like $wildExt) -and ($_.CreationTime -ge $filterDate) }
        $items = @()
        foreach ($childItem in $childItems) {
            $items += $childItem.VersionInfo.FileName
        }
        if ($null -ne $items) {
            Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items
            Invoke-ZipFolder -Folder $copyTo
        } else {
            Write-Host "Failed to find any files in the directory: '$strDirectory' that was greater than or equal to this time: $filterDate" -ForegroundColor "Yellow"
            Write-Host "Going to try to see if there are any files in this directory for you..." -NoNewline
            $files = Get-ChildItem $strDirectory -Recurse | Where-Object { $_.Name -like $wildExt }
            if ($null -ne $files) {
                #only want to get latest data
                $newestFilesTime = ($files | Sort-Object CreationTime -Descending)[0].CreationTime.AddDays(-1)
                $newestFiles = $files | Where-Object { $_.CreationTime -ge $newestFilesTime }

                $items = @()
                foreach ($newestFile in $newestFiles) {
                    $items += $newestFile.VersionInfo.FileName
                }

                if ($null -ne $items) {
                    Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items
                    Invoke-ZipFolder -Folder $copyTo
                }
            } else {
                Write-Host "Failed to find any files in the directory: '$strDirectory'" -ForegroundColor "Yellow"
                $tempFile = $copyTo + "\NoFiles.txt"
                New-Item $tempFile -ItemType File -Value $strDirectory | Out-Null
            }
        }
    } else {
        Write-Host "Doesn't look like this Directory is valid. $strDirectory" -ForegroundColor "Yellow"
        $tempFile = $copyTo + "\NotValidDirectory.txt"
        New-Item $tempFile -ItemType File -Value $strDirectory | Out-Null
    }
}
