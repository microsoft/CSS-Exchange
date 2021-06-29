# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
    New-Folder -NewFolder $copyTo -IncludeDisplayCreate $true
    if (Test-Path $strDirectory) {
        $wildExt = "*" + $objLogman.Ext
        $filterDate = $objLogman.StartDate

        $date = (Get-Date).AddDays(0 - $PassedInfo.DaysWorth)
        $copyFromDate = "$($Date.Month)/$($Date.Day)/$($Date.Year)"

        Write-ScriptDebug("Copy From Date: {0}" -f $filterDate)

        if ([DateTime]$filterDate -lt [DateTime]$copyFromDate) {
            $filterDate = $copyFromDate
            Write-ScriptDebug("Updating Copy From Date to: '{0}'" -f $filterDate)
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
            Write-ScriptHost -WriteString ("Failed to find any files in the directory: '{0}' that was greater than or equal to this time: {1}" -f $strDirectory, $filterDate) -ForegroundColor "Yellow"
            Write-ScriptHost -WriteString  ("Going to try to see if there are any files in this directory for you..." ) -NoNewline $true
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
                Write-ScriptHost -WriteString ("Failed to find any files in the directory: '{0}'" -f $strDirectory) -ForegroundColor "Yellow"
                $tempFile = $copyTo + "\NoFiles.txt"
                New-Item $tempFile -ItemType File -Value $strDirectory | Out-Null
            }
        }
    } else {
        Write-ScriptHost -WriteString  ("Doesn't look like this Directory is valid. {0}" -f $strDirectory) -ForegroundColor "Yellow"
        $tempFile = $copyTo + "\NotValidDirectory.txt"
        New-Item $tempFile -ItemType File -Value $strDirectory | Out-Null
    }
}
