# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Copy-BulkItems.ps1
<#
    Copy Log Directory Based Off Time.
    The IncludeSubDirectory bool set to false should only be use if we don't want to include sub directories
    Otherwise, in each sub directory try to collect logs based off the TimeSpan.
    If there is a directory that doesn't contain logs within the TimeSpan,
    Collect the latest log or provide there is no logs in the directory
#>
Function Copy-LogsBasedOnTime {
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$CopyToThisLocation,
        [Parameter(Mandatory = $true)][bool]$IncludeSubDirectory
    )
    begin {
        Function NoFilesInLocation {
            param(
                [string]$Value = "No data in the location"
            )
            $line = "It doesn't look like you have any data in this location $LogPath."

            if (-not ($IncludeSubDirectory)) {
                Write-Host $line -ForegroundColor "Yellow"
            } else {
                Write-Verbose $line
            }

            $params = @{
                Path     = "$CopyToThisLocation\NoFilesDetected.txt"
                ItemType = "File"
                Value    = $( "Location: $LogPath`r`n$Value" )
            }
            New-Item @params | Out-Null
        }

        Function CopyItemsFromDirectory {
            param(
                [object]$AllItems,
                [string]$CopyToLocation
            )

            if ($null -eq $AllItems) {
                Write-Verbose "No items were found in the directory."
                NoFilesInLocation
            } else {
                $timeRangeFiles = $AllItems | Where-Object { $_.LastWriteTime -ge $copyFromDate }

                if ($null -eq $timeRangeFiles) {
                    Write-Verbose "no files found in the range. Getting the last file."
                    Copy-BulkItems -CopyToLocation $CopyToLocation -ItemsToCopyLocation $AllItems[0].FullName
                } else {
                    Write-Verbose "Found files within the time range."
                    $timeRangeFiles | ForEach-Object { Write-Verbose "$($_.FullName)" }
                    $copyItemPaths = $timeRangeFiles | ForEach-Object { $_.FullName }
                    Copy-BulkItems -CopyToLocation $CopyToLocation -ItemsToCopyLocation $copyItemPaths
                }
                Invoke-ZipFolder -Folder $CopyToLocation
            }
        }

        Write-Verbose "Function Enter: $($MyInvocation.MyCommand)"
        Write-Verbose "LogPath: '$LogPath' | CopyToThisLocation: '$CopyToThisLocation'"
        $copyFromDate = [DateTime]::Now - $PassedInfo.TimeSpan

        if (-not (Test-Path $LogPath)) {
            # If the directory isn't there, provide that
            Write-Verbose "$LogPath doesn't exist"
            NoFilesInLocation "Path doesn't exist"
            return
        }
    }
    process {
        New-Item -ItemType Directory -Path $CopyToThisLocation -Force | Out-Null
        Write-Verbose "Copy From Date: $copyFromDate"

        if ($IncludeSubDirectory) {
            $getChildItem = Get-ChildItem -Path $LogPath -Recurse
            [array]$directories = Get-Item -Path $LogPath
            $directories += @($getChildItem |
                    Where-Object {
                        $_.Mode -like "d*"
                    })

            # Map and find all the items per directory
            foreach ($directory in $directories) {

                Write-Verbose "Working on finding items for directory $($directory.FullName)"
                if ($directory.FullName -eq $LogPath) {
                    $newCopyToThisLocation = $CopyToThisLocation
                } else {
                    $newCopyToThisLocation = "$CopyToThisLocation\$($directory.Name)"
                    New-Item -ItemType Directory -Path $newCopyToThisLocation -Force | Out-Null
                }
                # all the items that match this directory. Don't need to worry about directories because DirectoryName doesn't exist there.
                $items = $getChildItem | Where-Object { $_.DirectoryName -eq $directory.FullName } | Sort-Object LastWriteTime -Descending
                CopyItemsFromDirectory -AllItems $items -CopyToLocation $newCopyToThisLocation
            }
        } else {
            $getChildItem = Get-ChildItem -Path $LogPath |
                Sort-Object LastWriteTime -Descending |
                Where-Object { $_.Mode -notlike "d*" }

            CopyItemsFromDirectory -AllItems $getChildItem -CopyToLocation $CopyToThisLocation
        }
    }
    end {
        Write-Verbose("Function Exit: $($MyInvocation.MyCommand)")
    }
}
