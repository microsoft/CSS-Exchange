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
function Copy-LogsBasedOnTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$CopyToThisLocation,
        [Parameter(Mandatory = $true)][bool]$IncludeSubDirectory,
        [switch]$CopyAll
    )
    begin {
        function NoFilesInLocation {
            param(
                [string]$SourceLocation,
                [string]$DestinationLocation,
                [string]$Value = "No data in the location",
                [string]$MarkerName = 'NoFilesDetected.txt'
            )
            $line = "No files were found in '$SourceLocation'."

            if (-not ($IncludeSubDirectory)) {
                Write-Host $line -ForegroundColor "Yellow"
            } else {
                Write-Verbose $line
            }

            $params = @{
                Path     = [System.IO.Path]::Combine($DestinationLocation, $MarkerName)
                ItemType = "File"
                Value    = "Location: $SourceLocation`r`n$Value"
                Force    = $true
            }
            New-Item @params | Out-Null
        }

        function CopyItemsFromDirectory {
            param(
                [object]$AllItems,
                [string]$CopyToLocation
            )

            if (@($AllItems).Count -gt 0) {
                if ($CopyAll) {
                    Copy-BulkItems -CopyToLocation $CopyToLocation -ItemsToCopyLocation @($AllItems.FullName)
                    return
                }
                $timeRangeFiles = $AllItems | Where-Object { $_.LastWriteTime -ge $copyFromDate -and $_.LastWriteTime -le $copyToDate }

                if ($null -eq $timeRangeFiles) {
                    Write-Verbose "no files found in the range. Getting the last file."
                    Copy-BulkItems -CopyToLocation $CopyToLocation -ItemsToCopyLocation $AllItems[0].FullName
                } else {
                    Write-Verbose "Found files within the time range."
                    $timeRangeFiles | ForEach-Object { Write-Verbose "$($_.FullName)" }
                    $copyItemPaths = $timeRangeFiles | ForEach-Object { $_.FullName }
                    Copy-BulkItems -CopyToLocation $CopyToLocation -ItemsToCopyLocation $copyItemPaths
                }
            }
        }

        Write-Verbose "Function Enter: $($MyInvocation.MyCommand)"
        Write-Verbose "LogPath: '$LogPath' | CopyToThisLocation: '$CopyToThisLocation'"
        New-Item -ItemType Directory -Path $CopyToThisLocation -Force | Out-Null
        if (-not $CopyAll) {
            $collectionTime = [DateTime]::Now
            $copyFromDate = $collectionTime - $PassedInfo.TimeSpan
            $copyToDate = $collectionTime - $PassedInfo.EndTimeSpan
            Write-Verbose "Copy From Date: $copyFromDate"
            Write-Verbose "Copy To Date: $copyToDate"
        }
    }
    process {
        try {
            $sourceRoot = Get-Item -LiteralPath $LogPath -ErrorAction Stop
            if (-not $sourceRoot.PSIsContainer) {
                throw "The log path is not a directory."
            }
        } catch [System.Management.Automation.ItemNotFoundException] {
            $markerName = 'NoFilesDetected.txt'
            if ($CopyAll) { $markerName = 'NoFolderDetected.txt' }
            NoFilesInLocation -SourceLocation $LogPath -DestinationLocation $CopyToThisLocation -Value "Path doesn't exist" -MarkerName $markerName
            return
        } catch {
            Write-Warning "Unable to inspect log directory '$LogPath': $($_.Exception.Message)"
            return
        }

        $sourcePrefix = $sourceRoot.FullName.TrimEnd('\') + '\'
        $destinationRoot = [System.IO.Path]::GetFullPath($CopyToThisLocation).TrimEnd('\') + '\'
        if ($destinationRoot.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "The collection destination '$CopyToThisLocation' is inside '$LogPath'; skipping recursive self-copy."
            return
        }

        $directories = New-Object 'System.Collections.Generic.Queue[System.IO.DirectoryInfo]'
        $directories.Enqueue($sourceRoot)
        $hasFiles = $false
        $enumerationFailed = $false
        while ($directories.Count -gt 0) {
            $directory = $directories.Dequeue()
            $relativePath = ''
            if ($directory.FullName -ne $sourceRoot.FullName) {
                $relativePath = $directory.FullName.Substring($sourcePrefix.Length)
            }
            $destination = [System.IO.Path]::Combine($CopyToThisLocation, $relativePath)
            try {
                $children = @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)
            } catch {
                $enumerationFailed = $true
                Write-Warning "Unable to enumerate log directory '$($directory.FullName)': $($_.Exception.Message)"
                continue
            }

            New-Item -Path $destination -ItemType Directory -Force | Out-Null
            $items = @($children | Where-Object { -not $_.PSIsContainer } | Sort-Object LastWriteTime -Descending)
            if ($items.Count -gt 0) {
                $hasFiles = $true
                CopyItemsFromDirectory -AllItems $items -CopyToLocation $destination
            } elseif (-not $CopyAll -and (-not $IncludeSubDirectory -or $children.Count -eq 0)) {
                NoFilesInLocation -SourceLocation $directory.FullName -DestinationLocation $destination
            }

            if ($IncludeSubDirectory) {
                foreach ($child in $children | Where-Object { $_.PSIsContainer }) {
                    if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                        $enumerationFailed = $true
                        Write-Warning "Skipping linked directory '$($child.FullName)' to avoid following a directory loop."
                    } else {
                        $directories.Enqueue($child)
                    }
                }
            }
        }

        if ($hasFiles) {
            Invoke-ZipFolder -Folder $CopyToThisLocation
        } elseif ($CopyAll -and -not $enumerationFailed) {
            NoFilesInLocation -SourceLocation $LogPath -DestinationLocation $CopyToThisLocation -MarkerName 'NoDataDetected.txt'
        }
    }
    end {
        Write-Verbose("Function Exit: $($MyInvocation.MyCommand)")
    }
}
