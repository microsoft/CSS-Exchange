# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-StringDataForNotEnoughFreeSpace.ps1
. $PSScriptRoot\..\Test-FreeSpace.ps1
. $PSScriptRoot\..\LogCopyTaskActionFunctions.ps1
function Copy-BulkItems {
    [CmdletBinding()]
    param(
        [string]$CopyToLocation,
        [Array]$ItemsToCopyLocation
    )

    New-Item -ItemType Directory -Path $CopyToLocation -Force | Out-Null

    foreach ($item in $ItemsToCopyLocation) {
        $copyStarted = $false
        try {
            if (-not (Test-FreeSpace -FilePaths @($item) -CheckOnly)) {
                Write-Host "Not enough free space to copy over this data set."
                New-Item -Path ("{0}\NotEnoughFreeSpace.txt" -f $CopyToLocation) -ItemType File -Value (Get-StringDataForNotEnoughFreeSpaceFile -FileSizes $Script:ItemSizesHashed) -Force | Out-Null
                return
            }

            $source = Get-Item -LiteralPath $item -ErrorAction Stop
            $destination = [System.IO.Path]::Combine($CopyToLocation, $source.Name)
            if (Test-Path -LiteralPath $destination -ErrorAction Stop) {
                $sourceId = Get-LogSourceIdentifier -Path (Split-Path -Path $source.FullName -Parent)
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($source.Name)
                $extension = [System.IO.Path]::GetExtension($source.Name)
                $nameLimit = [Math]::Min(255, 259 - [System.IO.Path]::GetFullPath($CopyToLocation).TrimEnd('\').Length - 1)
                $baseNameLimit = $nameLimit - $sourceId.Length - $extension.Length - 13
                if ($baseNameLimit -lt 1) {
                    throw 'The collection destination is too long for a source-qualified filename. Use a shorter output path.'
                }
                if ($baseName.Length -gt $baseNameLimit) {
                    $baseName = $baseName.Substring(0, $baseNameLimit)
                }
                $destination = [System.IO.Path]::Combine($CopyToLocation, "${baseName}__${sourceId}$extension")
                $duplicate = 2
                while (Test-Path -LiteralPath $destination -ErrorAction Stop) {
                    $destination = [System.IO.Path]::Combine($CopyToLocation, "${baseName}__${sourceId}_${duplicate}$extension")
                    $duplicate++
                }
            }

            Write-Verbose "Copying '$($source.FullName)' to '$destination'."
            $copyStarted = $true
            $copiedItem = Copy-Item -LiteralPath $source.FullName -Destination $destination -PassThru -ErrorAction Stop
            $Script:TotalBytesSizeCopied += $copiedItem.Length
            $Script:FreeSpaceMinusCopiedAndCompressedGB -= $copiedItem.Length / 1GB
        } catch {
            Write-Warning "Failed to copy '$item' to '$CopyToLocation': $($_.Exception.Message)"
            if ($copyStarted) {
                try {
                    if (Test-Path -LiteralPath $destination -ErrorAction Stop) {
                        Remove-Item -LiteralPath $destination -Force -ErrorAction Stop
                    }
                } catch {
                    $Script:FreeSpaceMinusCopiedAndCompressedGB = 0
                    Write-Warning "Unable to remove incomplete copy '$destination'. Stopping this batch; free space must be checked again: $($_.Exception.Message)"
                    return
                }
            }
        }
    }
}
