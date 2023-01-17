# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Compress-Folder {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 1)][string]$Folder,
        [Parameter(Position = 2)][bool]$IncludeMonthDay = $false,
        [Parameter(Position = 3)][bool]$IncludeDisplayZipping = $true,
        [Parameter(Position = 4)][bool]$ReturnCompressedLocation = $false
    )

    $Folder = $Folder.TrimEnd("\")
    $compressedLocation = [string]::Empty
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "Passed - [string]Folder: $Folder | [bool]IncludeDisplayZipping: $IncludeDisplayZipping | [bool]ReturnCompressedLocation: $ReturnCompressedLocation"

    if (-not (Test-Path $Folder)) {
        Write-Host "Failed to find the folder $Folder"
        return $null
    }

    $successful = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Location -like "*System.IO.Compression.Filesystem*" }).Count -ge 1
    Write-Verbose "Found IO Compression loaded: $successful"

    if ($successful -eq $false) {
        # Try to load the IO Compression
        try {
            Add-Type -AssemblyName System.IO.Compression.Filesystem -ErrorAction Stop
            Write-Verbose "Loaded .NET Compression Assembly."
        } catch {
            Write-Host "Failed to load .NET Compression assembly. Unable to compress up the data."
            return $null
        }
    }

    if ($IncludeMonthDay) {
        $zipFolderNoEXT = "{0}-{1}" -f $Folder, (Get-Date -Format Md)
    } else {
        $zipFolderNoEXT = $Folder
    }
    Write-Verbose "[string]zipFolderNoEXT: $zipFolderNoEXT"
    $zipFolder = "{0}.zip" -f $zipFolderNoEXT
    [int]$i = 1
    while (Test-Path $zipFolder) {
        $zipFolder = "{0}-{1}.zip" -f $zipFolderNoEXT, $i
        $i++
    }
    Write-Verbose "Using Zip Folder Path: $zipFolder"

    if ($IncludeDisplayZipping) {
        Write-Host "Compressing Folder $Folder"
    }
    $sizeBytesBefore = 0
    Get-ChildItem $Folder -Recurse |
        Where-Object { -not ($_.Mode.StartsWith("d-")) } |
        ForEach-Object { $sizeBytesBefore += $_.Length }

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    [System.IO.Compression.ZipFile]::CreateFromDirectory($Folder, $zipFolder)
    $timer.Stop()
    $sizeBytesAfter = (Get-Item $zipFolder).Length
    Write-Verbose ("Compressing directory size of {0} MB down to the size of {1} MB took {2} seconds." -f ($sizeBytesBefore / 1MB), ($sizeBytesAfter / 1MB), $timer.Elapsed.TotalSeconds)

    if ((Test-Path -Path $zipFolder)) {
        Write-Verbose "Compress successful, removing folder."
        Remove-Item $Folder -Force -Recurse
    }

    if ($ReturnCompressedLocation) {
        $compressedLocation = $zipFolder
    }

    Write-Verbose "Returning: $compressedLocation"
    return $compressedLocation
}
