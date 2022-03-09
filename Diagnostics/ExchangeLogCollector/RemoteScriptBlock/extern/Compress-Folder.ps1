# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Compress-Folder {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 1)][string]$Folder,
        [Parameter(Position = 2)][bool]$IncludeMonthDay = $false,
        [Parameter(Position = 3)][bool]$IncludeDisplayZipping = $true,
        [Parameter(Position = 4)][bool]$ReturnCompressedLocation = $false
    )

    Function Get-DirectorySize {
        param(
            [Parameter(Mandatory = $true)][string]$Directory,
            [Parameter(Mandatory = $false)][bool]$IsCompressed = $false
        )
        $itemSize = 0
        if ($IsCompressed) {
            $itemSize = (Get-Item $Directory).Length
        } else {
            $childItems = Get-ChildItem $Directory -Recurse | Where-Object { -not($_.Mode.StartsWith("d-")) }
            foreach ($item in $childItems) {
                $itemSize += $item.Length
            }
        }
        return $itemSize
    }

    if ($Folder.EndsWith("\")) {
        $Folder = $Folder.TrimEnd("\")
    }
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "Passed - [string]Folder: $Folder | [bool]IncludeDisplayZipping: $IncludeDisplayZipping | [bool]ReturnCompressedLocation: $ReturnCompressedLocation"

    $compressedLocation = [string]::Empty
    if (Test-Path $Folder) {

        $assemblies = [Appdomain]::CurrentDomain.GetAssemblies()
        $successful = $false
        foreach ($assembly in $assemblies) {
            if ($assembly.Location -like "*System.IO.Compression.Filesystem*") {
                $successful = $true
                break
            }
        }

        Write-Verbose "Found IO Compression loaded: $successful"

        if ($successful -eq $false) {
            # Try to load the IO Compression
            $loadedIOCompression = $false
            try {
                Add-Type -AssemblyName System.IO.Compression.Filesystem -ErrorAction Stop
                $loadedIOCompression = $true
            } catch {
                Write-Host "Failed to load .NET Compression assembly. Unable to compress up the data."
            }

            if ($loadedIOCompression -eq $false) {
                Write-Verbose "Unable to compress folder $Folder"
                Write-Verbose "Unable to enable IO compression on this system"
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
        if (Test-Path $zipFolder) {
            [int]$i = 1
            do {
                $zipFolder = "{0}-{1}.zip" -f $zipFolderNoEXT, $i
                $i++
            }while (Test-Path $zipFolder)
        }
        Write-Verbose "Using Zip Folder Path: $zipFolder"

        if ($IncludeDisplayZipping) {
            Write-Host "Compressing Folder $Folder"
        }
        $sizeBytesBefore = Get-DirectorySize -Directory $Folder
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Folder, $zipFolder)
        $timer.Stop()
        $sizeBytesAfter = Get-DirectorySize -Directory $zipFolder -IsCompressed $true
        Write-Verbose ("Compressing directory size of {0} MB down to the size of {1} MB took {2} seconds." -f ($sizeBytesBefore / 1MB), ($sizeBytesAfter / 1MB), $timer.Elapsed.TotalSeconds)
        if ((Test-Path -Path $zipFolder)) {
            Write-Verbose "Compress successful, removing folder."
            Remove-Item $Folder -Force -Recurse
        }
        if ($ReturnCompressedLocation) {
            $compressedLocation = $zipFolder
        }
    } else {
        Write-Host "Failed to find the folder $Folder"
    }

    Write-Verbose "Returning: $compressedLocation"
    return $compressedLocation
}
