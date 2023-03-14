# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1

<#
    This function can be used to extract a zip or nupkg file to a specified folder.
    By default, the function will extract the archive to the same folder as the script.
#>

function Invoke-ExtractArchive {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]

    param(
        [Parameter(Mandatory = $false)]
        [string]$TargetFolder = $PSScriptRoot,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("(.*?)\.(zip|nupkg)$")]
        [string]$CompressedFilePath,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $successfullyUnzipped = $false
    }
    process {
        if ((Test-Path $TargetFolder) -eq $false) {
            try {
                Write-Verbose "Path: $TargetFolder doesn't exist, creating it"
                New-Item -Path $TargetFolder -ItemType Directory -ErrorAction Stop
            } catch {
                Write-Verbose "Unable to create target folder: $TargetFolder"
                Invoke-CatchActionError $CatchActionFunction
                return
            }
        }

        if ((Test-Path $CompressedFilePath) -eq $false) {
            Write-Verbose "Failed to find the archive: $CompressedFilePath"
            Invoke-CatchActionError $CatchActionFunction
            return
        }

        try {
            Add-Type -AssemblyName "System.IO.Compression.Filesystem" -ErrorAction Stop
            Write-Verbose "Loaded .NET Compression Assembly"
        } catch {
            Write-Verbose "Failed to load .NET Compression Assembly"
            Invoke-CatchActionError $CatchActionFunction
            return
        }

        try {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($CompressedFilePath, $TargetFolder)
            $successfullyUnzipped = $true
        } catch {
            Write-Verbose "Something went wrong while extracting the archive"
            Invoke-CatchActionError $CatchActionFunction
            return
        }
    }
    end {
        return [PSCustomObject]@{
            DecompressionSuccessful     = $successfullyUnzipped
            FullPathToDecompressedFiles = $TargetFolder
        }
    }
}
