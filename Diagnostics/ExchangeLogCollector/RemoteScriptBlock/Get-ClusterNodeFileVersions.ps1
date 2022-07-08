# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ClusterNodeFileVersions {
    [CmdletBinding()]
    param(
        [string]$ClusterDirectory = "C:\Windows\Cluster"
    )

    $fileHashes = @{}

    Get-ChildItem $ClusterDirectory |
        Where-Object {
            $_.Name.EndsWith(".dll") -or
            $_.Name.EndsWith(".exe")
        } |
        ForEach-Object {
            $item = [PSCustomObject]@{
                FileName        = $_.Name
                FileMajorPart   = $_.VersionInfo.FileMajorPart
                FileMinorPart   = $_.VersionInfo.FileMinorPart
                FileBuildPart   = $_.VersionInfo.FileBuildPart
                FilePrivatePart = $_.VersionInfo.FilePrivatePart
                ProductVersion  = $_.VersionInfo.ProductVersion
                LastWriteTime   = $_.LastWriteTimeUtc
            }
            $fileHashes.Add($_.Name, $item)
        }

    return [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Files        = $fileHashes
    }
}
