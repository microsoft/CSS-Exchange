# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/ComputerInformation/Get-ClusterNodeFileVersions/Get-ClusterNodeFileVersions.ps1
#v21.01.22.2212
Function Get-ClusterNodeFileVersions {
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
