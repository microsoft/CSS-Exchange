# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$CuRoot,
    [string]$CopyToRoot
)


$msiFromCU = Get-ChildItem $CuRoot -Recurse |
    Where-Object { $_.Name.ToLower().EndsWith(".msi") }


foreach ($msi in $msiFromCU) {

    $copyTo = $msi.Directory.FullName.Replace($CuRoot, $CopyToRoot)

    if (!(Test-Path $copyTo)) {
        New-Item $copyTo -ItemType Directory | Out-Null
    }

    Copy-Item $msi.FullName $copyTo
}
