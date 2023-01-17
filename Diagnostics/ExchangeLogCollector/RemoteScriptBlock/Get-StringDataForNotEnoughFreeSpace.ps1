# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-StringDataForNotEnoughFreeSpaceFile {
    param(
        [Parameter(Mandatory = $true)][Hashtable]$FileSizes
    )
    Write-Verbose("Calling: Get-StringDataForNotEnoughFreeSpaceFile")
    $reader = [string]::Empty
    $totalSizeMB = 0
    foreach ($key in $FileSizes.Keys) {
        $reader += ("File: {0} | Size: {1} MB`r`n" -f $key, ($keyValue = $FileSizes[$key]).ToString())
        $totalSizeMB += $keyValue
    }
    $reader += ("`r`nTotal Size Attempted To Copy Over: {0} MB`r`nCurrent Available Free Space: {1} GB" -f $totalSizeMB, $Script:CurrentFreeSpaceGB)
    return $reader
}
