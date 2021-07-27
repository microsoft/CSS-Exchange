# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-ItemsSize {
    param(
        [Parameter(Mandatory = $true)][array]$FilePaths
    )
    Write-ScriptDebug("Calling: Get-ItemsSize")
    $totalSize = 0
    $hashSizes = @{}
    foreach ($file in $FilePaths) {
        if (Test-Path $file) {
            $totalSize += ($fileSize = (Get-Item $file).Length)
            Write-ScriptDebug("File: {0} | Size: {1} MB" -f $file, ($fileSizeMB = $fileSize / 1MB))
            $hashSizes.Add($file, ("{0}" -f $fileSizeMB))
        } else {
            Write-ScriptDebug("File no longer exists: {0}" -f $file)
        }
    }
    Set-Variable -Name ItemSizesHashed -Value $hashSizes -Scope Script
    Write-ScriptDebug("Returning: {0}" -f $totalSize)
    return $totalSize
}
