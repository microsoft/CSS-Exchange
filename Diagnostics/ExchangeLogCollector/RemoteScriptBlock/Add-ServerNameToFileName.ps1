# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Add-ServerNameToFileName {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath
    )
    Write-Verbose("Calling: Add-ServerNameToFileName")
    Write-Verbose("Passed: [string]FilePath: {0}" -f $FilePath)
    $fileName = "{0}_{1}" -f $env:COMPUTERNAME, ($name = $FilePath.Substring($FilePath.LastIndexOf("\") + 1))
    $filePathWithServerName = $FilePath.Replace($name, $fileName)
    Write-Verbose("Returned: {0}" -f $filePathWithServerName)
    return $filePathWithServerName
}
