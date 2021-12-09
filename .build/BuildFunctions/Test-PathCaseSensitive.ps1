# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-PathCaseSensitive {
    [CmdletBinding()]
    [OutputType("System.Boolean")]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    if (-not (Test-Path $Path)) {
        Write-Warning "Path does not exist: $Path"
        return $false
    }

    $directoryName = [IO.Path]::GetDirectoryName($Path)
    $fileName = [IO.Path]::GetFileName($Path)
    $childItem = Get-ChildItem $directoryName -Filter $fileName
    $actualPath = $childItem.FullName
    if ($actualPath -ceq $Path) {
        return $true
    }

    Write-Warning "Provided path: $Path"
    Write-Warning "Actual path: $actualPath"
    Write-Warning "Path case is not correct."
    return $false
}
