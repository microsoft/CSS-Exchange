# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[CmdletBinding()]
param(
    [Switch]
    $Save,

    [string]
    $Branch
)

#Requires -Version 7

Set-StrictMode -Version Latest

. $PSScriptRoot\Invoke-CodeFormatterOnFiles.ps1
. $PSScriptRoot\HelpFunctions\Get-CommitFilesOnBranch.ps1

$repoRoot = Get-Item "$PSScriptRoot\.."

$optimizeCodeFormatter = [string]::IsNullOrEmpty($Branch) -eq $false
# Get only the files that are changed in this PR
if ($optimizeCodeFormatter) {

    $filesFullPath = Get-CommitFilesOnBranch -Branch $Branch

    # Only optimize CodeFormatter IF any CodeFormatter related files were not modified or PSScriptAnalyzerSettings.psd1
    $optimizeCodeFormatter = $null -eq ($filesFullPath | Where-Object { $_ -like "*.build\CodeFormatter*" -or $_ -like "*\PSScriptAnalyzerSettings.psd1" })
    Write-Host "Optimize Code: $optimizeCodeFormatter"
}

if ($optimizeCodeFormatter) {
    $filesToCheck = $filesFullPath | Get-ChildItem -Include "*.ps1", "*.psm1", "*.md"

    if ($null -eq $filesToCheck) {
        Write-Host "No scripts or md files were modified. Skipping over check."
        return
    }
    Write-Host "Files that we are looking at for code formatting:"
    $filesToCheck.FullName | Write-Host
} else {
    $filesToCheck = Get-ChildItem -Path $repoRoot -Directory | Where-Object {
        $_.Name -ne "dist" } | ForEach-Object {
        Get-ChildItem -Path $_.FullName -Include "*.ps1", "*.psm1", "*.md" -Recurse
    }
}

$errorCount = Invoke-CodeFormatterOnFiles -FilePaths ($filesToCheck | ForEach-Object { $_.FullName }) -Save:$Save

if ($errorCount -gt 0) {
    throw "Failed to match formatting requirements"
}
