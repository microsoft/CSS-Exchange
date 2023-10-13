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

. $PSScriptRoot\Load-Module.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckContainsCurlyQuotes.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckFileHasNewlineAtEndOfFile.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckMarkdownFileHasNoBOM.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckMultipleEmptyLines.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFileHasBOM.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFileHasComplianceHeader.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckKeywordCasing.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFormat.ps1
. $PSScriptRoot\HelpFunctions\Get-CommitFilesOnBranch.ps1

if (-not (Load-Module -Name PSScriptAnalyzer -MinimumVersion "1.20")) {
    throw "PSScriptAnalyzer module could not be loaded"
}

if (-not (Load-Module -Name EncodingAnalyzer)) {
    throw "EncodingAnalyzer module could not be loaded"
}

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

$errorCount = 0

foreach ($fileInfo in $filesToCheck) {
    $errorCount += (CheckFileHasNewlineAtEndOfFile $fileInfo $Save) ? 1 : 0
    $errorCount += (CheckMarkdownFileHasNoBOM $fileInfo $Save) ? 1 : 0
    $errorCount += (CheckScriptFileHasBOM $fileInfo $Save) ? 1 : 0
    $errorCount += (CheckScriptFileHasComplianceHeader $fileInfo $Save) ? 1 : 0
    $errorCount += (CheckKeywordCasing $fileInfo $Save) ? 1 : 0
    $errorCount += (CheckMultipleEmptyLines $fileInfo $Save) ?  1 : 0
    $errorCount += (CheckContainsCurlyQuotes $fileInfo $Save) ? 1 : 0

    # This one is tricky. It returns $true or $false like the others, but in the case
    # of an error, we also want to get the diff output. Piping to Out-Host from within
    # the function loses the colorization, as does redirection. I can't find any way
    # for the function to output the diff while preserving the color. So we unfortunately
    # have to handle the output here.
    $results = @(CheckScriptFormat $fileInfo $Save)
    if ($results.Length -gt 0 -and $results[0] -eq $true) {
        $errorCount++
        if ($results.Length -gt 2) {
            git -c color.status=always diff ($($results[1]) | git hash-object -w --stdin) ($($results[2]) | git hash-object -w --stdin)
        }
    }
}

$maxRetries = 5

foreach ($fileInfo in $filesToCheck) {
    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $params = @{
                Path                = ($fileInfo.FullName)
                Settings            = "$repoRoot\PSScriptAnalyzerSettings.psd1"
                CustomRulePath      = "$repoRoot\.build\CodeFormatterChecks\CustomRules.psm1"
                IncludeDefaultRules = $true
            }
            $analyzerResults = Invoke-ScriptAnalyzer @params
            if ($null -ne $analyzerResults) {
                $errorCount++
                $analyzerResults | Format-Table -AutoSize
            }
            break
        } catch {
            Write-Warning "Invoke-ScriptAnalyer failed on $($fileInfo.FullName). Error:"
            $_.Exception | Format-List | Out-Host
            Write-Warning "Retrying in 5 seconds."
            Start-Sleep -Seconds 5
        }
    }

    if ($i -eq $maxRetries) {
        throw "Invoke-ScriptAnalyzer failed $maxRetries times. Giving up."
    }
}

if ($errorCount -gt 0) {
    throw "Failed to match formatting requirements"
}
