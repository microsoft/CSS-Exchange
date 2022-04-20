# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = '$filesFailed is being used.')]
[CmdletBinding()]
param(
    [Switch]
    $Save
)

#Requires -Version 7

. $PSScriptRoot\Load-Module.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckFileHasNewlineAtEndOfFile.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckMarkdownFileHasNoBOM.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFileHasBOM.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFileHasComplianceHeader.ps1
. $PSScriptRoot\CodeFormatterChecks\CheckScriptFormat.ps1

if (-not (Load-Module -Name PSScriptAnalyzer -MinimumVersion "1.20")) {
    throw "PSScriptAnalyzer module could not be loaded"
}

if (-not (Load-Module -Name EncodingAnalyzer)) {
    throw "EncodingAnalyzer module could not be loaded"
}

$repoRoot = Get-Item "$PSScriptRoot\.."

$filesToCheck = Get-ChildItem -Path $repoRoot -Directory | Where-Object {
    $_.Name -ne "dist" } | ForEach-Object {
    Get-ChildItem -Path $_.FullName -Include "*.ps1", "*.psm1", "*.md" -Recurse
}

$errorCount = 0

foreach ($fileInfo in $filesToCheck) {
    $errorCount += (CheckFileHasNewlineAtEndOfFile $fileInfo $Save) ? 1 : 0
    $errorCount += (CheckMarkdownFileHasNoBOM $fileInfo $Save) ? 1 : 0
    $errorCount += (CheckScriptFileHasBOM $fileInfo $Save) ? 1 : 0
    $errorCount += (CheckScriptFileHasComplianceHeader $fileInfo $Save) ? 1 : 0

    # This one is tricky. It returns $true or $false like the others, but in the case
    # of an error, we also want to get the diff output. Piping to Out-Host from within
    # the function loses the colorization, as does redirection. I can't find any way
    # for the function to output the diff while preserving the color. So we unfortunately
    # have to handle the output here.
    $results = @(CheckScriptFormat $fileInfo $Save)
    if ($results[0]) {
        git -c color.status=always diff ($($results[1]) | git hash-object -w --stdin) ($($results[2]) | git hash-object -w --stdin)
    }
}

$maxRetries = 5

foreach ($fileInfo in $filesToCheck) {
    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $analyzerResults = Invoke-ScriptAnalyzer -Path $FileInfo.FullName -Settings $repoRoot\PSScriptAnalyzerSettings.psd1 -ErrorAction Stop
            if ($null -ne $analyzerResults) {
                $filesFailed = $true
                $analyzerResults | Format-Table -AutoSize
            }
            break
        } catch {
            Write-Warning "Invoke-ScriptAnalyer failed. Error:"
            $_.Exception | Format-List | Out-Host
            Write-Warning "Retrying in 5 seconds."
            Start-Sleep -Seconds 5
        }
    }
}

if ($i -eq $maxRetries) {
    $errorCount += 1
}

if ($errorCount -gt 0) {
    throw "Failed to match formatting requirements"
}
