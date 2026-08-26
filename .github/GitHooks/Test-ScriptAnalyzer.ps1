# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs PSScriptAnalyzer and CodeFormatter checks on staged PowerShell files.
.DESCRIPTION
    Blocks commits with PSScriptAnalyzer violations and CodeFormatter issues using
    the repository's PSScriptAnalyzerSettings.psd1, CustomRules.psm1, and
    CodeFormatterChecks to match the CI pipeline.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Files
)

# cspell:ignore toplevel
$repoRoot = git rev-parse --show-toplevel

if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($repoRoot)) {
    Write-Host "  Error: Unable to determine repository root." -ForegroundColor Red
    return 1
}

$settingsPath = Join-Path -Path $repoRoot -ChildPath "PSScriptAnalyzerSettings.psd1"
$customRulesPath = Join-Path -Path (Join-Path -Path (Join-Path -Path $repoRoot -ChildPath ".build") -ChildPath "CodeFormatterChecks") -ChildPath "CustomRules.psm1"
$codeFormatterChecksPath = Join-Path -Path (Join-Path -Path $repoRoot -ChildPath ".build") -ChildPath "CodeFormatterChecks"

# Dot-source CodeFormatter check functions
. (Join-Path -Path $codeFormatterChecksPath -ChildPath "CheckContainsCurlyQuotes.ps1")
. (Join-Path -Path $codeFormatterChecksPath -ChildPath "CheckFileHasNewlineAtEndOfFile.ps1")
. (Join-Path -Path $codeFormatterChecksPath -ChildPath "CheckMultipleEmptyLines.ps1")
. (Join-Path -Path $codeFormatterChecksPath -ChildPath "CheckScriptFileHasBOM.ps1")
. (Join-Path -Path $codeFormatterChecksPath -ChildPath "CheckScriptFileHasComplianceHeader.ps1")
. (Join-Path -Path $codeFormatterChecksPath -ChildPath "CheckScriptFormat.ps1")
. (Join-Path -Path $codeFormatterChecksPath -ChildPath "CheckTokenTypeCasing.ps1")

# Check if PSScriptAnalyzer >= 1.24 is available (matches .build/CodeFormatter.ps1)
$module = Get-Module -ListAvailable -Name PSScriptAnalyzer |
    Where-Object { $_.Version -ge [version]"1.24" } |
    Select-Object -First 1

if ($null -eq $module) {
    Write-Host "  SKIP: PSScriptAnalyzer >= 1.24 not installed." -ForegroundColor Yellow
    return 0
}

Import-Module PSScriptAnalyzer -MinimumVersion "1.24" -ErrorAction Stop

# Check if EncodingAnalyzer is available for BOM checks
$hasEncodingAnalyzer = $null -ne (Get-Module -ListAvailable -Name EncodingAnalyzer | Select-Object -First 1)
if ($hasEncodingAnalyzer) {
    Import-Module EncodingAnalyzer -ErrorAction SilentlyContinue
} else {
    Write-Host "  NOTE: EncodingAnalyzer not installed - BOM checks will be skipped." -ForegroundColor Yellow
}

$hasViolations = $false

foreach ($file in $Files) {
    if (-not (Test-Path $file)) { continue }

    $fileInfo = Get-Item -Path $file

    # Run CodeFormatter checks (report only, no auto-fix)
    if (CheckFileHasNewlineAtEndOfFile $fileInfo $false) { $hasViolations = $true }
    if (CheckScriptFileHasComplianceHeader $fileInfo $false) { $hasViolations = $true }
    if (CheckTokenTypeCasing $fileInfo $false "Keyword") { $hasViolations = $true }
    if (CheckTokenTypeCasing $fileInfo $false "Operator") { $hasViolations = $true }
    if (CheckMultipleEmptyLines $fileInfo $false) { $hasViolations = $true }
    if (CheckContainsCurlyQuotes $fileInfo $false) { $hasViolations = $true }

    if ($hasEncodingAnalyzer) {
        if (CheckScriptFileHasBOM $fileInfo $false) { $hasViolations = $true }
    }

    $formatResults = @(CheckScriptFormat $fileInfo $false)
    if ($formatResults.Length -gt 0 -and $formatResults[0] -eq $true) {
        $hasViolations = $true
    }

    # Run PSScriptAnalyzer with repo settings and custom rules
    $params = @{
        Path                = $file
        Severity            = @('ParseError', 'Error', 'Warning')
        Settings            = $settingsPath
        CustomRulePath      = $customRulesPath
        IncludeDefaultRules = $true
    }

    $results = Invoke-ScriptAnalyzer @params

    if ($null -ne $results -and $results.Count -gt 0) {
        $hasViolations = $true
        foreach ($r in $results) {
            Write-Host "  $($r.Severity): $file`:$($r.Line) - [$($r.RuleName)] $($r.Message)" -ForegroundColor $(if ($r.Severity -in @('Error', 'ParseError')) { 'Red' } else { 'Yellow' })
        }
    }
}

if ($hasViolations) {
    Write-Host "`nCode quality checks found violations. Fix before committing." -ForegroundColor Red
    return 1
} else {
    Write-Host "  Code quality checks: no issues found." -ForegroundColor Green
    return 0
}
