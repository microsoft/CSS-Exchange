# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Git pre-commit hook - runs validation checks on staged files
# Called by the pre-commit bash wrapper
# cspell:ignore github
# Install via: .github/Install-GitHooks.ps1

$exitCode = 0
$hookRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent

# Ensure CWD is repo root so relative staged file paths resolve correctly
# cspell:ignore toplevel
$repoRoot = git rev-parse --show-toplevel
if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrEmpty($repoRoot)) {
    Set-Location -Path $repoRoot
}

# Get staged files (include renames with R)
# cspell:ignore ACMR
$stagedFiles = @(git diff --cached --name-only --diff-filter=ACMR)

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: git diff failed. Are you in a git repository?" -ForegroundColor Red
    exit 1
}

if ($stagedFiles.Count -eq 0) {
    exit 0
}

# Run sensitive data scanner on test data files (all non-script files in Tests directories)
$testDataFiles = @($stagedFiles | Where-Object {
        $_ -match "Tests[/\\]" -and
        $_ -notmatch '\.(ps1|psm1|psd1)$'
    })

if ($testDataFiles.Count -gt 0) {
    Write-Host "Running sensitive data scan on $($testDataFiles.Count) test data file(s)..." -ForegroundColor Cyan
    $result = & (Join-Path -Path $hookRoot -ChildPath "Test-SensitiveData.ps1") -Files $testDataFiles
    if ($null -ne $result -and ($result | Select-Object -Last 1) -ne 0) {
        $exitCode = 1
    }
}

# Run test file run count check
$testFiles = @($stagedFiles | Where-Object { $_ -like "*.Tests.ps1" })

if ($testFiles.Count -gt 0) {
    Write-Host "Checking test file pipeline run counts..." -ForegroundColor Cyan
    $result = & (Join-Path -Path $hookRoot -ChildPath "Test-HealthCheckerScenarioRunCount.ps1") -Files $testFiles
    if ($null -ne $result -and ($result | Select-Object -Last 1) -ne 0) {
        $exitCode = 1
    }
}

# Run PSScriptAnalyzer on staged PowerShell files
$psFiles = @($stagedFiles | Where-Object { $_ -like "*.ps1" -or $_ -like "*.psm1" })

if ($psFiles.Count -gt 0) {
    Write-Host "Running PSScriptAnalyzer on $($psFiles.Count) PowerShell file(s)..." -ForegroundColor Cyan
    $result = & (Join-Path -Path $hookRoot -ChildPath "Test-ScriptAnalyzer.ps1") -Files $psFiles
    if ($null -ne $result -and ($result | Select-Object -Last 1) -ne 0) {
        $exitCode = 1
    }
}

if ($exitCode -eq 0) {
    Write-Host "All pre-commit checks passed." -ForegroundColor Green
} else {
    # Use 'git commit --no-verify' to bypass if needed
    Write-Host "Pre-commit checks failed. Fix the issues above." -ForegroundColor Red
}

exit $exitCode
