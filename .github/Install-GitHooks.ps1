# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Configures git to use the repository's pre-commit hooks.
.DESCRIPTION
    Sets git's core.hooksPath to .github/GitHooks/ so hooks run directly
    from the repository. This means hook updates are picked up automatically
    on git pull — no re-install needed.

    Enables local pre-commit validation including:
    - Sensitive data scanning on test data files
    - Pester test file pipeline run count checking
    - PSScriptAnalyzer validation on PowerShell files

    Hooks are local only and do not propagate via git clone.
    Run this script once after cloning the repository.
.EXAMPLE
    .github/Install-GitHooks.ps1
#>
# cspell:ignore github
[CmdletBinding()]
param()

$repoRoot = Get-Item (Join-Path -Path $PSScriptRoot -ChildPath "..")
$hooksDir = Join-Path -Path $PSScriptRoot -ChildPath "GitHooks"

if (-not (Test-Path (Join-Path -Path $repoRoot -ChildPath ".git"))) {
    Write-Host "Error: .git not found. Are you in a git repository?" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $hooksDir)) {
    Write-Host "Error: .github/GitHooks directory not found." -ForegroundColor Red
    exit 1
}

# Set git to use .github/GitHooks/ directly instead of .git/hooks/
git -C $repoRoot.FullName config core.hooksPath ".github/GitHooks"
$gitConfigResult = $LASTEXITCODE

# Ensure bash wrapper is executable on non-Windows platforms
if ($PSVersionTable.Platform -eq 'Unix' -or $PSVersionTable.OS -match 'Linux|Darwin') {
    $preCommitPath = Join-Path -Path $hooksDir -ChildPath "pre-commit"
    if (Test-Path $preCommitPath) {
        chmod +x $preCommitPath
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error: Failed to set executable permission on pre-commit hook." -ForegroundColor Red
            exit 1
        }
    }
}

if ($gitConfigResult -eq 0) {
    Write-Host "Git hooks configured successfully." -ForegroundColor Green
    Write-Host "  Hooks path: .github/GitHooks/" -ForegroundColor Cyan
    Write-Host "  Hook updates are picked up automatically on git pull." -ForegroundColor Cyan
} else {
    Write-Host "Error: Failed to set git hooks path." -ForegroundColor Red
    exit 1
}
