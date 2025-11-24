# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function DoSpellCheck {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'This is the correct syntax for cspell')]
    param()

    $nodeVersion = $null
    try {
        $nodeVersion = node -v
    } catch {
        Write-Host "Node.js is not installed. Please install Node.js from https://nodejs.org, launch a new instance of PowerShell, and try again."
        exit 1
    }

    $majorVersion = [int]::Parse($nodeVersion.Split(".")[0].Trim("v"))

    if ($majorVersion -lt 14) {
        Write-Host "Node.js version 14 or higher is required. Please upgrade Node.js and try again."
        exit 1
    }

    $cspellModule = npm -g ls cspell | Select-String "cspell@"

    if ([string]::IsNullOrEmpty($cspellModule)) {
        Write-Host "Installing cspell..."
        npm install -g cspell
    }

    $cspellModule = npm -g ls cspell | Select-String "cspell@"

    if ([string]::IsNullOrEmpty($cspellModule)) {
        Write-Host "Could not install cspell. Please install cspell and try again."
        exit 1
    }

    $repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

    cspell lint --dot --config "$PSScriptRoot\cspell.json" --no-progress (Join-Path $repoRoot "**" "*.md") (Join-Path $repoRoot "**" "*.ps1")
}

DoSpellCheck
