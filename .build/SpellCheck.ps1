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

    $cspellPath = (npm -g ls cspell | Select-String "C:\\(\S+)$").Matches.Value
    if ([string]::IsNullOrEmpty($cspellPath)) {
        Write-Host "Installing cspell..."
        npm install -g cspell

        $cspellPath = (npm -g ls cspell | Select-String "C:\\(\S+)$").Matches.Value
        if ([string]::IsNullOrEmpty($cspellPath)) {
            Write-Host "Could not install cspell."
            exit 1
        }
    }

    if (-not ($env:PATH | Select-String $cspellPath -SimpleMatch)) {
        Write-Host "Adding cspell path to PATH..."
        $env:PATH = "$env:PATH;$cspellPath"
    }

    $repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

    cspell lint --config "$PSScriptRoot\cspell.json" --no-progress (Join-Path $repoRoot "**" "*.md") (Join-Path $repoRoot "**" "*.ps1")
}

DoSpellCheck
