# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

BeforeAll {
    . (Join-Path $PSScriptRoot "..\CheckBacktickLineContinuation.ps1")

    $Script:fixturePath = Join-Path ([System.IO.Path]::GetTempPath()) "CheckBacktickLineContinuation.Tests.ps1"
    $Script:fixtureContent = "Write-Output ``" + [Environment]::NewLine + "    'value'" + [Environment]::NewLine
}

AfterAll {
    Remove-Item -LiteralPath $Script:fixturePath -Force -ErrorAction SilentlyContinue
}

Describe "CheckBacktickLineContinuation" {
    BeforeEach {
        Set-Content -LiteralPath $Script:fixturePath -Value $Script:fixtureContent -NoNewline
    }

    It "warns about the violation and returns true without Save" {
        $warnings = @()
        $result = CheckBacktickLineContinuation -FileInfo (Get-Item -LiteralPath $Script:fixturePath) -Save:$false -WarningVariable warnings -WarningAction SilentlyContinue

        $result | Should -BeTrue
        ($warnings -join " ") | Should -Match "Backtick line continuation at line 1"
        ($warnings -join " ") | Should -Not -Match "manual fix required"
    }

    It "warns that a manual fix is required and returns true with Save" {
        $warnings = @()
        $result = CheckBacktickLineContinuation -FileInfo (Get-Item -LiteralPath $Script:fixturePath) -Save:$true -WarningVariable warnings -WarningAction SilentlyContinue

        $result | Should -BeTrue
        ($warnings -join " ") | Should -Match "Backtick line continuation at line 1.*manual fix required \(no autofix\)"
        (Get-Content -LiteralPath $Script:fixturePath -Raw) | Should -Be $Script:fixtureContent
    }
}
