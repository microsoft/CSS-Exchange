# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Describe 'Resolve-SkillLocalPath' {
    BeforeAll {
        $Script:helperPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Resolve-SkillLocalPath.ps1'
        . $Script:helperPath
        $Script:fixtureRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('SkillPathTests-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $Script:fixtureRoot -ItemType Directory | Out-Null
        $Script:filePath = Join-Path -Path $Script:fixtureRoot -ChildPath 'fixture.txt'
        [System.IO.File]::WriteAllText($Script:filePath, 'Controlled fixture')
    }

    AfterAll {
        Remove-Item -LiteralPath $Script:fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'resolves a relative path against PowerShell rather than the process directory' {
        $processDirectory = [System.Environment]::CurrentDirectory
        Push-Location -LiteralPath $Script:fixtureRoot
        try {
            [System.Environment]::CurrentDirectory = [System.IO.Path]::GetPathRoot($Script:fixtureRoot)
            Resolve-SkillLocalPath -Path '.' | Should -BeExactly $Script:fixtureRoot
        } finally {
            [System.Environment]::CurrentDirectory = $processDirectory
            Pop-Location
        }
    }

    It 'requires existence unless missing paths are explicitly allowed' {
        $missing = Join-Path -Path $Script:fixtureRoot -ChildPath 'missing\cache.xml'
        Resolve-SkillLocalPath -Path $missing | Should -BeNullOrEmpty
        Resolve-SkillLocalPath -Path $missing -AllowMissing | Should -BeExactly $missing
    }

    It 'distinguishes existing files from directories' {
        Resolve-SkillLocalPath -Path $Script:filePath | Should -BeNullOrEmpty
        Resolve-SkillLocalPath -Path $Script:filePath -PathType Leaf | Should -BeExactly $Script:filePath
        Resolve-SkillLocalPath -Path $Script:fixtureRoot -PathType Leaf | Should -BeNullOrEmpty
    }

    It 'refuses <Label> before inspecting the target' -ForEach @(
        @{ Label = 'UNC'; InputPath = '\\attacker.example\share\logs' }
        @{ Label = 'mixed-separator UNC'; InputPath = '/\attacker.example\share\logs' }
        @{ Label = 'device namespace'; InputPath = '\\?\C:\logs' }
        @{ Label = 'NT namespace'; InputPath = '\??\C:\logs' }
        @{ Label = 'provider-qualified'; InputPath = 'FileSystem::C:\logs' }
        @{ Label = 'non-filesystem provider'; InputPath = 'Env:\TEMP' }
        @{ Label = 'drive-relative'; InputPath = 'C:logs' }
        @{ Label = 'whitespace-only'; InputPath = '   ' }
    ) {
        Mock -CommandName Test-PathHasReparsePointRootToLeaf -MockWith { throw 'Unexpected target inspection' }
        Mock -CommandName Test-Path -MockWith { throw 'Unexpected existence check' }

        Resolve-SkillLocalPath -Path $InputPath -AllowMissing | Should -BeNullOrEmpty
        Should -Invoke -CommandName Test-PathHasReparsePointRootToLeaf -Times 0 -Exactly
        Should -Invoke -CommandName Test-Path -Times 0 -Exactly
    }

    It 'refuses a drive shadowed by <Label> before inspecting the target' -ForEach @(
        @{ Label = 'a network root'; ProviderName = 'FileSystem'; Root = '\\attacker.example\share' }
        @{ Label = 'a directory alias'; ProviderName = 'FileSystem'; Root = 'C:\redirected' }
        @{ Label = 'another local volume'; ProviderName = 'FileSystem'; Root = 'other-volume' }
        @{ Label = 'another provider'; ProviderName = 'Environment'; Root = '' }
    ) {
        $drive = [System.IO.Path]::GetPathRoot($Script:fixtureRoot).Substring(0, 1)
        $shadowRoot = if ($Root -eq 'other-volume') {
            if ($drive -ieq 'Z') { 'Y:\' } else { 'Z:\' }
        } else {
            $Root
        }
        $shadow = [PSCustomObject]@{
            Provider = [PSCustomObject]@{ Name = $ProviderName }
            Root     = $shadowRoot
        }
        Mock -CommandName Get-PSDrive -MockWith ({ return $shadow }.GetNewClosure())
        Mock -CommandName Test-PathHasReparsePointRootToLeaf -MockWith { throw 'Unexpected target inspection' }

        Resolve-SkillLocalPath -Path "${drive}:\logs" | Should -BeNullOrEmpty
        Should -Invoke -CommandName Test-PathHasReparsePointRootToLeaf -Times 0 -Exactly
    }

    It 'refuses DOS-device aliases before inspecting their filesystem targets' {
        Mock -CommandName Test-IsLocalDosDeviceTarget -MockWith { return $false }
        Mock -CommandName Test-PathHasReparsePointRootToLeaf -MockWith { throw 'Unexpected target inspection' }

        Resolve-SkillLocalPath -Path $Script:fixtureRoot | Should -BeNullOrEmpty
        Should -Invoke -CommandName Test-PathHasReparsePointRootToLeaf -Times 0 -Exactly
    }

    It 'refuses a reparse ancestor even when the tail does not exist' {
        $target = Join-Path -Path $Script:fixtureRoot -ChildPath 'target'
        $link = Join-Path -Path $Script:fixtureRoot -ChildPath 'junction'
        New-Item -Path $target -ItemType Directory | Out-Null
        New-Item -Path $link -ItemType Junction -Target $target | Out-Null
        try {
            Mock -CommandName Test-Path -MockWith { throw 'Unexpected existence check' }
            Resolve-SkillLocalPath -Path (Join-Path -Path $link -ChildPath 'missing\cache.xml') -AllowMissing |
                Should -BeNullOrEmpty
            Should -Invoke -CommandName Test-Path -Times 0 -Exactly
        } finally {
            [System.IO.Directory]::Delete($link)
        }
    }
}
