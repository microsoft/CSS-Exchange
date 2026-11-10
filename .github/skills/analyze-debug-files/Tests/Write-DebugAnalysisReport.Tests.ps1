# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Tests for `.github/skills/analyze-debug-files/Write-DebugAnalysisReport.ps1`.
#
# This helper owns Step 8's only side effect: creating the single report
# artifact in the caller's debug directory. Its two load-bearing guarantees are
# (a) it NEVER overwrites an existing file, and (b) it refuses report text
# carrying stray C0/C1 control characters -- the fingerprint of a double-quoted
# here-string bug in the generator. Both must stay hard behaviors.

[CmdletBinding()]
param()

Describe "Write-DebugAnalysisReport" {

    BeforeAll {
        $Script:repoRoot = (Get-Item "$PSScriptRoot\..\..\..\..").FullName
        $Script:scriptPath = Join-Path $Script:repoRoot '.github\skills\analyze-debug-files\Write-DebugAnalysisReport.ps1'

        # Fixture root under %TEMP% rather than Pester's TestDrive PSDrive: the
        # helper validates the drive via DriveInfo + QueryDosDevice, which only
        # speaks about real OS drive letters, not PowerShell provider drives.
        $Script:fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("WriteReportTests-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $Script:fixtureRoot -Force | Out-Null

        function Script:New-WorkDirectory {
            $p = Join-Path $Script:fixtureRoot ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            return $p
        }

        function Script:Invoke-Target {
            param([hashtable]$Params)
            $splat = @{
                DebugDirectory = (Script:New-WorkDirectory)
                ReportText     = "# Debug Analysis`n`nSome body text.`n"
            }
            if ($Params) { foreach ($k in $Params.Keys) { $splat[$k] = $Params[$k] } }
            return & $Script:scriptPath @splat
        }

        if (-not ('ReportWriteTestFactory' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.IO;
public static class ReportWriteTestFactory {
    public static bool FailWrite;
    public static bool FailFlush;
    public static bool FailDispose;
    public static int OpenCount;
    public static FileStream Open(string path, FileMode mode, FileAccess access, FileShare share) {
        OpenCount++;
        return new ReportWriteTestStream(path, mode, access, share);
    }
}
public sealed class ReportWriteTestStream : FileStream {
    private bool disposed;
    public ReportWriteTestStream(string path, FileMode mode, FileAccess access, FileShare share)
        : base(path, mode, access, share) { }
    public override void Write(byte[] buffer, int offset, int count) {
        if (ReportWriteTestFactory.FailWrite) {
            base.Write(buffer, offset, Math.Min(count, 7));
            base.Flush();
            throw new IOException("Injected write failure");
        }
        base.Write(buffer, offset, count);
    }
    public override void Flush() {
        if (ReportWriteTestFactory.FailFlush) throw new IOException("Injected flush failure");
        base.Flush();
    }
    protected override void Dispose(bool disposing) {
        bool first = !disposed;
        disposed = true;
        try { base.Dispose(disposing); }
        finally {
            if (disposing && first && ReportWriteTestFactory.FailDispose)
                throw new IOException("Injected disposal failure");
        }
    }
}
'@
        }
        $injectedRoot = Join-Path -Path $Script:fixtureRoot -ChildPath 'injected'
        $injectedSkill = Join-Path -Path $injectedRoot -ChildPath 'skills\analyze-debug-files'
        $injectedLibrary = Join-Path -Path $injectedRoot -ChildPath 'skill-lib'
        New-Item -Path $injectedSkill, $injectedLibrary -ItemType Directory -Force | Out-Null
        foreach ($name in @('Resolve-SkillLocalPath.ps1', 'Test-IsLocalDosDeviceTarget.ps1', 'Test-PathHasReparsePointRootToLeaf.ps1')) {
            Copy-Item -LiteralPath (Join-Path -Path $Script:repoRoot -ChildPath ".github\skill-lib\$name") -Destination $injectedLibrary
        }
        $Script:injectedScriptPath = Join-Path -Path $injectedSkill -ChildPath 'Write-DebugAnalysisReport.ps1'
        $source = [System.IO.File]::ReadAllText($Script:scriptPath)
        $source = $source.Replace('[System.IO.File]::Open(', '[ReportWriteTestFactory]::Open(')
        [System.IO.File]::WriteAllText($Script:injectedScriptPath, $source, [System.Text.UTF8Encoding]::new($true))
    }

    AfterAll {
        Remove-Item -LiteralPath $Script:fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Context "Happy path" {

        It "writes the report and returns its path" {
            $dir = Script:New-WorkDirectory
            $r = Script:Invoke-Target -Params @{ DebugDirectory = $dir; TimeStamp = '20260912181122' }
            $r.FileName | Should -BeExactly 'DebugAnalysis-20260912181122.md'
            $r.Path | Should -BeExactly (Join-Path $dir 'DebugAnalysis-20260912181122.md')
            $r.Collided | Should -BeFalse
            Test-Path -LiteralPath $r.Path -PathType Leaf | Should -BeTrue
        }

        It "writes the exact report text back" {
            $dir = Script:New-WorkDirectory
            $text = "# Title`n`nLine one.`nLine two with a tab" + [char]9 + "here.`n"
            $r = Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = $text }
            [System.IO.File]::ReadAllText($r.Path) | Should -BeExactly $text
            $r.BytesWritten | Should -Be ([System.Text.Encoding]::UTF8.GetByteCount($text))
        }

        It "writes into a relative PowerShell directory when the process directory differs" {
            $dir = Script:New-WorkDirectory
            $other = Script:New-WorkDirectory
            $processDirectory = [System.Environment]::CurrentDirectory
            Push-Location -LiteralPath $dir
            try {
                [System.Environment]::CurrentDirectory = $other
                $r = Script:Invoke-Target -Params @{ DebugDirectory = '.'; TimeStamp = '20261103075933' }
                $r.Path | Should -BeExactly (Join-Path -Path $dir -ChildPath 'DebugAnalysis-20261103075933.md')
                @(Get-ChildItem -LiteralPath $other -File).Count | Should -Be 0
            } finally {
                [System.Environment]::CurrentDirectory = $processDirectory
                Pop-Location
            }
        }

        It "writes UTF-8 WITHOUT a BOM, matching the repository markdown convention" {
            $dir = Script:New-WorkDirectory
            $r = Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = "# No BOM please`n" }
            $bytes = [System.IO.File]::ReadAllBytes($r.Path)
            $bytes.Length | Should -BeGreaterThan 3
            ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) |
                Should -BeFalse -Because "generated markdown must not carry a BOM"
        }

        It "defaults the timestamp to the current time in yyyyMMddHHmmss form" {
            $dir = Script:New-WorkDirectory
            $r = Script:Invoke-Target -Params @{ DebugDirectory = $dir }
            $r.FileName | Should -Match '\ADebugAnalysis-[0-9]{14}\.md\z'
        }

        It "returns exactly one object" {
            $dir = Script:New-WorkDirectory
            $r = @(Script:Invoke-Target -Params @{ DebugDirectory = $dir })
            $r.Count | Should -Be 1 -Because "stray pipeline output would corrupt the caller's contract"
        }
    }

    Context "Never overwrites" {

        It "writes a suffixed name instead of clobbering a same-second collision" {
            $dir = Script:New-WorkDirectory
            $stamp = '20260912181122'
            $first = Script:Invoke-Target -Params @{ DebugDirectory = $dir; TimeStamp = $stamp; ReportText = "# first`n" }
            $second = Script:Invoke-Target -Params @{ DebugDirectory = $dir; TimeStamp = $stamp; ReportText = "# second`n" }

            $second.Path | Should -Not -Be $first.Path
            $second.Collided | Should -BeTrue
            $second.FileName | Should -Match "\ADebugAnalysis-$stamp-[0-9a-f]{8}\.md\z"
            # The original must be byte-for-byte intact.
            [System.IO.File]::ReadAllText($first.Path) | Should -BeExactly "# first`n"
            [System.IO.File]::ReadAllText($second.Path) | Should -BeExactly "# second`n"
        }

        Context "Post-create failure cleanup" {

            It "preserves the <Label> failure and removes the report even when disposal fails" -ForEach @(
                @{ Label = 'write'; WriteFails = $true; FlushFails = $false; ErrorText = 'Injected write failure' }
                @{ Label = 'flush'; WriteFails = $false; FlushFails = $true; ErrorText = 'Injected flush failure' }
                @{ Label = 'disposal-only'; WriteFails = $false; FlushFails = $false; ErrorText = 'Injected disposal failure' }
            ) {
                $directory = Script:New-WorkDirectory
                [ReportWriteTestFactory]::FailWrite = $WriteFails
                [ReportWriteTestFactory]::FailFlush = $FlushFails
                [ReportWriteTestFactory]::FailDispose = $true
                [ReportWriteTestFactory]::OpenCount = 0
                $parameters = @{
                    DebugDirectory = $directory
                    ReportText     = "# The entire expected report`n"
                    TimeStamp      = '20261028074641'
                }

                { & $Script:injectedScriptPath @parameters } | Should -Throw "*$ErrorText*"
                @(Get-ChildItem -LiteralPath $directory -File).Count | Should -Be 0
                [ReportWriteTestFactory]::OpenCount | Should -Be 1
            }

            It "discloses a retained partial report without replacing the write error under WarningAction Stop" {
                $directory = Script:New-WorkDirectory
                [ReportWriteTestFactory]::FailWrite = $true
                [ReportWriteTestFactory]::FailFlush = $false
                [ReportWriteTestFactory]::FailDispose = $true
                Mock -CommandName Remove-Item -ParameterFilter { $LiteralPath -like '*DebugAnalysis-*.md' } -MockWith {
                    throw 'Injected deletion failure'
                }
                $parameters = @{
                    DebugDirectory  = $directory
                    ReportText      = "# The entire expected report`n"
                    TimeStamp       = '20261028074641'
                    WarningAction   = 'Stop'
                    WarningVariable = 'cleanupWarnings'
                }

                $caughtError = $null
                try {
                    & $Script:injectedScriptPath @parameters
                } catch {
                    $caughtError = $_
                }
                $caughtError | Should -Not -BeNullOrEmpty
                $caughtError.Exception.Message | Should -Match 'Injected write failure'
                @($cleanupWarnings).Count | Should -Be 1
                [string]$cleanupWarnings[0] | Should -Match 'Failed to remove partial report'
                @(Get-ChildItem -LiteralPath $directory -File).Count | Should -Be 1
            }
        }

        It "leaves every prior report intact across repeated same-second writes" {
            $dir = Script:New-WorkDirectory
            $stamp = '20260912181122'
            foreach ($i in 1..4) {
                $null = Script:Invoke-Target -Params @{ DebugDirectory = $dir; TimeStamp = $stamp; ReportText = "# report $i`n" }
            }
            @(Get-ChildItem -LiteralPath $dir -Filter 'DebugAnalysis-*.md').Count |
                Should -Be 4 -Because "each write must create its own file rather than replacing the last"
        }

        It "surfaces a non-collision failure immediately instead of consuming the retry budget" {
            # A directory occupying the destination name makes
            # `File.Open(..CreateNew..)` throw UnauthorizedAccessException,
            # which is NOT an IOException and must therefore bypass the
            # collision retry entirely. Asserting that no suffixed file was
            # created proves no retry happened -- the earlier revision's
            # Test-Path-based collision fallback would have retried here and
            # reported a misleading "could not find a free name".
            $dir = Script:New-WorkDirectory
            $stamp = '20260912181122'
            New-Item -ItemType Directory -Path (Join-Path $dir "DebugAnalysis-$stamp.md") -Force | Out-Null
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; TimeStamp = $stamp } } | Should -Throw
            @(Get-ChildItem -LiteralPath $dir -File -Filter 'DebugAnalysis-*.md').Count |
                Should -Be 0 -Because "a non-collision failure must not be retried under a suffixed name"
        }

        It "reports Collided and a distinct path when the base name is taken" {
            $dir = Script:New-WorkDirectory
            $stamp = '20260912181122'
            $first = Script:Invoke-Target -Params @{ DebugDirectory = $dir; TimeStamp = $stamp }
            $second = Script:Invoke-Target -Params @{ DebugDirectory = $dir; TimeStamp = $stamp; MaxCollisionRetries = 1 }
            $second.Collided | Should -BeTrue
            $second.Path | Should -Not -Be $first.Path
            $second.Path | Should -Not -Be (Join-Path $dir "DebugAnalysis-$stamp.md")
        }
    }

    Context "Encoding fidelity" {

        It "refuses report text that cannot be encoded faithfully as UTF-8" {
            # A lone high surrogate is not valid UTF-16. The default UTF8
            # encoder silently replaces it with U+FFFD, so the bytes on disk
            # would differ from $ReportText. The strict encoder throws instead.
            $dir = Script:New-WorkDirectory
            $loneSurrogate = "# Title" + [char]0xD800 + " body"
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = $loneSurrogate } } | Should -Throw
            @(Get-ChildItem -LiteralPath $dir -File).Count |
                Should -Be 0 -Because "encoding is validated before the file is created"
        }

        It "round-trips non-ASCII content byte-for-byte" {
            # Built from explicit code points rather than literal words so the
            # test exercises multi-byte UTF-8 (2-byte Latin-1 supplement,
            # 2-byte Cyrillic, 3-byte arrow) without depending on dictionary
            # words the repository spell-checker would have to learn.
            $dir = Script:New-WorkDirectory
            $twoByteA = [string]([char]0x00E9 + [char]0x00FC + [char]0x00F1)
            $twoByteB = [string]([char]0x0411 + [char]0x0430 + [char]0x0437)
            $threeByte = [string][char]0x2190
            $text = "# Report $twoByteA`n`n$twoByteB $threeByte annotation`n"
            $r = Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = $text }
            [System.IO.File]::ReadAllText($r.Path) | Should -BeExactly $text
            # Prove it really was multi-byte: byte count must exceed char count.
            $r.BytesWritten | Should -BeGreaterThan $text.Length
        }
    }

    Context "Control-character refusal" {

        # A double-quoted here-string silently turns `v into U+000B and `a
        # into U+0007. The report contract forbids every C0/C1 control except
        # tab, CR, and LF, so the helper must refuse rather than persist it.

        It "refuses a vertical tab (the here-string fingerprint)" {
            $dir = Script:New-WorkDirectory
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = "# Title`n$([char]0x0B)body" } } |
                Should -Throw '*U+000B*'
        }

        It "refuses a NUL character" {
            $dir = Script:New-WorkDirectory
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = "ok$([char]0x00)bad" } } |
                Should -Throw '*control character*'
        }

        It "refuses an ESC character (ANSI sequence leakage)" {
            $dir = Script:New-WorkDirectory
            $escapeSequence = "ok" + [char]0x1B + "[31m" + "danger"
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = $escapeSequence } } |
                Should -Throw '*control character*'
        }

        It "refuses a C1 control" {
            $dir = Script:New-WorkDirectory
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = "ok$([char]0x9B)bad" } } |
                Should -Throw '*control character*'
        }

        It "writes nothing when the report text is refused" {
            $dir = Script:New-WorkDirectory
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = "bad$([char]0x0B)" } } | Should -Throw
            @(Get-ChildItem -LiteralPath $dir -File).Count |
                Should -Be 0 -Because "the refusal must happen before any file is created"
        }

        It "permits tab, CR, and LF" {
            $dir = Script:New-WorkDirectory
            $text = "first line" + "`r`n" + "second" + [char]9 + "column" + "`n"
            $r = Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = $text }
            [System.IO.File]::ReadAllText($r.Path) | Should -BeExactly $text
        }
    }

    Context "DebugDirectory local-path validation (hard refusal)" {

        It "refuses a UNC debug directory" {
            { Script:Invoke-Target -Params @{ DebugDirectory = '\\attacker.example\share\logs' } } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a device-namespace debug directory" {
            { Script:Invoke-Target -Params @{ DebugDirectory = '\\?\C:\logs' } } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a provider-qualified debug directory" {
            { Script:Invoke-Target -Params @{ DebugDirectory = 'FileSystem::C:\logs' } } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a drive-relative debug directory" {
            # `C:relative` resolves against the PSDrive's own current
            # directory, which can differ from .NET's -- validation and write
            # could target different trees.
            { Script:Invoke-Target -Params @{ DebugDirectory = 'C:relative' } } |
                Should -Throw '*failed local-path validation*'
        }

        It "refuses a directory that does not exist" {
            { Script:Invoke-Target -Params @{ DebugDirectory = (Join-Path $Script:fixtureRoot 'missing-7f2a') } } |
                Should -Throw '*failed local-path validation*'
        }
    }

    Context "Parameter validation" {

        It "rejects an empty ReportText" {
            $dir = Script:New-WorkDirectory
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; ReportText = '' } } | Should -Throw
        }

        It "rejects a TimeStamp that is not 14 digits" {
            $dir = Script:New-WorkDirectory
            { Script:Invoke-Target -Params @{ DebugDirectory = $dir; TimeStamp = '2026-09-12' } } | Should -Throw
        }
    }
}
