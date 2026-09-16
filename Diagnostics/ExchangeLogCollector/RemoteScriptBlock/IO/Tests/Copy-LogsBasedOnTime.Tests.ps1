# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    . $PSScriptRoot\..\Copy-BulkItems.ps1
    . $PSScriptRoot\..\Copy-LogsBasedOnTime.ps1
    . $PSScriptRoot\..\Copy-FullLogFullPathRecurse.ps1
    . $PSScriptRoot\..\Compress-Folder.ps1

    function Invoke-ZipFolder {
        param([string]$Folder)
    }
}

Describe 'Log file copying preserves every source' {
    BeforeEach {
        $script:fixtureRoot = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $script:firstSource = Join-Path -Path $script:fixtureRoot -ChildPath 'serverA\W3SVC1'
        $script:secondSource = Join-Path -Path $script:fixtureRoot -ChildPath 'serverB\W3SVC1'
        $script:destination = Join-Path -Path $script:fixtureRoot -ChildPath 'Collected'
        $null = New-Item -Path $script:firstSource, $script:secondSource -ItemType Directory -Force
        $script:PassedInfo = [PSCustomObject]@{ TimeSpan = [TimeSpan]::FromMinutes(30); EndTimeSpan = [TimeSpan]::Zero }
        Mock -CommandName Test-FreeSpace -MockWith { $true }
        Mock -CommandName Invoke-ZipFolder -MockWith {}
    }

    It 'copies a literal filename with square brackets' {
        $source = Join-Path -Path $script:firstSource -ChildPath 'log[01].log'
        Set-Content -LiteralPath $source -Value 'first marker'
        Copy-BulkItems -CopyToLocation $script:destination -ItemsToCopyLocation @($source)
        Get-Content -LiteralPath "$script:destination\log[01].log" | Should -Be 'first marker'
    }

    It 'adds the source identity to a subsequent same-named file' {
        Set-Content -LiteralPath "$script:firstSource\same.log" -Value 'first marker'
        Set-Content -LiteralPath "$script:secondSource\same.log" -Value 'second marker'
        Copy-BulkItems -CopyToLocation $script:destination -ItemsToCopyLocation @("$script:firstSource\same.log", "$script:secondSource\same.log")
        Get-Content -LiteralPath "$script:destination\same.log" | Should -Be 'first marker'
        $files = @(Get-ChildItem -LiteralPath $script:destination -File)
        $files | Should -HaveCount 2
        $additional = $files | Where-Object { $_.Name -ne 'same.log' }
        $additional.Name | Should -Match '^same__.*ServerB_W3SVC1_[a-f0-9]{12}\.log$'
        Get-Content -LiteralPath $additional.FullName | Should -Be 'second marker'
    }

    It 'preserves all files even when the source suffix already exists' {
        Set-Content -LiteralPath "$script:firstSource\same.log" -Value 'first marker'
        Set-Content -LiteralPath "$script:secondSource\same.log" -Value 'second marker'
        $paths = @("$script:firstSource\same.log", "$script:secondSource\same.log", "$script:secondSource\same.log")
        Copy-BulkItems -CopyToLocation $script:destination -ItemsToCopyLocation $paths
        $files = @(Get-ChildItem -LiteralPath $script:destination -File)
        $files | Should -HaveCount 3
        @($files | Where-Object { $_.Name -match '_2\.log$' }) | Should -HaveCount 1
    }

    It 'warns on a locked file and continues with the next file' {
        $locked = Join-Path -Path $script:firstSource -ChildPath 'locked.log'
        $readable = Join-Path -Path $script:firstSource -ChildPath 'readable.log'
        Set-Content -LiteralPath $locked -Value 'locked marker'
        Set-Content -LiteralPath $readable -Value 'readable marker'
        $stream = [System.IO.File]::Open($locked, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            Copy-BulkItems -CopyToLocation $script:destination -ItemsToCopyLocation @($locked, $readable) -WarningVariable copyWarnings -WarningAction SilentlyContinue
            @($copyWarnings) | Should -HaveCount 1
            Get-Content -LiteralPath "$script:destination\readable.log" | Should -Be 'readable marker'
        } finally {
            $stream.Dispose()
        }
    }

    It 'preserves the relative structure of repeated directory names' {
        Set-Content -LiteralPath "$script:firstSource\same.log" -Value 'first marker'
        Set-Content -LiteralPath "$script:secondSource\same.log" -Value 'second marker'
        $output = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        Copy-LogsBasedOnTime -LogPath $script:fixtureRoot -CopyToThisLocation $output -IncludeSubDirectory $true
        Get-Content -LiteralPath "$output\serverA\W3SVC1\same.log" | Should -Be 'first marker'
        Get-Content -LiteralPath "$output\serverB\W3SVC1\same.log" | Should -Be 'second marker'
    }

    It 'copies from a literal directory containing square brackets' {
        $source = Join-Path -Path $script:firstSource -ChildPath 'Logs[2026]'
        $null = New-Item -Path $source -ItemType Directory
        Set-Content -LiteralPath "$source\current.log" -Value 'literal directory marker'
        Copy-LogsBasedOnTime -LogPath $source -CopyToThisLocation $script:destination -IncludeSubDirectory $true
        Get-Content -LiteralPath "$script:destination\current.log" | Should -Be 'literal directory marker'
        Test-Path -LiteralPath "$script:destination\NoFilesDetected.txt" | Should -BeFalse
    }

    It 'keeps the latest old file when the requested interval is empty' {
        Set-Content -LiteralPath "$script:firstSource\old.log" -Value 'old marker'
        Set-Content -LiteralPath "$script:firstSource\older.log" -Value 'older marker'
        (Get-Item -LiteralPath "$script:firstSource\old.log").LastWriteTime = (Get-Date).AddDays(-4)
        (Get-Item -LiteralPath "$script:firstSource\older.log").LastWriteTime = (Get-Date).AddDays(-5)
        Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $false
        Get-Content -LiteralPath "$script:destination\old.log" | Should -Be 'old marker'
        Test-Path -LiteralPath "$script:destination\older.log" | Should -BeFalse
    }

    It 'reports enumeration failure without a false empty-directory marker' {
        Mock -CommandName Get-ChildItem -ParameterFilter { $LiteralPath -eq $script:firstSource } -MockWith { throw 'Access denied by test.' }
        Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $true -WarningVariable copyWarnings -WarningAction SilentlyContinue
        @($copyWarnings) | Should -HaveCount 1
        Test-Path -LiteralPath "$script:destination\NoFilesDetected.txt" | Should -BeFalse
    }

    It 'refuses to recurse into its own collection output' {
        Copy-LogsBasedOnTime -LogPath $script:fixtureRoot -CopyToThisLocation $script:destination -IncludeSubDirectory $true -WarningVariable copyWarnings -WarningAction SilentlyContinue
        @($copyWarnings) | Should -HaveCount 1
        Should -Invoke -CommandName Invoke-ZipFolder -Times 0 -Exactly
    }

    It 'measures literal paths without duplicate-key exceptions' {
        $source = Join-Path -Path $script:firstSource -ChildPath 'log[01].log'
        Set-Content -LiteralPath $source -Value 'size marker'
        Get-ItemsSize -FilePaths @($source, $source) | Should -Be ((Get-Item -LiteralPath $source).Length * 2)
    }

    It 'compresses literal directories and deletes only the source directory' {
        $source = Join-Path -Path $script:firstSource -ChildPath 'Logs[2026]'
        $null = New-Item -Path $source -ItemType Directory
        Set-Content -LiteralPath "$source\current.log" -Value 'compressed marker'
        $archive = Compress-Folder -Folder $source -ReturnCompressedLocation $true -IncludeDisplayZipping $false
        Test-Path -LiteralPath $archive | Should -BeTrue
        Test-Path -LiteralPath $source | Should -BeFalse
        $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
        try {
            $zip.Entries.Name | Should -Contain 'current.log'
        } finally {
            $zip.Dispose()
        }
    }

    It 'honors both boundaries of a historical collection window' {
        $script:PassedInfo.TimeSpan = [TimeSpan]::FromDays(2)
        $script:PassedInfo.EndTimeSpan = [TimeSpan]::FromDays(1)
        foreach ($entry in @(@{ Name = 'wanted.log'; Age = -36 }, @{ Name = 'too-new.log'; Age = -1 }, @{ Name = 'too-old.log'; Age = -72 })) {
            $path = Join-Path -Path $script:firstSource -ChildPath $entry.Name
            Set-Content -LiteralPath $path -Value $entry.Name
            (Get-Item -LiteralPath $path).LastWriteTime = (Get-Date).AddHours($entry.Age)
        }
        Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $false
        @(Get-ChildItem -LiteralPath $script:destination -File).Name | Should -Be 'wanted.log'
    }

    It 'reports only a genuinely empty directory as having no files' {
        Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $false
        Get-Content -LiteralPath "$script:destination\NoFilesDetected.txt" -Raw | Should -Match ([regex]::Escape($script:firstSource))
    }

    It 'identifies an actually missing source directory' {
        Copy-LogsBasedOnTime -LogPath "$script:firstSource\missing" -CopyToThisLocation $script:destination -IncludeSubDirectory $true
        Get-Content -LiteralPath "$script:destination\NoFilesDetected.txt" -Raw | Should -Match "Path doesn't exist"
    }

    It 'does not mark a root empty when its child contains a central log' {
        Set-Content -LiteralPath "$script:firstSource\central.log" -Value 'central marker'
        $output = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        Copy-LogsBasedOnTime -LogPath $script:fixtureRoot -CopyToThisLocation $output -IncludeSubDirectory $true
        Test-Path -LiteralPath "$output\NoFilesDetected.txt" | Should -BeFalse
        Get-Content -LiteralPath "$output\serverA\W3SVC1\central.log" | Should -Be 'central marker'
    }

    It 'copies binary bytes without applying a text-log extension filter' {
        $source = Join-Path -Path $script:firstSource -ChildPath 'ra260916.ibl'
        [System.IO.File]::WriteAllBytes($source, [byte[]]@(0, 1, 127, 128, 255))
        Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $false
        (Get-FileHash -LiteralPath "$script:destination\ra260916.ibl").Hash | Should -Be (Get-FileHash -LiteralPath $source).Hash
    }

    It 'copies an active log opened with normal IIS file sharing' {
        $source = Join-Path -Path $script:firstSource -ChildPath 'active.log'
        Set-Content -LiteralPath $source -Value 'active marker'
        $stream = [System.IO.File]::Open($source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
        try {
            Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $false
            Get-Content -LiteralPath "$script:destination\active.log" | Should -Be 'active marker'
        } finally {
            $stream.Dispose()
        }
    }

    It 'retains the existing insufficient-space diagnostic' {
        Mock -CommandName Test-FreeSpace -MockWith { $false }
        Mock -CommandName Get-StringDataForNotEnoughFreeSpaceFile -MockWith { 'Insufficient fixture space.' }
        $script:ItemSizesHashed = @{ "$script:firstSource\current.log" = 10 }
        Set-Content -LiteralPath "$script:firstSource\current.log" -Value 'current marker'
        Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $false
        Test-Path -LiteralPath "$script:destination\NotEnoughFreeSpace.txt" | Should -BeTrue
        Test-Path -LiteralPath "$script:destination\NoFilesDetected.txt" | Should -BeFalse
    }

    It 'preserves files without extensions when their names collide' {
        Set-Content -LiteralPath "$script:firstSource\log" -Value 'first marker'
        Set-Content -LiteralPath "$script:secondSource\log" -Value 'second marker'
        Copy-BulkItems -CopyToLocation $script:destination -ItemsToCopyLocation @("$script:firstSource\log", "$script:secondSource\log")
        @(Get-ChildItem -LiteralPath $script:destination -File) | Should -HaveCount 2
    }

    It 'keeps a collision suffix within the filename component limit' {
        $longName = ('n' * 240) + '.log'
        Mock -CommandName Get-Item -MockWith {
            [PSCustomObject]@{ Name = $longName; FullName = "C:\Source\$longName" }
        }
        Mock -CommandName Test-Path -MockWith { param($LiteralPath) $LiteralPath -eq "C:\Out\$longName" }
        Mock -CommandName New-Item -MockWith {}
        Mock -CommandName Copy-Item -MockWith {}
        Copy-BulkItems -CopyToLocation 'C:\Out' -ItemsToCopyLocation @("C:\Source\$longName")
        Should -Invoke -CommandName Copy-Item -Times 1 -Exactly -ParameterFilter {
            [System.IO.Path]::GetFileName($Destination).Length -le 255 -and $Destination -match '__C_SOURCE_[a-f0-9]{12}\.log$'
        }
    }

    It 'creates the space diagnostic in the literal bracketed output directory' {
        $script:destination = Join-Path -Path $script:fixtureRoot -ChildPath 'Collected\Logs[2026]'
        $lookalike = Join-Path -Path $script:fixtureRoot -ChildPath 'Collected\Logs2'
        $null = New-Item -Path $lookalike -ItemType Directory -Force
        $source = Join-Path -Path $script:firstSource -ChildPath 'current.log'
        Set-Content -LiteralPath $source -Value 'current marker'
        $script:ItemSizesHashed = @{ $source = 10 }
        Mock -CommandName Test-FreeSpace -MockWith { $false }
        Mock -CommandName Get-StringDataForNotEnoughFreeSpaceFile -MockWith { 'Insufficient fixture space.' }
        Copy-BulkItems -CopyToLocation $script:destination -ItemsToCopyLocation @($source)
        Test-Path -LiteralPath "$script:destination\NotEnoughFreeSpace.txt" | Should -BeTrue
        Test-Path -LiteralPath "$lookalike\NotEnoughFreeSpace.txt" | Should -BeFalse
    }

    It 'creates the empty-directory marker in the literal bracketed destination' {
        $script:destination = Join-Path -Path $script:fixtureRoot -ChildPath 'Collected\Logs[2026]'
        $lookalike = Join-Path -Path $script:fixtureRoot -ChildPath 'Collected\Logs2'
        $null = New-Item -Path $lookalike -ItemType Directory -Force
        Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $true
        Test-Path -LiteralPath "$script:destination\NoFilesDetected.txt" | Should -BeTrue
        Test-Path -LiteralPath "$lookalike\NoFilesDetected.txt" | Should -BeFalse
    }

    It 'creates a bracketed child directory without writing into a similar existing name' {
        $source = Join-Path -Path $script:firstSource -ChildPath 'Logs[2026]'
        $lookalike = Join-Path -Path $script:destination -ChildPath 'Logs2'
        $null = New-Item -Path $source, $lookalike -ItemType Directory -Force
        Set-Content -LiteralPath "$source\current.log" -Value 'literal child marker'
        Copy-LogsBasedOnTime -LogPath $script:firstSource -CopyToThisLocation $script:destination -IncludeSubDirectory $true
        Get-Content -LiteralPath "$script:destination\Logs[2026]\current.log" | Should -Be 'literal child marker'
        Test-Path -LiteralPath "$lookalike\current.log" | Should -BeFalse
    }

    It 'qualifies a colliding filename from a bracketed source without resolving wildcards' {
        $source = Join-Path -Path $script:secondSource -ChildPath 'Logs[2026]'
        $lookalike = Join-Path -Path $script:secondSource -ChildPath 'Logs2'
        $null = New-Item -Path $source, $lookalike -ItemType Directory -Force
        Set-Content -LiteralPath "$script:firstSource\same.log" -Value 'first marker'
        Set-Content -LiteralPath "$source\same.log" -Value 'second marker'
        Set-Content -LiteralPath "$lookalike\same.log" -Value 'wrong marker'
        Copy-BulkItems -CopyToLocation $script:destination -ItemsToCopyLocation @("$script:firstSource\same.log", "$source\same.log") -WarningVariable copyWarnings -WarningAction SilentlyContinue
        $files = @(Get-ChildItem -LiteralPath $script:destination -File)
        $contents = @($files | ForEach-Object { Get-Content -LiteralPath $_.FullName })
        $files | Should -HaveCount 2
        $contents | Should -Contain 'first marker'
        $contents | Should -Contain 'second marker'
        $contents | Should -Not -Contain 'wrong marker'
        @($copyWarnings) | Should -HaveCount 0
    }
}

Describe 'Copy preflight isolates files while preserving the disk reserve' {
    BeforeEach {
        $script:sourceRoot = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $script:RootCopyToDirectory = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:sourceRoot -ItemType Directory
        $script:rotatingFile = Join-Path -Path $script:sourceRoot -ChildPath 'rotating.log'
        $script:readableFile = Join-Path -Path $script:sourceRoot -ChildPath 'readable.log'
        Set-Content -LiteralPath $script:rotatingFile -Value 'rotation control'
        Set-Content -LiteralPath $script:readableFile -Value 'surviving control'
        $script:FreeSpaceMinusCopiedAndCompressedGB = 100
        $script:CurrentFreeSpaceGB = 100
        $script:AdditionalFreeSpaceCushionGB = 10
        $script:TotalBytesSizeCopied = 0
    }

    It 'checks and accounts for both files using the real sizing code' {
        $expectedSize = (Get-Item -LiteralPath $script:rotatingFile).Length + (Get-Item -LiteralPath $script:readableFile).Length
        Copy-BulkItems -CopyToLocation $script:RootCopyToDirectory -ItemsToCopyLocation @($script:rotatingFile, $script:readableFile)
        @(Get-ChildItem -LiteralPath $script:RootCopyToDirectory -File) | Should -HaveCount 2
        $script:TotalBytesSizeCopied | Should -Be $expectedSize
        $script:FreeSpaceMinusCopiedAndCompressedGB | Should -Be (100 - $expectedSize / 1GB)
    }

    It 'does not charge a check-only preflight as a completed copy' {
        Test-FreeSpace -FilePaths @($script:rotatingFile) -CheckOnly | Should -BeTrue
        $script:TotalBytesSizeCopied | Should -Be 0
        $script:FreeSpaceMinusCopiedAndCompressedGB | Should -Be 100
    }

    It 'does not count a locked file as copied or consume its estimated capacity' {
        [System.IO.File]::WriteAllBytes($script:rotatingFile, (New-Object byte[] 1048576))
        [System.IO.File]::WriteAllBytes($script:readableFile, (New-Object byte[] 4096))
        $stream = [System.IO.File]::Open($script:rotatingFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            Copy-BulkItems -CopyToLocation $script:RootCopyToDirectory -ItemsToCopyLocation @($script:rotatingFile, $script:readableFile) -WarningVariable copyWarnings -WarningAction SilentlyContinue
            @($copyWarnings) | Should -HaveCount 1
            (Get-Item -LiteralPath "$script:RootCopyToDirectory\readable.log").Length | Should -Be 4096
            $script:TotalBytesSizeCopied | Should -Be 4096
            $script:FreeSpaceMinusCopiedAndCompressedGB | Should -Be (100 - 4096 / 1GB)
        } finally {
            $stream.Dispose()
        }
    }

    It 'removes an incomplete copy and charges only the successful neighbor' {
        Mock -CommandName Copy-Item -MockWith {
            param($LiteralPath, $Destination)
            if ($LiteralPath -eq $script:rotatingFile) {
                [System.IO.File]::WriteAllBytes($Destination, [byte[]]@(1, 2, 3))
                throw 'Copy interrupted after writing a partial file.'
            }
            [System.IO.File]::Copy($LiteralPath, $Destination)
            Get-Item -LiteralPath $Destination
        }
        $expectedBytes = (Get-Item -LiteralPath $script:readableFile).Length
        Copy-BulkItems -CopyToLocation $script:RootCopyToDirectory -ItemsToCopyLocation @($script:rotatingFile, $script:readableFile) -WarningVariable copyWarnings -WarningAction SilentlyContinue
        @($copyWarnings) | Should -HaveCount 1
        Test-Path -LiteralPath "$script:RootCopyToDirectory\rotating.log" | Should -BeFalse
        Test-Path -LiteralPath "$script:RootCopyToDirectory\readable.log" | Should -BeTrue
        $script:TotalBytesSizeCopied | Should -Be $expectedBytes
        $script:FreeSpaceMinusCopiedAndCompressedGB | Should -Be (100 - $expectedBytes / 1GB)
    }

    It 'stops and invalidates the capacity estimate if partial-copy cleanup fails' {
        Mock -CommandName Copy-Item -MockWith {
            param($Destination)
            [System.IO.File]::WriteAllBytes($Destination, [byte[]]@(1, 2, 3))
            throw 'Copy interrupted.'
        }
        Mock -CommandName Remove-Item -MockWith { throw 'Cleanup denied.' }
        Copy-BulkItems -CopyToLocation $script:RootCopyToDirectory -ItemsToCopyLocation @($script:rotatingFile, $script:readableFile) -WarningVariable copyWarnings -WarningAction SilentlyContinue
        @($copyWarnings) | Should -HaveCount 2
        ($copyWarnings -join ' ') | Should -Match 'incomplete copy'
        (Get-Item -LiteralPath "$script:RootCopyToDirectory\rotating.log").Length | Should -Be 3
        Test-Path -LiteralPath "$script:RootCopyToDirectory\readable.log" | Should -BeFalse
        $script:TotalBytesSizeCopied | Should -Be 0
        $script:FreeSpaceMinusCopiedAndCompressedGB | Should -Be 0
        Should -Invoke -CommandName Copy-Item -Times 1 -Exactly
    }

    It 'continues with a readable file when another rotates during sizing' {
        Mock -CommandName Test-Path -MockWith {
            param($LiteralPath)
            [System.IO.File]::Exists($LiteralPath) -or [System.IO.Directory]::Exists($LiteralPath)
        }
        Mock -CommandName Test-Path -ParameterFilter { $LiteralPath -eq $script:rotatingFile } -MockWith {
            Remove-Item -LiteralPath $script:rotatingFile -Force -ErrorAction SilentlyContinue
            return $true
        }
        $expectedSize = (Get-Item -LiteralPath $script:readableFile).Length
        Copy-BulkItems -CopyToLocation $script:RootCopyToDirectory -ItemsToCopyLocation @($script:rotatingFile, $script:readableFile) -WarningVariable copyWarnings -WarningAction SilentlyContinue
        [System.IO.File]::Exists([System.IO.Path]::Combine($script:RootCopyToDirectory, 'readable.log')) | Should -BeTrue
        [System.IO.File]::Exists([System.IO.Path]::Combine($script:RootCopyToDirectory, 'rotating.log')) | Should -BeFalse
        @($copyWarnings) | Should -HaveCount 1
        ($copyWarnings -join ' ') | Should -Match 'rotating\.log'
        $script:TotalBytesSizeCopied | Should -Be $expectedSize
    }

    It 'rejects copying when the actual disk has no space above the reserve' {
        $script:FreeSpaceMinusCopiedAndCompressedGB = 10
        $script:CurrentFreeSpaceGB = 10
        Mock -CommandName Get-FreeSpace -MockWith { 10 }
        Copy-BulkItems -CopyToLocation $script:RootCopyToDirectory -ItemsToCopyLocation @($script:rotatingFile, $script:readableFile)
        Test-Path -LiteralPath "$script:RootCopyToDirectory\rotating.log" | Should -BeFalse
        Test-Path -LiteralPath "$script:RootCopyToDirectory\readable.log" | Should -BeFalse
        Test-Path -LiteralPath "$script:RootCopyToDirectory\NotEnoughFreeSpace.txt" | Should -BeTrue
        $script:TotalBytesSizeCopied | Should -Be 0
        Should -Invoke -CommandName Get-FreeSpace -Times 1 -Exactly
    }

    It 'stops before a later file would consume the disk reserve' {
        $firstSize = (Get-Item -LiteralPath $script:rotatingFile).Length
        $secondSize = (Get-Item -LiteralPath $script:readableFile).Length
        $script:FreeSpaceMinusCopiedAndCompressedGB = 10 + $firstSize / 1GB + $secondSize / 2GB
        $script:CurrentFreeSpaceGB = $script:FreeSpaceMinusCopiedAndCompressedGB
        Mock -CommandName Get-FreeSpace -MockWith { 10 }
        Copy-BulkItems -CopyToLocation $script:RootCopyToDirectory -ItemsToCopyLocation @($script:rotatingFile, $script:readableFile)
        Test-Path -LiteralPath "$script:RootCopyToDirectory\rotating.log" | Should -BeTrue
        Test-Path -LiteralPath "$script:RootCopyToDirectory\readable.log" | Should -BeFalse
        Test-Path -LiteralPath "$script:RootCopyToDirectory\NotEnoughFreeSpace.txt" | Should -BeTrue
        $script:TotalBytesSizeCopied | Should -Be $firstSize
        Should -Invoke -CommandName Get-FreeSpace -Times 1 -Exactly
    }
}

Describe 'Full log copying uses the same per-file safeguards' {
    BeforeEach {
        $script:sourceRoot = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $script:RootCopyToDirectory = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:sourceRoot -ItemType Directory
        $script:rotatingFile = Join-Path -Path $script:sourceRoot -ChildPath 'rotating.log'
        $script:readableFile = Join-Path -Path $script:sourceRoot -ChildPath 'readable.log'
        Set-Content -LiteralPath $script:rotatingFile -Value 'rotation control'
        Set-Content -LiteralPath $script:readableFile -Value 'surviving control'
        $script:PassedInfo = $null
        $script:FreeSpaceMinusCopiedAndCompressedGB = 100
        $script:CurrentFreeSpaceGB = 100
        $script:AdditionalFreeSpaceCushionGB = 10
        $script:TotalBytesSizeCopied = 0
        Mock -CommandName Invoke-ZipFolder -MockWith {}
    }

    It 'copies all ages without requiring a collection window' {
        (Get-Item -LiteralPath $script:rotatingFile).LastWriteTime = (Get-Date).AddDays(-30)
        (Get-Item -LiteralPath $script:readableFile).LastWriteTime = (Get-Date).AddDays(-60)
        $expectedBytes = (Get-Item -LiteralPath $script:rotatingFile).Length + (Get-Item -LiteralPath $script:readableFile).Length
        Copy-FullLogFullPathRecurse -LogPath $script:sourceRoot -CopyToThisLocation $script:RootCopyToDirectory
        @(Get-ChildItem -LiteralPath $script:RootCopyToDirectory -File) | Should -HaveCount 2
        $script:TotalBytesSizeCopied | Should -Be $expectedBytes
        Should -Invoke -CommandName Invoke-ZipFolder -Times 1 -Exactly
    }

    It 'preserves readable siblings if a file rotates during size checking' {
        Mock -CommandName Test-Path -MockWith {
            param($LiteralPath)
            [System.IO.File]::Exists($LiteralPath) -or [System.IO.Directory]::Exists($LiteralPath)
        }
        Mock -CommandName Test-Path -ParameterFilter { $LiteralPath -eq $script:rotatingFile } -MockWith {
            Remove-Item -LiteralPath $script:rotatingFile -Force -ErrorAction SilentlyContinue
            return $true
        }
        $expectedBytes = (Get-Item -LiteralPath $script:readableFile).Length
        Copy-FullLogFullPathRecurse -LogPath $script:sourceRoot -CopyToThisLocation $script:RootCopyToDirectory -WarningVariable copyWarnings -WarningAction SilentlyContinue
        @($copyWarnings) | Should -HaveCount 1
        [System.IO.File]::Exists("$script:RootCopyToDirectory\readable.log") | Should -BeTrue
        $script:TotalBytesSizeCopied | Should -Be $expectedBytes
    }

    It 'does not charge a failed full-copy file or discard its readable neighbor' {
        $expectedBytes = (Get-Item -LiteralPath $script:readableFile).Length
        $stream = [System.IO.File]::Open($script:rotatingFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            Copy-FullLogFullPathRecurse -LogPath $script:sourceRoot -CopyToThisLocation $script:RootCopyToDirectory -WarningVariable copyWarnings -WarningAction SilentlyContinue
            @($copyWarnings) | Should -HaveCount 1
            Test-Path -LiteralPath "$script:RootCopyToDirectory\readable.log" | Should -BeTrue
            $script:TotalBytesSizeCopied | Should -Be $expectedBytes
            $script:FreeSpaceMinusCopiedAndCompressedGB | Should -Be (100 - $expectedBytes / 1GB)
        } finally {
            $stream.Dispose()
        }
    }

    It 'preserves full-copy hierarchy including empty and bracketed directories' {
        $null = New-Item -Path "$script:sourceRoot\First\Logs[2026]", "$script:sourceRoot\Second\Logs[2026]", "$script:sourceRoot\Empty" -ItemType Directory -Force
        Set-Content -LiteralPath "$script:sourceRoot\First\Logs[2026]\same.log" -Value 'first'
        Set-Content -LiteralPath "$script:sourceRoot\Second\Logs[2026]\same.log" -Value 'second'
        Copy-FullLogFullPathRecurse -LogPath $script:sourceRoot -CopyToThisLocation $script:RootCopyToDirectory
        Get-Content -LiteralPath "$script:RootCopyToDirectory\First\Logs[2026]\same.log" | Should -Be 'first'
        Get-Content -LiteralPath "$script:RootCopyToDirectory\Second\Logs[2026]\same.log" | Should -Be 'second'
        Test-Path -LiteralPath "$script:RootCopyToDirectory\Empty" -PathType Container | Should -BeTrue
    }

    It 'keeps the full-copy missing-directory diagnostic name' {
        Copy-FullLogFullPathRecurse -LogPath "$script:sourceRoot\missing" -CopyToThisLocation $script:RootCopyToDirectory
        Test-Path -LiteralPath "$script:RootCopyToDirectory\NoFolderDetected.txt" | Should -BeTrue
    }

    It 'keeps the full-copy empty-directory diagnostic name' {
        $emptySource = Join-Path -Path $script:sourceRoot -ChildPath 'empty'
        $null = New-Item -Path "$emptySource\nested" -ItemType Directory -Force
        Copy-FullLogFullPathRecurse -LogPath $emptySource -CopyToThisLocation $script:RootCopyToDirectory
        Test-Path -LiteralPath "$script:RootCopyToDirectory\NoDataDetected.txt" | Should -BeTrue
    }

    It 'does not report an unreadable full-copy directory as empty' {
        Mock -CommandName Get-ChildItem -ParameterFilter { $LiteralPath -eq $script:sourceRoot } -MockWith { throw 'Access denied.' }
        Copy-FullLogFullPathRecurse -LogPath $script:sourceRoot -CopyToThisLocation $script:RootCopyToDirectory -WarningVariable copyWarnings -WarningAction SilentlyContinue
        @($copyWarnings) | Should -HaveCount 1
        Test-Path -LiteralPath "$script:RootCopyToDirectory\NoDataDetected.txt" | Should -BeFalse
    }

    It 'still enforces the disk reserve when copying all logs' {
        $script:FreeSpaceMinusCopiedAndCompressedGB = 10
        $script:CurrentFreeSpaceGB = 10
        Mock -CommandName Get-FreeSpace -MockWith { 10 }
        Copy-FullLogFullPathRecurse -LogPath $script:sourceRoot -CopyToThisLocation $script:RootCopyToDirectory
        Test-Path -LiteralPath "$script:RootCopyToDirectory\NotEnoughFreeSpace.txt" | Should -BeTrue
        Test-Path -LiteralPath "$script:RootCopyToDirectory\readable.log" | Should -BeFalse
        $script:TotalBytesSizeCopied | Should -Be 0
    }
}
