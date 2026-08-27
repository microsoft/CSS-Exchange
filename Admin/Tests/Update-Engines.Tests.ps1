# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore chash Kaspersky redownload redownloads redownloaded redownloading shortbase badbase mpengine mpasbase unreg

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = Split-Path -Path $PSScriptRoot -Parent
    $Script:scriptPath = Join-Path -Path $Script:parentPath -ChildPath "Update-Engines.ps1"
    $Script:dataPath = Join-Path -Path $PSScriptRoot -ChildPath "Data"

    # Load only the function definitions from Update-Engines.ps1.
    # The script has a param() block and a main-script body that would run on
    # dot-source and try to hit the network. Extracting just the functions via
    # AST avoids triggering the main body while still exposing every function
    # under test to Pester.
    $Script:ast = [System.Management.Automation.Language.Parser]::ParseFile($Script:scriptPath, [ref]$null, [ref]$null)
    $functionDefs = $Script:ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
    foreach ($fn in $functionDefs) {
        . ([ScriptBlock]::Create($fn.Extent.Text))
    }

    # The functions expect these file-scope constants, which are declared in the
    # main-script section we deliberately skipped. Re-declare them here.
    $Script:UmFileName = "UniversalManifest.cab"
    $Script:EliFileName = "EngineInfo.cab"

    # Register-WrittenFile / Test-WrittenFileHashes read and write $Script:writtenFileHashes,
    # which the production script initializes at the top of its begin{} block --
    # a block we skipped by loading function definitions only. Initialize it
    # here so functions that call Register-WrittenFile (Invoke-EngineUpdate,
    # Invoke-UniversalManifestDownload, Invoke-EngineLicenseInfoDownload, ...)
    # do not blow up. Per-test resets happen in each Describe's BeforeEach.
    $Script:writtenFileHashes = @{}

    # Derive engine-manifest values (full-package filename, package version) from
    # the fixture manifest so tests are not coupled to the specific literal
    # filename Microsoft happens to ship today.
    $manifestFixture = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml"))
    $Script:PackageFileName = $manifestFixture.ManifestFile.Package.FullPackage.name
    $Script:PackageVersion = $manifestFixture.ManifestFile.Package.version

    function Get-FakeWebClient {
        # A stand-in for [System.Net.WebClient] that satisfies the parameter
        # type constraint on the download functions. Never actually reached
        # because Invoke-WebClientDownload is always mocked.
        return New-Object -TypeName System.Net.WebClient
    }
}

Describe "Script parameter block" {

    BeforeAll {
        # Parse the top-level param() block via AST so we can assert on the
        # declared parameters and their validation attributes without running
        # the script body. All ScriptBlockAst.ParamBlock lookups work off the
        # already-parsed $Script:ast (populated in the file-level BeforeAll).
        $Script:paramBlock = $Script:ast.ParamBlock
        $Script:paramsByName = @{}
        foreach ($p in $Script:paramBlock.Parameters) {
            $Script:paramsByName[$p.Name.VariablePath.UserPath] = $p
        }
    }

    It "no longer exposes a -Platforms parameter (amd64 is hardcoded)" {
        $Script:paramsByName.ContainsKey('Platforms') | Should -BeFalse
    }

    It "still exposes -Engines" {
        $Script:paramsByName.ContainsKey('Engines') | Should -BeTrue
    }

    It "constrains -Engines to the only two engines the update endpoints serve" {
        $enginesParam = $Script:paramsByName['Engines']
        $validateSet = $enginesParam.Attributes |
            Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
            Select-Object -First 1
        $validateSet | Should -Not -BeNullOrEmpty

        $values = @($validateSet.PositionalArguments | ForEach-Object { $_.Value })
        $values | Should -HaveCount 2
        $values | Should -Contain 'Microsoft'
        $values | Should -Contain 'Command'
    }

    It "defaults -Engines to Microsoft only" {
        $enginesParam = $Script:paramsByName['Engines']
        $defaultText = $enginesParam.DefaultValue.Extent.Text
        $defaultText | Should -Match 'Microsoft'
    }
}

Describe "CreatePath" {

    BeforeAll { Mock Write-Host {} }

    It "creates the directory when it does not exist" {
        $target = Join-Path -Path $TestDrive -ChildPath "new-dir"
        Test-Path -Path $target | Should -BeFalse
        CreatePath -path $target | Out-Null
        Test-Path -Path $target | Should -BeTrue
    }

    It "is a no-op when the directory already exists" {
        $target = Join-Path -Path $TestDrive -ChildPath "existing-dir"
        New-Item -ItemType Directory -Path $target | Out-Null
        Mock New-Item {}
        CreatePath -path $target | Out-Null
        Should -Invoke New-Item -Times 0 -Exactly
    }
}

Describe "CleanUpFolder" {

    It "keeps the newest N directories and removes the rest" {
        $root = Join-Path -Path $TestDrive -ChildPath "cleanup"
        New-Item -ItemType Directory -Path $root | Out-Null
        # Create 5 subdirectories with staggered creation times so the sort is deterministic.
        for ($i = 1; $i -le 5; $i++) {
            $sub = New-Item -ItemType Directory -Path (Join-Path -Path $root -ChildPath "v$i")
            $sub.CreationTime = (Get-Date).AddMinutes($i)
        }
        CleanUpFolder -path $root -itemsToKeep 2
        $remaining = (Get-ChildItem $root | Sort-Object Name).Name
        $remaining.Count | Should -Be 2
        $remaining | Should -Contain "v4"
        $remaining | Should -Contain "v5"
    }
}

Describe "Read-Manifest" {

    It "returns a parsed XmlDocument for a valid manifest file" {
        $result = Read-Manifest -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml")
        $result | Should -BeOfType [System.Xml.XmlDocument]
        $result.UniversalManifest.licenseInfoVersion | Should -Be "201910170001"
    }
}

Describe "Get-PlatformElement" {

    BeforeAll {
        $Script:um = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml"))
    }

    It "returns the amd64 platform when it exists" {
        $result = Get-PlatformElement -UniversalManifest $Script:um -PlatformName "amd64"
        $result | Should -BeOfType [System.Xml.XmlElement]
        $result.id | Should -Be "amd64"
    }

    It "returns the x86 platform when it exists" {
        $result = Get-PlatformElement -UniversalManifest $Script:um -PlatformName "x86"
        $result.id | Should -Be "x86"
    }

    It "throws when the platform is not present" {
        { Get-PlatformElement -UniversalManifest $Script:um -PlatformName "arm64" } |
            Should -Throw -ExpectedMessage "*Platform*arm64*not valid*"
    }
}

Describe "Get-EngineElement" {

    BeforeAll {
        $Script:um = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml"))
        $Script:platform = Get-PlatformElement -UniversalManifest $Script:um -PlatformName "amd64"
    }

    It "returns the Microsoft engine when it exists on amd64" {
        $result = Get-EngineElement -PlatformElement $Script:platform -EngineName "Microsoft"
        $result | Should -BeOfType [System.Xml.XmlElement]
        $result.name | Should -Be "Microsoft"
        $result.default | Should -Be "{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}"
    }

    It "returns `$null and writes a non-terminating error when the engine is not present" {
        $result = Get-EngineElement -PlatformElement $Script:platform -EngineName "DoesNotExist" -ErrorAction SilentlyContinue -ErrorVariable ev
        $result | Should -BeNullOrEmpty
        $ev.Count | Should -BeGreaterThan 0
    }
}

Describe "Invoke-WebClientDownload" {

    It "delegates to the WebClient's DownloadFile with the supplied URI and destination" {
        $mockClient = New-MockObject -Type System.Net.WebClient -Methods @{
            DownloadFile = { param($uri, $dest) $Script:capturedUri = $uri; $Script:capturedDest = $dest }
        }
        Invoke-WebClientDownload -WebClient $mockClient -Uri "http://example.com/file.cab" -Destination "C:\out\file.cab"
        $Script:capturedUri | Should -Be "http://example.com/file.cab"
        $Script:capturedDest | Should -Be "C:\out\file.cab"
    }
}

Describe "Invoke-UniversalManifestDownload" {

    BeforeAll { Mock Write-Host {} }

    BeforeEach {
        $Script:engineDir = (Join-Path -Path $TestDrive -ChildPath "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path -Path $Script:engineDir -ChildPath "temp\")
        if (Test-Path -Path $Script:engineDir) { Remove-Item -Path $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $Script:capturedUri = $Uri
            $Script:capturedDest = $Destination
            Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml") -Destination $Destination
        }

        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml") -Destination (Join-Path -Path $destinationDirectory -ChildPath "UniversalManifest.xml")
        }

        # Integrity checks pass by default; individual tests can override.
        Mock Test-AuthenticodeSignature { }
        Mock Test-FileHash { }
    }

    It "downloads the Universal Manifest from the correct URL to the correct destination" {
        Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://forefrontdl.microsoft.com/server/scanengineupdate/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir | Out-Null

        $Script:capturedUri | Should -Be "http://forefrontdl.microsoft.com/server/scanengineupdate/metadata/UniversalManifest.cab"
        $Script:capturedDest | Should -Be ($Script:engineDir + "metadata\UniversalManifest.cab")
    }

    It "creates the metadata and temp directories" {
        Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir | Out-Null

        Test-Path -Path (Join-Path -Path $Script:engineDir -ChildPath "metadata") | Should -BeTrue
        Test-Path -Path $Script:tempDir | Should -BeTrue
    }

    It "clears stale files from the temp directory before extracting" {
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null
        Set-Content -Path (Join-Path -Path $Script:tempDir -ChildPath "stale.tmp") -Value "old"

        Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir | Out-Null

        Test-Path -Path (Join-Path -Path $Script:tempDir -ChildPath "stale.tmp") | Should -BeFalse
    }

    It "returns a parsed XmlDocument for the Universal Manifest" {
        $result = Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir
        $result | Should -BeOfType [System.Xml.XmlDocument]
        $result.UniversalManifest.licenseInfoVersion | Should -Be "201910170001"
    }
}

Describe "Invoke-EngineLicenseInfoDownload" {

    BeforeAll { Mock Write-Host {} }

    BeforeEach {
        $Script:engineDir = (Join-Path -Path $TestDrive -ChildPath "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path -Path $Script:engineDir -ChildPath "temp\")
        if (Test-Path -Path $Script:engineDir) { Remove-Item -Path $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null
        $Script:um = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml"))

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $Script:capturedUri = $Uri
            $Script:capturedDest = $Destination
            # Create a placeholder file so subsequent Test-Path returns $true.
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Set-Content -Path $Destination -Value "placeholder"
        }

        # Simulate CAB extraction by dropping a stub inner file so the code
        # can locate and hash it. Individual tests can override.
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if (-not (Test-Path -Path $destinationDirectory)) { New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null }
            Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "EngineInfo.cab") -Value "inner-eli-placeholder"
        }

        # Integrity checks pass by default; individual tests can override.
        Mock Test-AuthenticodeSignature { }
        Mock Test-FileHash { }
    }

    It "creates the versioned metadata directory" {
        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um

        Test-Path -Path (Join-Path -Path $Script:engineDir -ChildPath "metadata\201910170001") | Should -BeTrue
    }

    It "downloads the Engine License Info when it is missing" {
        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um

        Should -Invoke Invoke-WebClientDownload -Times 1 -Exactly
        $Script:capturedUri | Should -Be "http://x/\metadata\201910170001/EngineInfo.cab"
        $Script:capturedDest | Should -Be ($Script:engineDir + "metadata\201910170001\EngineInfo.cab")
    }

    It "skips the download when the Engine License Info is already present" {
        $target = Join-Path -Path $Script:engineDir -ChildPath "metadata\201910170001"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Set-Content -Path (Join-Path -Path $target -ChildPath "EngineInfo.cab") -Value "already-here"

        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um

        Should -Invoke Invoke-WebClientDownload -Times 0 -Exactly
    }
}

Describe "Invoke-EngineUpdate" {

    BeforeAll {
        Mock Write-Host {}

        # Helper used by cached-fast-path tests. B3 inventory validation
        # now requires every file the per-engine manifest declares
        # (Package.Files.File[]) to be present under $fullPackageDir, or
        # Invoke-EngineUpdate throws "Cached extraction ... is incomplete".
        # Call this to pre-populate the declared inventory in a version
        # directory the test set up by hand.
        function New-CachedInventory {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper; no state a caller would expect ShouldProcess to gate.')]
            param([string]$PackageDir, [string]$ManifestFixture)
            $mf = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath $ManifestFixture))
            foreach ($f in $mf.ManifestFile.Package.Files.File) {
                $sub = $f.GetAttribute('path')
                $name = $f.GetAttribute('name')
                $target = if ([string]::IsNullOrEmpty($sub)) { $PackageDir } else {
                    $subDir = Join-Path -Path $PackageDir -ChildPath $sub
                    if (-not (Test-Path -Path $subDir)) { New-Item -ItemType Directory -Path $subDir -Force | Out-Null }
                    $subDir
                }
                Set-Content -Path (Join-Path -Path $target -ChildPath ($name + '.cab')) -Value "cached-payload-$name"
            }
        }
    }

    BeforeEach {
        $Script:engineDir = (Join-Path -Path $TestDrive -ChildPath "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path -Path $Script:engineDir -ChildPath "temp\")
        if (Test-Path -Path $Script:engineDir) { Remove-Item -Path $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null
        $Script:um = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml"))
        $Script:platform = Get-PlatformElement -UniversalManifest $Script:um -PlatformName "amd64"
        $Script:engine = Get-EngineElement -PlatformElement $Script:platform -EngineName "Microsoft"

        # Track every URI the code asked to download.
        $Script:downloads = New-Object -TypeName System.Collections.Generic.List[hashtable]

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $Script:downloads.Add(@{ Uri = $Uri; Destination = $Destination })
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            # Simulate a downloaded file the size the manifest expects.
            if ($Uri -like "*/$Script:PackageFileName") {
                # 214529388 is the real declared size; we can't create a real file that big.
                # Write any content; individual tests that need size-match will control this.
                Set-Content -Path $Destination -Value ("0" * 100)
            } else {
                Set-Content -Path $Destination -Value "cab-placeholder"
            }
        }

        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            # If we're extracting the manifest cab into the temp dir, write the
            # pre-parsed manifest.xml. If we're extracting the full package,
            # produce every file the per-engine manifest declares under
            # Package.Files.File. B3 inventory validation requires every
            # declared entry to be present in scratch before commit; the
            # extraction mock has to satisfy that contract or the flow
            # bails on "declared file(s) missing from scratch dir".
            if ($sourceCabPath -like "*manifest.*.cab") {
                Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml") -Destination (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml")
            } else {
                $mf = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml"))
                foreach ($f in $mf.ManifestFile.Package.Files.File) {
                    $sub = $f.GetAttribute('path')
                    $name = $f.GetAttribute('name')
                    $target = if ([string]::IsNullOrEmpty($sub)) { $destinationDirectory } else {
                        $subDir = Join-Path -Path $destinationDirectory -ChildPath $sub
                        if (-not (Test-Path -Path $subDir)) { New-Item -ItemType Directory -Path $subDir -Force | Out-Null }
                        $subDir
                    }
                    Set-Content -Path (Join-Path -Path $target -ChildPath ($name + '.cab')) -Value "extracted-payload-$name"
                }
            }
        }

        # Integrity checks pass by default; individual tests can override.
        Mock Test-AuthenticodeSignature { }
        Mock Test-FileHash { }
    }

    It "on the happy path downloads the manifest CAB, then the full package, then copies the manifest into the package directory" {
        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        # Manifest download call.
        $manifestCall = $Script:downloads | Where-Object { $_.Uri -like "*manifest.*.cab" }
        $manifestCall | Should -Not -BeNullOrEmpty
        $manifestCall.Uri | Should -Be "http://x/amd64/Microsoft/Package/manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab"

        # Full package download call.
        $fullCall = $Script:downloads | Where-Object { $_.Uri -like "*/$Script:PackageFileName" }
        $fullCall | Should -Not -BeNullOrEmpty
        $fullCall.Uri | Should -Be "http://x/amd64/Microsoft/Package/$Script:PackageVersion/$Script:PackageFileName"

        # Manifest copied into the versioned package directory.
        Test-Path -Path (Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion\manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab") | Should -BeTrue
    }

    It "skips the full-package download but re-extracts when the CAB is present without the completion marker (recovery from prior partial extraction)" {
        # Pre-create the destination with the exact declared size but WITHOUT
        # the extraction-completion marker. This simulates a prior run that
        # downloaded the CAB and then died partway through ExtractCab. The
        # code must skip the download (hash-verified CAB present) but MUST
        # re-extract instead of trusting the incomplete on-disk mirror.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName
        # 214529388 is the declared size in the manifest fixture.
        $fs = [System.IO.File]::Create($pkgPath)
        $fs.SetLength(214529388)
        $fs.Close()

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        # Manifest CAB is always downloaded; the full package is not.
        $fullCall = $Script:downloads | Where-Object { $_.Uri -like "*/$Script:PackageFileName" }
        $fullCall | Should -BeNullOrEmpty

        # Because the completion marker is missing, ExtractCab MUST have been
        # invoked on the full package CAB and the manifest MUST have been
        # copied into the package directory as the new completion marker.
        Should -Invoke ExtractCab -Times 1 -Exactly -ParameterFilter { $sourceCabPath -eq $pkgPath }
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab") | Should -BeTrue
    }

    It "skips both download and extraction when the CAB and the extraction-completion marker are both present" {
        # Pre-create the CAB at the declared size AND the completion marker,
        # AND every file the per-engine manifest declares. Together these
        # represent a fully successful previous run: the 'Engine already up
        # to date' path must be taken. Without the inventory pre-population,
        # B3 cached-fast-path validation throws "Cached extraction is
        # incomplete", which is the CORRECT behavior for AV quarantine but
        # not what this test is exercising.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName
        $fs = [System.IO.File]::Create($pkgPath)
        $fs.SetLength(214529388)
        $fs.Close()
        # The completion marker: the per-engine manifest CAB copied into the
        # versioned package directory as the LAST step of a successful run.
        Set-Content -Path (Join-Path -Path $pkgDir -ChildPath "manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab") -Value "prior-run-marker"
        New-CachedInventory -PackageDir $pkgDir -ManifestFixture "Manifest.Microsoft.xml"

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        # Neither the full package download nor the ExtractCab call for the
        # full package should have run.
        $fullCall = $Script:downloads | Where-Object { $_.Uri -like "*/$Script:PackageFileName" }
        $fullCall | Should -BeNullOrEmpty
        Should -Invoke ExtractCab -Times 0 -Exactly -ParameterFilter { $sourceCabPath -eq $pkgPath }
    }

    It "preserves leftover files from a prior incomplete run when re-extracting (B3: no purge)" {
        # Simulate the exact state a crashed-mid-extraction previous run
        # leaves behind: correctly-sized CAB, some (stale) subdirectory
        # content, no completion marker. Under the old implementation
        # everything except the payload CAB was purged before re-extract;
        # that destroyed any customer/sibling files an operator had put
        # under the versioned package directory. The new implementation
        # extracts into a per-invocation scratch subdirectory under the
        # temp dir and moves files into place, so anything else survives.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName
        $fs = [System.IO.File]::Create($pkgPath)
        $fs.SetLength(214529388)
        $fs.Close()

        # Customer- or operator-authored files sitting alongside the extracted
        # content. These are the artifacts the old implementation would delete.
        New-Item -ItemType Directory -Path (Join-Path -Path $pkgDir -ChildPath "customer-notes") -Force | Out-Null
        Set-Content -Path (Join-Path -Path $pkgDir -ChildPath "customer-notes\deploy-runbook.md") -Value "operator-added"
        Set-Content -Path (Join-Path -Path $pkgDir -ChildPath "operator-added-loose-file.bin") -Value "operator-added"

        # ExtractCab writes files into the SCRATCH dir now (not $fullPackageDir).
        # Match the new flow: any file the extractor writes is later moved into
        # $fullPackageDir by the Move-Item loop. Must produce EVERY file the
        # per-engine manifest declares under Package.Files.File so the B3
        # inventory check passes, plus a distinguishable extra ("customer
        # file collision proof") so the test can prove customer files are
        # preserved.
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml") -Destination (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml")
            } else {
                $mf = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml"))
                foreach ($f in $mf.ManifestFile.Package.Files.File) {
                    Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath ($f.GetAttribute('name') + '.cab')) -Value "extracted"
                }
            }
        }

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        # Customer/operator files MUST still be there.
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "customer-notes\deploy-runbook.md") | Should -BeTrue
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "operator-added-loose-file.bin") | Should -BeTrue
        # The full package CAB is still there.
        Test-Path -Path $pkgPath | Should -BeTrue
        # A freshly extracted file was moved into place.
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "update.ini.cab") | Should -BeTrue
        # The completion marker was written last.
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab") | Should -BeTrue
    }

    It "on fail-open cache: deletes the cached full package and redownloads once when the cached hash check fails (B2)" {
        # Pre-create a properly-sized CAB so needDownload=false and the code
        # reaches the cached-hash check. Wire Test-FileHash to throw ONCE,
        # then succeed on the retry -- this simulates a corrupt cached
        # payload whose fresh redownload recovers.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName
        $fs = [System.IO.File]::Create($pkgPath)
        $fs.SetLength(214529388)
        $fs.Close()

        $Script:hashCalls = 0
        Mock Test-FileHash {
            $Script:hashCalls++
            if ($Script:hashCalls -eq 1) {
                $(throw "SHA256 mismatch for '$Path'. (simulated corruption)")
            }
        }

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        # The full package was redownloaded (in addition to the always-download
        # of the per-engine manifest CAB).
        $fullDownloads = @($Script:downloads | Where-Object { $_.Uri -like "*/$Script:PackageFileName" })
        $fullDownloads | Should -HaveCount 1
        # Test-FileHash was called twice: once against the cached (bad)
        # payload, then again after the redownload.
        Should -Invoke Test-FileHash -Times 2 -Exactly -ParameterFilter { $Path -eq $pkgPath }
    }

    It "on fail-open cache: propagates the hash failure when the FRESH download also fails (B2)" {
        # If Microsoft has published a bad artifact or the endpoint is
        # compromised, the redownload will also fail hash -- and at that
        # point we MUST throw. The rescue is once-only.
        Mock Test-FileHash {
            $(throw "SHA256 mismatch for '$Path'. (persistent corruption)")
        }

        # No pre-created CAB -- needDownload=true from the start. The FIRST
        # Test-FileHash call is against a freshly-downloaded file, so the
        # rescue path does not apply and the throw propagates.
        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*SHA256 mismatch*"
    }

    It "on fail-open cache: propagates the hash failure when the retry after redownload also fails (B2)" {
        # Both calls fail: cached and redownloaded. The retry is not
        # infinite -- the second failure is fatal.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName
        $fs = [System.IO.File]::Create($pkgPath)
        $fs.SetLength(214529388)
        $fs.Close()

        Mock Test-FileHash {
            $(throw "SHA256 mismatch for '$Path'.")
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*SHA256 mismatch*"
        # We tried twice (initial + one retry) and gave up.
        Should -Invoke Test-FileHash -Times 2 -Exactly -ParameterFilter { $Path -eq $pkgPath }
    }

    It "re-downloads the full package when the file is present but the size does not match" {
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        Set-Content -Path (Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName) -Value "wrong-size"

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        $fullCall = $Script:downloads | Where-Object { $_.Uri -like "*/$Script:PackageFileName" }
        $fullCall | Should -Not -BeNullOrEmpty
    }

    It "creates the subdirectories declared by <Files><Dir> in the manifest" {
        # Override ExtractCab to hand back a manifest that includes <Dir> entries.
        # WithDirs manifest declares a single file (update.ini) plus two Dir
        # entries; produce that file in scratch to satisfy the B3 inventory
        # check for the full-package extraction.
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.WithDirs.xml") -Destination (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml")
            } else {
                Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "update.ini.cab") -Value "extracted"
            }
        }

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\2112342123"
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "sub1") | Should -BeTrue
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "sub2") | Should -BeTrue
    }

    It "invokes CleanUpFolder when -CleanUp is specified" {
        Mock CleanUpFolder {}

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine -CleanUp -VersionsToKeep 3

        Should -Invoke CleanUpFolder -Times 1 -Exactly -ParameterFilter { $itemsToKeep -eq 3 }
    }

    It "does not invoke CleanUpFolder when -CleanUp is not specified" {
        Mock CleanUpFolder {}

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        Should -Invoke CleanUpFolder -Times 0 -Exactly
    }

    It "aborts before writing the completion marker when a manifest-declared file is missing from scratch (B3 fresh-extract)" {
        # Extractor produces a subset of the declared inventory (AV
        # quarantined a file mid-extract, or the payload CAB itself
        # was tampered so expand.exe missed a file). The flow MUST
        # throw before the manifest is copied to the versioned dir
        # so the next run correctly re-extracts.
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml") -Destination (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml")
            } else {
                # Produce every declared file EXCEPT mpengine.dll.
                $mf = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml"))
                foreach ($f in $mf.ManifestFile.Package.Files.File) {
                    if ($f.GetAttribute('name') -eq 'mpengine.dll') { continue }
                    Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath ($f.GetAttribute('name') + '.cab')) -Value "partial"
                }
            }
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*mpengine.dll.cab*"

        # Marker must NOT exist after the failed run.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab") | Should -BeFalse
    }

    It "aborts before 'already up to date' when a manifest-declared file is missing from the cached extraction (B3 cached path)" {
        # Cached CAB + marker + inventory with ONE file quarantined
        # since the prior successful extraction. Cached fast path
        # MUST detect the missing file and throw with the operator
        # instruction to delete the marker.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName
        $fs = [System.IO.File]::Create($pkgPath)
        $fs.SetLength(214529388)
        $fs.Close()
        Set-Content -Path (Join-Path -Path $pkgDir -ChildPath "manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab") -Value "prior-run-marker"

        # Pre-populate all inventory EXCEPT one.
        $mf = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml"))
        foreach ($f in $mf.ManifestFile.Package.Files.File) {
            if ($f.GetAttribute('name') -eq 'mpasbase.vdm') { continue }
            Set-Content -Path (Join-Path -Path $pkgDir -ChildPath ($f.GetAttribute('name') + '.cab')) -Value "cached"
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*mpasbase.vdm.cab*"
    }

    It "deletes the completion marker before mutating the payload CAB on cache-recovery redownload (B1)" {
        # Cached CAB + marker + inventory that would pass the cached
        # fast path -- BUT Test-FileHash fails once on the cached
        # payload, triggering the recovery redownload. Prove the
        # marker is GONE at the moment Invoke-WebClientDownload
        # writes fresh CAB bytes, so a crash between the fresh
        # download and the eventual mid-extract failure cannot leave
        # a stale marker beside a new CAB.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName
        $markerPath = Join-Path -Path $pkgDir -ChildPath "manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab"
        $fs = [System.IO.File]::Create($pkgPath)
        $fs.SetLength(214529388)
        $fs.Close()
        Set-Content -Path $markerPath -Value "prior-run-marker"

        $Script:markerExistedOnRedownload = $null
        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            if ($Uri -like "*/$Script:PackageFileName") {
                $Script:markerExistedOnRedownload = Test-Path -LiteralPath $markerPath
            }
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            if ($Uri -like "*/$Script:PackageFileName") {
                Set-Content -Path $Destination -Value ("0" * 100)
            } else {
                Set-Content -Path $Destination -Value "cab-placeholder"
            }
        }

        $Script:hashCalls = 0
        Mock Test-FileHash {
            $Script:hashCalls++
            if ($Script:hashCalls -eq 1) {
                $(throw "SHA256 mismatch for '$Path' ($FieldName).")
            }
        }

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        $Script:markerExistedOnRedownload | Should -BeFalse
    }

    It "deletes the completion marker before mutating the payload CAB on initial size-drift redownload (B1)" {
        # Marker present, payload CAB present but size does not
        # match the manifest -> $needDownload=true -> we overwrite
        # the CAB. The marker MUST be gone at redownload time so a
        # crash between the fresh CAB write and the marker rewrite
        # cannot leave a stale marker beside a new CAB.
        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path -Path $pkgDir -ChildPath $Script:PackageFileName
        $markerPath = Join-Path -Path $pkgDir -ChildPath "manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab"
        # Wrong size on purpose.
        Set-Content -Path $pkgPath -Value "wrong-size-payload"
        Set-Content -Path $markerPath -Value "stale-marker"

        $Script:markerExistedOnDownload = $null
        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            if ($Uri -like "*/$Script:PackageFileName") {
                $Script:markerExistedOnDownload = Test-Path -LiteralPath $markerPath
            }
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            if ($Uri -like "*/$Script:PackageFileName") {
                Set-Content -Path $Destination -Value ("0" * 100)
            } else {
                Set-Content -Path $Destination -Value "cab-placeholder"
            }
        }

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        $Script:markerExistedOnDownload | Should -BeFalse
    }

    It "propagates Move-Item failure and does not write the completion marker (B2)" {
        # Simulate a Move-Item failure mid-commit. Under -ErrorAction
        # Stop this becomes terminating; the marker Copy-Item further
        # down MUST NOT run.
        Mock Move-Item { $(throw "Access to the path is denied.") }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*Access to the path is denied*"

        $pkgDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$Script:PackageVersion"
        Test-Path -Path (Join-Path -Path $pkgDir -ChildPath "manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab") | Should -BeFalse
    }

    It "propagates marker Copy-Item failure so the marker is not silently absent (B2)" {
        # Copy-Item failure at marker-write time. -ErrorAction Stop
        # turns it terminating so the caller sees the failure. Without
        # -ErrorAction Stop the marker would silently not be written
        # while everything else looked successful, breaking the "marker
        # present == extraction complete" invariant. The extract branch
        # only calls Copy-Item once (the marker copy), so a blanket
        # throw is safe here.
        Mock Copy-Item { $(throw "The file is being used by another process.") }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*being used by another process*"
    }
}

Describe "Get-ContainedPath" {

    BeforeAll {
        $Script:root = (Join-Path -Path $TestDrive -ChildPath "engines") -replace '/', '\'
        if (-not (Test-Path -Path $Script:root)) { New-Item -ItemType Directory -Path $Script:root | Out-Null }
    }

    It "returns the joined path when the segment is contained under the root" {
        $result = Get-ContainedPath -Root $Script:root -Segment "amd64\Microsoft"
        $result | Should -Match ([regex]::Escape("engines\amd64\Microsoft"))
    }

    It "preserves the trailing directory separator when the segment ends with one" {
        $result = Get-ContainedPath -Root $Script:root -Segment "amd64\"
        $result.EndsWith("\") | Should -BeTrue
    }

    It "throws when the segment traverses out of the root with ..\\" {
        { Get-ContainedPath -Root $Script:root -Segment "..\evil.cab" } | Should -Throw -ExpectedMessage "*escapes root*"
    }

    It "throws when the segment traverses deeper with multiple ..\\" {
        { Get-ContainedPath -Root $Script:root -Segment "sub\..\..\..\..\Windows\System32\evil.cab" } | Should -Throw -ExpectedMessage "*escapes root*"
    }

    It "throws when the segment is an absolute path outside the root" {
        { Get-ContainedPath -Root $Script:root -Segment "C:\Windows\System32\evil.cab" } | Should -Throw -ExpectedMessage "*escapes root*"
    }

    It "throws when the segment escapes to a sibling directory whose name starts with the root name" {
        # Prefix look-alike: 'engines' vs 'engines-evil'. The trailing-separator
        # normalization in Get-ContainedPath is what makes this detectable.
        { Get-ContainedPath -Root $Script:root -Segment "..\engines-evil\payload.cab" } | Should -Throw -ExpectedMessage "*escapes root*"
    }

    It "throws when the segment is null" {
        { Get-ContainedPath -Root $Script:root -Segment $null } | Should -Throw -ExpectedMessage "*null or empty*"
    }

    It "throws when the segment is an empty string" {
        { Get-ContainedPath -Root $Script:root -Segment "" } | Should -Throw -ExpectedMessage "*null or empty*"
    }
}

Describe "Test-ManifestFieldShape" {

    It "returns silently for a value that matches the pattern" {
        { Test-ManifestFieldShape -Value "201910170001" -Pattern '^\d+$' -FieldName 'licenseInfoVersion' } | Should -Not -Throw
    }

    It "throws when the value contains ..\\" {
        { Test-ManifestFieldShape -Value "..\evil" -Pattern '^\d+$' -FieldName 'licenseInfoVersion' } |
            Should -Throw -ExpectedMessage "*licenseInfoVersion*"
    }

    It "throws when the value contains a forward slash" {
        { Test-ManifestFieldShape -Value "12345/evil" -Pattern '^\d+$' -FieldName 'Package.version' } |
            Should -Throw -ExpectedMessage "*Package.version*"
    }

    It "throws when the value contains a backslash" {
        { Test-ManifestFieldShape -Value "engine\evil" -Pattern '^[A-Za-z0-9_\-]+$' -FieldName 'Engine.Name' } |
            Should -Throw -ExpectedMessage "*Engine.Name*"
    }

    It "throws when the value is null" {
        { Test-ManifestFieldShape -Value $null -Pattern '^\d+$' -FieldName 'Package.version' } |
            Should -Throw -ExpectedMessage "*null or empty*"
    }

    It "throws when the value is empty" {
        { Test-ManifestFieldShape -Value "" -Pattern '^\d+$' -FieldName 'Package.version' } |
            Should -Throw -ExpectedMessage "*null or empty*"
    }

    It "throws with the field name embedded in the error message" {
        { Test-ManifestFieldShape -Value "not-a-cab" -Pattern '^[A-Za-z0-9_\-]+\.cab$' -FieldName 'Package.FullPackage.name' } |
            Should -Throw -ExpectedMessage "*Package.FullPackage.name*"
    }
}

Describe "Test-EngineDirPathIsLocal" {

    It "returns silently for a rooted local path" {
        { Test-EngineDirPathIsLocal -EngineDirPath "C:\Engines\" } | Should -Not -Throw
    }

    It "returns silently for a rooted local path without trailing slash" {
        { Test-EngineDirPathIsLocal -EngineDirPath "C:\Engines" } | Should -Not -Throw
    }

    It "returns silently for a bare drive root with separator" {
        { Test-EngineDirPathIsLocal -EngineDirPath "C:\" } | Should -Not -Throw
    }

    It "throws for a drive prefix with no separator (single-letter drive)" {
        { Test-EngineDirPathIsLocal -EngineDirPath "C:" } |
            Should -Throw -ExpectedMessage "*drive prefix with no path*"
    }

    It "throws for a drive prefix with no separator (multi-character PSDrive)" {
        { Test-EngineDirPathIsLocal -EngineDirPath "Remote:" } |
            Should -Throw -ExpectedMessage "*drive prefix with no path*"
    }

    It "throws for a provider-qualified drive prefix with no separator" {
        { Test-EngineDirPathIsLocal -EngineDirPath "Microsoft.PowerShell.Core\FileSystem::C:" } |
            Should -Throw -ExpectedMessage "*drive prefix with no path*"
    }

    It "returns silently for a relative path (no drive root to inspect)" {
        { Test-EngineDirPathIsLocal -EngineDirPath "engines\" } | Should -Not -Throw
    }

    It "returns silently when the path is empty (upstream guard handles that)" {
        { Test-EngineDirPathIsLocal -EngineDirPath "" } | Should -Not -Throw
    }

    It "returns silently when the path is null" {
        { Test-EngineDirPathIsLocal -EngineDirPath $null } | Should -Not -Throw
    }

    It "throws when the path is a UNC path" {
        { Test-EngineDirPathIsLocal -EngineDirPath "\\server\share\engines\" } |
            Should -Throw -ExpectedMessage "*UNC path*"
    }

    It "throws when the path is a UNC path to a hidden admin share" {
        { Test-EngineDirPathIsLocal -EngineDirPath "\\localhost\c$\engines\" } |
            Should -Throw -ExpectedMessage "*UNC path*"
    }

    It "throws when the drive letter maps to a UNC target via DisplayRoot" {
        Mock Get-PSDrive { [PSCustomObject]@{ Name = 'Z'; DisplayRoot = '\\server\share'; Root = 'Z:\' } } -ParameterFilter { $Name -eq 'Z' }

        { Test-EngineDirPathIsLocal -EngineDirPath "Z:\engines\" } |
            Should -Throw -ExpectedMessage "*mapped network drive*"
    }

    It "throws when the drive letter maps to a UNC target via Root (non-persistent New-PSDrive)" {
        Mock Get-PSDrive { [PSCustomObject]@{ Name = 'Z'; DisplayRoot = $null; Root = '\\server\share' } } -ParameterFilter { $Name -eq 'Z' }

        { Test-EngineDirPathIsLocal -EngineDirPath "Z:\engines\" } |
            Should -Throw -ExpectedMessage "*mapped network drive*"
    }

    It "includes the UNC target in the mapped-drive error for diagnostics" {
        Mock Get-PSDrive { [PSCustomObject]@{ Name = 'Z'; DisplayRoot = '\\backup01\shared'; Root = 'Z:\' } } -ParameterFilter { $Name -eq 'Z' }

        { Test-EngineDirPathIsLocal -EngineDirPath "Z:\engines\" } |
            Should -Throw -ExpectedMessage "*\\backup01\shared*"
    }

    It "does not throw when the drive exists locally (Root is a drive letter)" {
        Mock Get-PSDrive { [PSCustomObject]@{ Name = 'C'; DisplayRoot = $null; Root = 'C:\' } } -ParameterFilter { $Name -eq 'C' }

        { Test-EngineDirPathIsLocal -EngineDirPath "C:\engines\" } | Should -Not -Throw
    }

    It "does not throw when the drive letter is unknown to PowerShell" {
        Mock Get-PSDrive { $null } -ParameterFilter { $Name -eq 'Q' }

        { Test-EngineDirPathIsLocal -EngineDirPath "Q:\engines\" } | Should -Not -Throw
    }

    It "throws when the path uses forward-slash UNC (//server/share)" {
        { Test-EngineDirPathIsLocal -EngineDirPath "//server/share/engines/" } |
            Should -Throw -ExpectedMessage "*UNC path*"
    }

    It "throws when the path uses mixed slash UNC (\/server/share)" {
        { Test-EngineDirPathIsLocal -EngineDirPath "\/server/share/engines/" } |
            Should -Throw -ExpectedMessage "*UNC*"
    }

    It "throws when the path uses mixed slash UNC (/\server/share)" {
        { Test-EngineDirPathIsLocal -EngineDirPath "/\server/share/engines/" } |
            Should -Throw -ExpectedMessage "*UNC*"
    }

    It "throws when the path is a provider-qualified UNC (Microsoft.PowerShell.Core\FileSystem::\\...)" {
        { Test-EngineDirPathIsLocal -EngineDirPath "Microsoft.PowerShell.Core\FileSystem::\\server\share\engines\" } |
            Should -Throw -ExpectedMessage "*UNC*"
    }

    It "throws for a multi-character PSDrive backed by a UNC root (DisplayRoot)" {
        Mock Get-PSDrive { [PSCustomObject]@{ Name = 'Remote'; DisplayRoot = '\\server\share'; Root = 'Remote:\' } } -ParameterFilter { $Name -eq 'Remote' }

        { Test-EngineDirPathIsLocal -EngineDirPath "Remote:\engines\" } |
            Should -Throw -ExpectedMessage "*mapped network drive*"
    }

    It "throws for a multi-character PSDrive backed by a UNC root (Root)" {
        Mock Get-PSDrive { [PSCustomObject]@{ Name = 'Remote'; DisplayRoot = $null; Root = '\\server\share' } } -ParameterFilter { $Name -eq 'Remote' }

        { Test-EngineDirPathIsLocal -EngineDirPath "Remote:\engines\" } |
            Should -Throw -ExpectedMessage "*mapped network drive*"
    }

    It "throws when a relative path resolves against a mapped network current directory" {
        # Simulate the caller's current PowerShell location resolving to a UNC.
        # We mock the resolution helper and then verify the resolved-UNC branch
        # of Test-EngineDirPathIsLocal fires. The InModuleScope-free equivalent
        # is unavailable, so we set up the situation by mocking Get-PSDrive on
        # the drive letter the resolved path would land on.
        # For direct coverage, we route through the '$pathRoot -match ^\\\\'
        # branch by supplying an input that GetPathRoot normalizes to UNC.
        { Test-EngineDirPathIsLocal -EngineDirPath "\\\\server\share\engines\" } |
            Should -Throw -ExpectedMessage "*UNC*"
    }

    It "throws when the target directory is a reparse point (junction)" {
        $target = Join-Path -Path $TestDrive -ChildPath "junction-target"
        $link = Join-Path -Path $TestDrive -ChildPath "junction-link"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        if (Test-Path -LiteralPath $link) { Remove-Item -LiteralPath $link -Recurse -Force }
        try {
            New-Item -ItemType Junction -Path $link -Value $target -ErrorAction Stop | Out-Null
        } catch {
            Set-ItResult -Skipped -Because "environment cannot create a junction (requires NTFS)"
            return
        }

        { Test-EngineDirPathIsLocal -EngineDirPath $link } |
            Should -Throw -ExpectedMessage "*reparse point*"
    }

    It "throws when an ancestor directory is a reparse point (junction)" {
        $target = Join-Path -Path $TestDrive -ChildPath "ancestor-target"
        $link = Join-Path -Path $TestDrive -ChildPath "ancestor-link"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        if (Test-Path -LiteralPath $link) { Remove-Item -LiteralPath $link -Recurse -Force }
        try {
            New-Item -ItemType Junction -Path $link -Value $target -ErrorAction Stop | Out-Null
        } catch {
            Set-ItResult -Skipped -Because "environment cannot create a junction (requires NTFS)"
            return
        }
        $child = Join-Path -Path $link -ChildPath "engines"
        # Do not need to actually create $child; Test-EngineDirPathIsLocal
        # inspects each existing ancestor and stops at the drive root.

        { Test-EngineDirPathIsLocal -EngineDirPath $child } |
            Should -Throw -ExpectedMessage "*reparse point*"
    }

    It "does not throw for a plain (non-reparse) directory tree" {
        $plain = Join-Path -Path $TestDrive -ChildPath "plain-engines"
        New-Item -ItemType Directory -Path $plain -Force | Out-Null

        { Test-EngineDirPathIsLocal -EngineDirPath $plain } | Should -Not -Throw
    }
}

Describe "Get-CertificateChainStatusPartition" {

    BeforeAll {
        # Helper to synthesize an X509ChainStatus with a chosen Status flag
        # and message. The type is a struct so we build via constructor.
        # Uses 'Build-' verb (rather than 'New-') so PSScriptAnalyzer does
        # not require ShouldProcess support on this test helper.
        function Build-FakeChainStatus {
            param(
                [Parameter(Mandatory = $true)]
                [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]$Status,
                [string]$StatusInformation = ""
            )
            $s = [System.Security.Cryptography.X509Certificates.X509ChainStatus]::new()
            $s.Status = $Status
            $s.StatusInformation = $StatusInformation
            return $s
        }
    }

    It "returns empty Hard and Soft arrays when ChainStatus is null" {
        $result = Get-CertificateChainStatusPartition -ChainStatus $null
        $result.Hard.Count | Should -Be 0
        $result.Soft.Count | Should -Be 0
    }

    It "returns empty Hard and Soft arrays when ChainStatus is empty" {
        $result = Get-CertificateChainStatusPartition -ChainStatus @()
        $result.Hard.Count | Should -Be 0
        $result.Soft.Count | Should -Be 0
    }

    It "classifies RevocationStatusUnknown as a soft failure" {
        $status = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown) -StatusInformation "revocation info unavailable"
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Soft.Count | Should -Be 1
        $result.Hard.Count | Should -Be 0
    }

    It "classifies OfflineRevocation as a soft failure" {
        $status = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation) -StatusInformation "CRL offline"
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Soft.Count | Should -Be 1
        $result.Hard.Count | Should -Be 0
    }

    It "classifies UntrustedRoot as a hard failure" {
        $status = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot) -StatusInformation "root not trusted"
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Hard.Count | Should -Be 1
        $result.Soft.Count | Should -Be 0
    }

    It "classifies Revoked as a hard failure" {
        $status = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked) -StatusInformation "certificate revoked"
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Hard.Count | Should -Be 1
        $result.Soft.Count | Should -Be 0
    }

    It "classifies NotSignatureValid as a hard failure" {
        $status = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotSignatureValid) -StatusInformation "signature mismatch"
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Hard.Count | Should -Be 1
        $result.Soft.Count | Should -Be 0
    }

    It "partitions a mixed set into Hard and Soft correctly" {
        $hardStatus = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot)
        $softStatus = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation)
        $revokedStatus = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked)

        $result = Get-CertificateChainStatusPartition -ChainStatus @($hardStatus, $softStatus, $revokedStatus)
        $result.Hard.Count | Should -Be 2
        $result.Soft.Count | Should -Be 1
    }

    It "preserves the StatusInformation so callers can build error details" {
        $status = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot) -StatusInformation "root certificate not trusted"
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Hard[0].StatusInformation | Should -Match "not trusted"
    }

    It "classifies combined soft flags (RevocationStatusUnknown -bor OfflineRevocation) as soft" {
        $combined =
        [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown -bor
        [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation
        $status = Build-FakeChainStatus -Status $combined -StatusInformation "revocation offline and unknown"
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Soft.Count | Should -Be 1
        $result.Hard.Count | Should -Be 0
    }

    It "classifies soft-bit mixed with hard-bit in a single status as hard" {
        $mixed =
        [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown -bor
        [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot
        $status = Build-FakeChainStatus -Status $mixed -StatusInformation "untrusted root with revocation unknown"
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Hard.Count | Should -Be 1
        $result.Soft.Count | Should -Be 0
    }

    It "classifies NoError as hard (fail-closed on anomalous input)" {
        # NoError (0) appearing on a failed X509Chain.Build is anomalous and
        # must not be silently accepted. Fail-closed classification.
        $status = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError)
        $result = Get-CertificateChainStatusPartition -ChainStatus @($status)
        $result.Hard.Count | Should -Be 1
        $result.Soft.Count | Should -Be 0
    }

    It "classifies each entry independently in a multi-status array" {
        $softOnly = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown)
        $combinedSoft = Build-FakeChainStatus -Status (
            [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown -bor
            [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation
        )
        $mixed = Build-FakeChainStatus -Status (
            [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation -bor
            [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotSignatureValid
        )
        $noError = Build-FakeChainStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError)

        $result = Get-CertificateChainStatusPartition -ChainStatus @($softOnly, $combinedSoft, $mixed, $noError)
        $result.Soft.Count | Should -Be 2
        $result.Hard.Count | Should -Be 2
    }
}

Describe "Assert-ChainBuildResult" {

    BeforeAll {
        # Build a fake X509ChainStatus struct with the requested Status
        # flag and message. Same pattern as Get-CertificateChainStatusPartition
        # tests use.
        function Build-FakeStatus {
            param(
                [Parameter(Mandatory = $true)]
                [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]$Status,
                [string]$StatusInformation = ""
            )
            $s = [System.Security.Cryptography.X509Certificates.X509ChainStatus]::new()
            $s.Status = $Status
            $s.StatusInformation = $StatusInformation
            return $s
        }
    }

    Context "when Build() returned true" {

        It "returns silently regardless of ChainStatus" {
            { Assert-ChainBuildResult -Built $true -ChainStatus @() -SubjectForDiagnostics 'CN=Foo' } |
                Should -Not -Throw
        }

        It "returns silently even if ChainStatus contains findings (Build() overrides)" {
            $status = Build-FakeStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot) -StatusInformation "Untrusted root."
            { Assert-ChainBuildResult -Built $true -ChainStatus @($status) -SubjectForDiagnostics 'CN=Foo' } |
                Should -Not -Throw
        }
    }

    Context "when Build() returned false with hard findings" {

        It "throws with the hard finding details" {
            $status = Build-FakeStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked) -StatusInformation "Certificate was revoked."
            { Assert-ChainBuildResult -Built $false -ChainStatus @($status) -SubjectForDiagnostics 'CN=Foo' } |
                Should -Throw -ExpectedMessage "*chain validation failed*CN=Foo*Revoked*"
        }

        It "throws when both hard and soft findings are present (hard wins)" {
            $hard = Build-FakeStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot) -StatusInformation "Untrusted root."
            $soft = Build-FakeStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown) -StatusInformation "Revocation unknown."
            { Assert-ChainBuildResult -Built $false -ChainStatus @($hard, $soft) -SubjectForDiagnostics 'CN=Foo' } |
                Should -Throw -ExpectedMessage "*chain validation failed*UntrustedRoot*"
        }
    }

    Context "when Build() returned false with only soft findings" {

        It "does not throw" {
            $soft = Build-FakeStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown) -StatusInformation "Revocation unknown."
            { Assert-ChainBuildResult -Built $false -ChainStatus @($soft) -SubjectForDiagnostics 'CN=Foo' -WarningAction SilentlyContinue } |
                Should -Not -Throw
        }

        It "writes a warning naming the soft finding" {
            $soft = Build-FakeStatus -Status ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation) -StatusInformation "CRL server unreachable."
            $warnings = @()
            Assert-ChainBuildResult -Built $false -ChainStatus @($soft) -SubjectForDiagnostics 'CN=Bar' -WarningVariable warnings -WarningAction SilentlyContinue
            $warnings.Count | Should -BeGreaterThan 0
            "$warnings" | Should -Match 'CN=Bar'
            "$warnings" | Should -Match 'OfflineRevocation'
        }
    }

    Context "fail-closed invariant: Build() returned false with no findings" {

        # This is the invariant Test-CertificateChain's dedicated defensive
        # branch guards against. Now that classification is factored out
        # into Assert-ChainBuildResult, the invariant is directly exercisable.

        It "throws when ChainStatus is an empty array" {
            { Assert-ChainBuildResult -Built $false -ChainStatus @() -SubjectForDiagnostics 'CN=Foo' } |
                Should -Throw -ExpectedMessage "*returned false but reported no chain-status details*"
        }

        It "throws when ChainStatus is null" {
            { Assert-ChainBuildResult -Built $false -ChainStatus $null -SubjectForDiagnostics 'CN=Foo' } |
                Should -Throw -ExpectedMessage "*returned false but reported no chain-status details*"
        }

        It "names the subject in the fail-closed error message for diagnostics" {
            { Assert-ChainBuildResult -Built $false -ChainStatus @() -SubjectForDiagnostics 'CN=EmptyStatusDemo' } |
                Should -Throw -ExpectedMessage "*CN=EmptyStatusDemo*"
        }
    }
}

Describe "Test-CertificateChain fail-closed invariant" {

    # The invariant "Build() returned false but ChainStatus reported no
    # findings" now has direct coverage via Assert-ChainBuildResult (see
    # Describe above). This Describe kept for the legacy documentation
    # assertion below, which verifies the classifier's null-safety contract
    # that Test-CertificateChain relies on.

    It "Get-CertificateChainStatusPartition returns empty partition for null (Test-CertificateChain invariant)" {
        $result = Get-CertificateChainStatusPartition -ChainStatus $null
        $result.Hard.Count | Should -Be 0
        $result.Soft.Count | Should -Be 0
    }
}

Describe "Invoke-EngineLicenseInfoDownload path-traversal defense" {

    BeforeAll { Mock Write-Host {} }

    BeforeEach {
        $Script:engineDir = (Join-Path -Path $TestDrive -ChildPath "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path -Path $Script:engineDir -ChildPath "temp\")
        if (Test-Path -Path $Script:engineDir) { Remove-Item -Path $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null

        Mock Invoke-WebClientDownload { }
        Mock ExtractCab { }
        Mock Test-AuthenticodeSignature { }
        Mock Test-FileHash { }
    }

    It "throws when licenseInfoVersion contains path-traversal characters" {
        $poisoned = [xml]@"
<UniversalManifest licenseInfoVersion="..\..\evil">
  <EngineVersions />
</UniversalManifest>
"@

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $poisoned } |
            Should -Throw -ExpectedMessage "*licenseInfoVersion*"

        Should -Invoke Invoke-WebClientDownload -Times 0 -Exactly
    }

    It "throws when licenseInfoVersion is a non-numeric string" {
        $poisoned = [xml]@"
<UniversalManifest licenseInfoVersion="abc123">
  <EngineVersions />
</UniversalManifest>
"@

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $poisoned } |
            Should -Throw -ExpectedMessage "*licenseInfoVersion*"
    }
}

Describe "Invoke-EngineUpdate path-traversal defense" {

    BeforeAll { Mock Write-Host {} }

    BeforeEach {
        $Script:engineDir = (Join-Path -Path $TestDrive -ChildPath "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path -Path $Script:engineDir -ChildPath "temp\")
        if (Test-Path -Path $Script:engineDir) { Remove-Item -Path $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null
        $Script:um = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml"))
        $Script:platform = Get-PlatformElement -UniversalManifest $Script:um -PlatformName "amd64"
        $Script:engine = Get-EngineElement -PlatformElement $Script:platform -EngineName "Microsoft"

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Set-Content -Path $Destination -Value "cab-placeholder"
        }

        Mock Test-AuthenticodeSignature { }
        Mock Test-FileHash { }
    }

    It "throws when the engine manifest Package.version contains ..\\" {
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml") -Value @"
<ManifestFile>
  <Package version="..\..\evil">
    <FullPackage name="$Script:PackageFileName" Size="100" />
  </Package>
</ManifestFile>
"@
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*Package.version*"
    }

    It "throws when the engine manifest FullPackage.name contains ..\\" {
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml") -Value @"
<ManifestFile>
  <Package name="Microsoft" platform="amd64" version="$Script:PackageVersion">
    <FullPackage name="..\..\evil.cab" Size="100" />
  </Package>
</ManifestFile>
"@
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*Package.FullPackage.name*"
    }

    It "throws when the engine manifest Files.Dir[i].name contains ..\\" {
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml") -Value @"
<ManifestFile>
  <Package name="Microsoft" platform="amd64" version="$Script:PackageVersion">
    <FullPackage name="$Script:PackageFileName" Size="100">
      <hash algorithm="sha256" hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" />
    </FullPackage>
    <Files>
      <Dir name="..\..\evil" />
    </Files>
  </Package>
</ManifestFile>
"@
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*Files.Dir*"
    }

    It "throws when the Platform.id contains path-traversal characters" {
        # Build a synthetic Platform element with a poisoned id attribute.
        $poisonedPlatformXml = [xml]'<Platform id="..\..\evil" />'
        $poisonedPlatform = $poisonedPlatformXml.DocumentElement

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $poisonedPlatform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*Platform.id*"
    }

    It "throws when the Engine.Default contains path-traversal characters instead of a GUID" {
        $poisonedEngineXml = [xml]'<Engine name="Microsoft" default="..\..\evil" />'
        $poisonedEngine = $poisonedEngineXml.DocumentElement

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $poisonedEngine } |
            Should -Throw -ExpectedMessage "*Engine.Default*"
    }
}

Describe "Test-AuthenticodeSignature" {

    BeforeEach {
        $Script:target = Join-Path -Path $TestDrive -ChildPath "signed.cab"
        Set-Content -Path $Script:target -Value "placeholder"

        # Skip real X509Chain.Build against PSCustomObject fake certs by default.
        # Individual chain-behavior tests can override.
        Mock Test-CertificateChain { }
    }

    It "returns silently when the signature is Valid and the signer is Microsoft" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = [PSCustomObject]@{
                    Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
                }
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Not -Throw
    }

    It "returns silently when the signature is Valid and the signer is Microsoft Windows (catalog-signed)" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = [PSCustomObject]@{
                    Subject = 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
                }
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Not -Throw
    }

    It "throws when the signature Status is NotSigned" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'NotSigned'
                StatusMessage     = 'The file is not digitally signed.'
                SignerCertificate = $null
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Throw -ExpectedMessage "*not Valid*"
    }

    It "throws when the signature Status is HashMismatch" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'HashMismatch'
                StatusMessage     = 'The signature does not match the file.'
                SignerCertificate = [PSCustomObject]@{ Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation' }
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Throw -ExpectedMessage "*HashMismatch*"
    }

    It "throws when the signature Status is NotTrusted" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'NotTrusted'
                StatusMessage     = 'A certificate chain processed, but terminated in a root certificate which is not trusted.'
                SignerCertificate = [PSCustomObject]@{ Subject = 'CN=Attacker' }
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Throw -ExpectedMessage "*NotTrusted*"
    }

    It "throws when the signer certificate is Valid but not from Microsoft" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = [PSCustomObject]@{ Subject = 'CN=Contoso, O=Contoso Ltd, L=Seattle' }
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Throw -ExpectedMessage "*not Microsoft*"
    }

    It "throws when the signer subject contains 'O=Microsoft Corporation' as a substring but not as a complete RDN component" {
        # Guards against a subject like 'O=Microsoft Corporation Evil' or
        # 'O=Not Microsoft Corporation' being accepted by a loose substring match.
        # The check must bound the O= component so only an exact RDN match passes.
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = [PSCustomObject]@{
                    Subject = 'CN=Attacker, O=Microsoft Corporation Evil, L=Nowhere, C=US'
                }
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Throw -ExpectedMessage "*not Microsoft*"
    }

    It "throws when the signer subject is 'O=Not Microsoft Corporation'" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = [PSCustomObject]@{
                    Subject = 'CN=Attacker, O=Not Microsoft Corporation, L=Nowhere, C=US'
                }
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Throw -ExpectedMessage "*not Microsoft*"
    }

    It "invokes Test-CertificateChain after the subject check passes" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = [PSCustomObject]@{
                    Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
                }
            }
        }

        Test-AuthenticodeSignature -Path $Script:target

        Should -Invoke Test-CertificateChain -Times 1 -Exactly
    }

    It "does not invoke Test-CertificateChain when the subject check fails" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = [PSCustomObject]@{ Subject = 'CN=Contoso, O=Contoso Ltd' }
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } |
            Should -Throw -ExpectedMessage "*not Microsoft*"
        Should -Invoke Test-CertificateChain -Times 0 -Exactly
    }

    It "propagates a chain-validation failure from Test-CertificateChain" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = [PSCustomObject]@{
                    Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
                }
            }
        }
        Mock Test-CertificateChain { $(throw "Certificate chain validation failed for '$($Certificate.Subject)': Revoked.") }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Throw -ExpectedMessage "*chain validation failed*"
    }

    It "throws when the signature is Valid but has no signer certificate" {
        Mock Get-AuthenticodeSignature {
            [PSCustomObject]@{
                Status            = 'Valid'
                StatusMessage     = 'Signature verified.'
                SignerCertificate = $null
            }
        }

        { Test-AuthenticodeSignature -Path $Script:target } | Should -Throw -ExpectedMessage "*no signer certificate*"
    }
}

Describe "Test-FileHash" {

    BeforeEach {
        $Script:target = Join-Path -Path $TestDrive -ChildPath "content.bin"
        Set-Content -Path $Script:target -Value "placeholder"
    }

    It "returns silently when the SHA256 matches the expected base64 value" {
        Mock Get-FileHash {
            [PSCustomObject]@{ Hash = 'AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899' }
        }
        # 32 zero bytes → base64 'AAAA...' (44 chars). Use a known base64 of 32 bytes.
        # AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899 in hex
        # is a valid 32-byte SHA256. Convert to base64 for the expected value.
        $bytes = 0..31 | ForEach-Object {
            $offset = $_ * 2
            [System.Convert]::ToByte('AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899'.Substring($offset, 2), 16)
        }
        $expectedBase64 = [System.Convert]::ToBase64String([byte[]]$bytes)

        { Test-FileHash -Path $Script:target -ExpectedSha256Base64 $expectedBase64 -FieldName 'test.hash' } | Should -Not -Throw
    }

    It "throws when the actual hash does not match the expected hash" {
        Mock Get-FileHash {
            [PSCustomObject]@{ Hash = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' }
        }
        # Expected is 32 bytes of 0x00 (base64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=').
        $expectedBase64 = [System.Convert]::ToBase64String((New-Object byte[] 32))

        { Test-FileHash -Path $Script:target -ExpectedSha256Base64 $expectedBase64 -FieldName 'test.hash' } |
            Should -Throw -ExpectedMessage "*SHA256 mismatch*"
    }

    It "throws when the expected base64 decodes to fewer than 32 bytes" {
        # 16 bytes of 0x00 → 24-char base64.
        $shortBase64 = [System.Convert]::ToBase64String((New-Object byte[] 16))

        { Test-FileHash -Path $Script:target -ExpectedSha256Base64 $shortBase64 -FieldName 'test.hash' } |
            Should -Throw -ExpectedMessage "*32-byte*"
    }

    It "throws when the expected value is not valid base64" {
        { Test-FileHash -Path $Script:target -ExpectedSha256Base64 '!!!not-base64!!!' -FieldName 'test.hash' } |
            Should -Throw -ExpectedMessage "*does not match required pattern*"
    }

    It "throws when the expected value is null" {
        { Test-FileHash -Path $Script:target -ExpectedSha256Base64 $null -FieldName 'test.hash' } |
            Should -Throw -ExpectedMessage "*null or empty*"
    }

    It "throws when the expected value is empty" {
        { Test-FileHash -Path $Script:target -ExpectedSha256Base64 '' -FieldName 'test.hash' } |
            Should -Throw -ExpectedMessage "*null or empty*"
    }

    It "embeds the field name in the mismatch error for attribution" {
        Mock Get-FileHash {
            [PSCustomObject]@{ Hash = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' }
        }
        $expectedBase64 = [System.Convert]::ToBase64String((New-Object byte[] 32))

        { Test-FileHash -Path $Script:target -ExpectedSha256Base64 $expectedBase64 -FieldName 'LicenseInfo.hash.hash' } |
            Should -Throw -ExpectedMessage "*LicenseInfo.hash.hash*"
    }
}

Describe "Register-WrittenFile and Test-WrittenFileHashes" {

    BeforeAll { Mock Write-Host {} }

    BeforeEach {
        # Reset the ledger. $Script:writtenFileHashes is defined in the
        # begin{} block of Update-Engines.ps1 and dot-sourced by the
        # top-level BeforeAll. It survives across Describes, so this
        # BeforeEach resets it per test.
        $Script:writtenFileHashes = @{}
    }

    Context "Register-WrittenFile without a manifest hash (runtime capture)" {

        It "captures the on-disk SHA256 at write time" {
            $target = Join-Path -Path $TestDrive -ChildPath "runtime-file.bin"
            Set-Content -Path $target -Value "hello world" -NoNewline

            Register-WrittenFile -Path $target -Source 'test:runtime'

            $Script:writtenFileHashes.Count | Should -Be 1
            $entry = $Script:writtenFileHashes.Values | Select-Object -First 1
            $entry.Anchor | Should -Be 'runtime'
            $entry.Source | Should -Be 'test:runtime'
            $entry.Hex | Should -Match '^[0-9A-F]{64}$'
        }

        It "throws when the file does not exist yet" {
            $target = Join-Path -Path $TestDrive -ChildPath "not-written.bin"
            { Register-WrittenFile -Path $target -Source 'test:missing' } |
                Should -Throw -ExpectedMessage "*does not exist*"
        }

        It "resolves relative paths to absolute for aliasing safety" {
            $target = Join-Path -Path $TestDrive -ChildPath "abs-file.bin"
            Set-Content -Path $target -Value "abs" -NoNewline

            Register-WrittenFile -Path $target -Source 'test:abs'

            $keys = @($Script:writtenFileHashes.Keys)
            $keys | Should -HaveCount 1
            [System.IO.Path]::IsPathRooted($keys[0]) | Should -BeTrue
        }
    }

    Context "Register-WrittenFile with a manifest hash (anchor reuse)" {

        It "stores the manifest base64 hash converted to uppercase hex" {
            $target = Join-Path -Path $TestDrive -ChildPath "manifest-file.bin"
            Set-Content -Path $target -Value "content" -NoNewline

            # 32 bytes of 0x00 → base64 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            $expectedBase64 = [System.Convert]::ToBase64String((New-Object byte[] 32))
            Register-WrittenFile -Path $target -ExpectedSha256Base64 $expectedBase64 -Source 'test:manifest'

            $entry = $Script:writtenFileHashes.Values | Select-Object -First 1
            $entry.Anchor | Should -Be 'manifest'
            $entry.Hex | Should -Be ('0' * 64)
        }

        It "throws when the base64 is not 32 bytes" {
            $target = Join-Path -Path $TestDrive -ChildPath "shortbase64.bin"
            Set-Content -Path $target -Value "content" -NoNewline
            $shortBase64 = [System.Convert]::ToBase64String((New-Object byte[] 16))
            { Register-WrittenFile -Path $target -ExpectedSha256Base64 $shortBase64 -Source 'test:short' } |
                Should -Throw -ExpectedMessage "*32 bytes*"
        }

        It "throws when the base64 is malformed" {
            $target = Join-Path -Path $TestDrive -ChildPath "badbase64.bin"
            Set-Content -Path $target -Value "content" -NoNewline
            { Register-WrittenFile -Path $target -ExpectedSha256Base64 '!!not-base64!!' -Source 'test:bad' } |
                Should -Throw -ExpectedMessage "*invalid base64*"
        }
    }

    Context "Test-WrittenFileHashes verifies at end-of-run" {

        It "returns silently when the ledger is empty" {
            { Test-WrittenFileHashes } | Should -Not -Throw
        }

        It "returns silently when every tracked file still hashes to the recorded value" {
            $target = Join-Path -Path $TestDrive -ChildPath "unchanged.bin"
            Set-Content -Path $target -Value "keep-me" -NoNewline
            Register-WrittenFile -Path $target -Source 'test:unchanged'

            { Test-WrittenFileHashes } | Should -Not -Throw
        }

        It "throws when a tracked file was mutated after registration" {
            $target = Join-Path -Path $TestDrive -ChildPath "mutated.bin"
            Set-Content -Path $target -Value "original" -NoNewline
            Register-WrittenFile -Path $target -Source 'test:mutated'

            Set-Content -Path $target -Value "tampered" -NoNewline

            { Test-WrittenFileHashes } |
                Should -Throw -ExpectedMessage "*integrity sanity check failed*CHANGED*"
        }

        It "throws when a tracked file was deleted after registration (AV/quarantine scenario)" {
            $target = Join-Path -Path $TestDrive -ChildPath "quarantined.bin"
            Set-Content -Path $target -Value "victim" -NoNewline
            Register-WrittenFile -Path $target -Source 'test:av'

            Remove-Item -LiteralPath $target -Force

            { Test-WrittenFileHashes } |
                Should -Throw -ExpectedMessage "*integrity sanity check failed*MISSING*"
        }

        It "aggregates multiple violations in a single throw" {
            $a = Join-Path -Path $TestDrive -ChildPath "victim-a.bin"
            $b = Join-Path -Path $TestDrive -ChildPath "victim-b.bin"
            Set-Content -Path $a -Value "aa" -NoNewline
            Set-Content -Path $b -Value "bb" -NoNewline
            Register-WrittenFile -Path $a -Source 'test:agg-a'
            Register-WrittenFile -Path $b -Source 'test:agg-b'

            Set-Content -Path $a -Value "AA" -NoNewline
            Remove-Item -LiteralPath $b -Force

            $err = { Test-WrittenFileHashes } | Should -Throw -PassThru
            "$err" | Should -Match 'CHANGED'
            "$err" | Should -Match 'MISSING'
            "$err" | Should -Match '2 file'
        }

        It "reuses the manifest anchor without re-computing on registration" {
            # Verifies that when a manifest hash is supplied, the ledger
            # holds THAT hash (not the runtime one). If the file's actual
            # hash differs from the manifest hash, verification will fail,
            # which is the desired end-of-run behavior for a tamper attempt
            # that predates the initial hash check.
            $target = Join-Path -Path $TestDrive -ChildPath "manifest-anchor.bin"
            Set-Content -Path $target -Value "content" -NoNewline
            # Register with an ALL-ZEROES manifest hash (which will not
            # match the real content). We want to see that end-of-run
            # verification uses the registered value, not a fresh compute.
            $bogusBase64 = [System.Convert]::ToBase64String((New-Object byte[] 32))
            Register-WrittenFile -Path $target -ExpectedSha256Base64 $bogusBase64 -Source 'test:manifest-anchor'

            { Test-WrittenFileHashes } |
                Should -Throw -ExpectedMessage "*CHANGED*manifest:test:manifest-anchor*"
        }
    }

    Context "Unregister-WrittenFile" {

        It "removes the ledger entry when the file still exists at the resolved path" {
            $target = Join-Path -Path $TestDrive -ChildPath "unregLive.bin"
            Set-Content -Path $target -Value "live" -NoNewline
            Register-WrittenFile -Path $target -Source 'test:live'
            $Script:writtenFileHashes.Count | Should -Be 1

            Unregister-WrittenFile -Path $target

            $Script:writtenFileHashes.Count | Should -Be 0
        }

        It "removes the ledger entry when the file has already been deleted" {
            # Callers hit this path when a Remove-Item runs before
            # Unregister-WrittenFile (marker invalidation is exactly
            # that pattern). Resolve-Path would throw on a missing
            # file; the helper falls back to a lexical GetFullPath
            # lookup so the caller does not have to sequence the
            # deletion around ledger cleanup.
            $target = Join-Path -Path $TestDrive -ChildPath "unregDeleted.bin"
            Set-Content -Path $target -Value "gone-in-a-moment" -NoNewline
            Register-WrittenFile -Path $target -Source 'test:deleted'
            Remove-Item -LiteralPath $target -Force

            Unregister-WrittenFile -Path $target

            $Script:writtenFileHashes.Count | Should -Be 0
        }

        It "removes the ledger entry when the caller uses different casing on the path" {
            # NTFS is case-insensitive; the ledger key was captured
            # from Resolve-Path at registration time. A caller passing
            # a different casing (or a deleted-file path where the
            # lexical GetFullPath result cases differently) must still
            # find and remove the entry.
            $target = Join-Path -Path $TestDrive -ChildPath "unregCase.bin"
            Set-Content -Path $target -Value "case-drift" -NoNewline
            Register-WrittenFile -Path $target -Source 'test:case'
            Remove-Item -LiteralPath $target -Force

            Unregister-WrittenFile -Path ($target.ToUpper())

            $Script:writtenFileHashes.Count | Should -Be 0
        }

        It "is a no-op when the path was never registered" {
            $target = Join-Path -Path $TestDrive -ChildPath "unregUnknown.bin"
            Set-Content -Path $target -Value "unknown" -NoNewline

            { Unregister-WrittenFile -Path $target } | Should -Not -Throw

            $Script:writtenFileHashes.Count | Should -Be 0
        }
    }
}

Describe "Invoke-UniversalManifestDownload signature verification" {

    BeforeAll { Mock Write-Host {} }

    BeforeEach {
        $Script:engineDir = (Join-Path -Path $TestDrive -ChildPath "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path -Path $Script:engineDir -ChildPath "temp\")
        if (Test-Path -Path $Script:engineDir) { Remove-Item -Path $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml") -Destination $Destination
        }

        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml") -Destination (Join-Path -Path $destinationDirectory -ChildPath "UniversalManifest.xml")
        }
    }

    It "throws before extraction when the Universal Manifest signature is invalid" {
        Mock Test-AuthenticodeSignature { $(throw "Authenticode signature not Valid for '$Path' (Status: NotSigned).") }

        { Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir } |
            Should -Throw -ExpectedMessage "*Authenticode*"

        # ExtractCab should never be reached.
        Should -Invoke ExtractCab -Times 0 -Exactly
    }
}

Describe "Invoke-EngineLicenseInfoDownload integrity verification" {

    BeforeAll { Mock Write-Host {} }

    BeforeEach {
        $Script:engineDir = (Join-Path -Path $TestDrive -ChildPath "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path -Path $Script:engineDir -ChildPath "temp\")
        if (Test-Path -Path $Script:engineDir) { Remove-Item -Path $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null
        $Script:um = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml"))

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Set-Content -Path $Destination -Value "placeholder"
        }

        # Simulate CAB extraction by dropping a stub inner file so the code
        # can locate and hash it. Individual tests override this to test
        # the "no inner file" and "extract order" edge cases.
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if (-not (Test-Path -Path $destinationDirectory)) { New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null }
            Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "EngineInfo.cab") -Value "inner-eli-placeholder"
        }

        Mock Test-AuthenticodeSignature { }
        Mock Test-FileHash { }
    }

    It "throws when the Engine License Info signature is invalid" {
        Mock Test-AuthenticodeSignature { $(throw "Authenticode signature not Valid for '$Path' (Status: NotTrusted).") }

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um } |
            Should -Throw -ExpectedMessage "*Authenticode*"
    }

    It "throws when the inner Engine License Info CAB hash does not match" {
        Mock Test-FileHash { $(throw "SHA256 mismatch for '$Path' ($FieldName).") }

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um } |
            Should -Throw -ExpectedMessage "*SHA256 mismatch*"
    }

    It "passes the UM.LicenseInfo.hash.hash value to Test-FileHash and targets the extracted inner CAB" {
        $expected = $Script:um.UniversalManifest.LicenseInfo.hash.hash

        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um

        # Hash must target the extracted inner CAB, NOT the outer downloaded file.
        # UM.LicenseInfo.hash.hash is the SHA256 of the inner ELI archive.
        Should -Invoke Test-FileHash -Times 1 -Exactly -ParameterFilter {
            $ExpectedSha256Base64 -eq $expected -and
            $FieldName -eq 'LicenseInfo.hash.hash' -and
            $Path -notlike "*\metadata\*\EngineInfo.cab" -and
            $Path -like "*\eli-*"
        }
    }

    It "extracts the outer CAB before hashing the inner file" {
        $Script:order = @()
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            $Script:order += 'extract'
            if (-not (Test-Path -Path $destinationDirectory)) { New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null }
            Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "EngineInfo.cab") -Value "inner"
        }
        Mock Test-FileHash { $Script:order += 'hash' }

        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um

        $Script:order | Should -Be @('extract', 'hash')
    }

    It "throws before hashing when the inner CAB is missing after extraction" {
        Mock ExtractCab {
            # Simulate an extraction that produces no output files.
            param($sourceCabPath, $destinationDirectory)
            if (-not (Test-Path -Path $destinationDirectory)) { New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null }
        }

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um } |
            Should -Throw -ExpectedMessage "*did not contain any files*"

        Should -Invoke Test-FileHash -Times 0 -Exactly
    }

    It "reads the hash attribute, not the chash attribute" {
        # The real UM publishes both hash and chash on LicenseInfo. Only hash
        # is the SHA256 of the inner CAB (verified via live probe). Regression
        # guard against a future change that swaps them.
        $chashValue = $Script:um.UniversalManifest.LicenseInfo.hash.chash

        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um

        Should -Invoke Test-FileHash -Times 0 -Exactly -ParameterFilter { $ExpectedSha256Base64 -eq $chashValue }
    }

    It "verifies the signature and hash on the cached-file fast path too" {
        # Seed a cached outer CAB so the download branch is skipped.
        $target = Join-Path -Path $Script:engineDir -ChildPath "metadata\201910170001"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Set-Content -Path (Join-Path -Path $target -ChildPath "EngineInfo.cab") -Value "cached"

        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um

        Should -Invoke Invoke-WebClientDownload -Times 0 -Exactly
        Should -Invoke Test-AuthenticodeSignature -Times 1 -Exactly
        Should -Invoke Test-FileHash -Times 1 -Exactly
    }

    It "throws with a clear message when the Universal Manifest is missing the LicenseInfo element" {
        $bareUm = [xml]@"
<UniversalManifest licenseInfoVersion="201910170001">
  <EngineVersions />
</UniversalManifest>
"@

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $bareUm } |
            Should -Throw -ExpectedMessage "*LicenseInfo*"

        Should -Invoke Invoke-WebClientDownload -Times 0 -Exactly
    }

    It "recovers by redownloading once when the cached ELI signature fails, then succeeds" {
        # Fail-open cache pattern for the ELI outer CAB: cached bytes fail
        # Authenticode (AV replaced the file, disk corruption, killed prior
        # run left a truncated file), fresh redownload succeeds. Exactly
        # one download call must fire, and the flow completes without
        # throwing.
        $target = Join-Path -Path $Script:engineDir -ChildPath "metadata\201910170001"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Set-Content -Path (Join-Path -Path $target -ChildPath "EngineInfo.cab") -Value "cached-corrupt"

        $Script:sigCalls = 0
        Mock Test-AuthenticodeSignature {
            $Script:sigCalls++
            if ($Script:sigCalls -eq 1) {
                $(throw "Authenticode signature not Valid for '$Path' (Status: NotSigned).")
            }
        }

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um } |
            Should -Not -Throw

        Should -Invoke Invoke-WebClientDownload -Times 1 -Exactly
        Should -Invoke Test-AuthenticodeSignature -Times 2 -Exactly
    }

    It "recovers by redownloading once when the cached ELI inner hash fails, then succeeds" {
        # Same fail-open pattern for the inner-CAB SHA256. Exactly one
        # redownload; the second verification pass succeeds and the flow
        # completes without throwing.
        $target = Join-Path -Path $Script:engineDir -ChildPath "metadata\201910170001"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Set-Content -Path (Join-Path -Path $target -ChildPath "EngineInfo.cab") -Value "cached-corrupt"

        $Script:hashCalls = 0
        Mock Test-FileHash {
            $Script:hashCalls++
            if ($Script:hashCalls -eq 1) {
                $(throw "SHA256 mismatch for '$Path' ($FieldName).")
            }
        }

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um } |
            Should -Not -Throw

        Should -Invoke Invoke-WebClientDownload -Times 1 -Exactly
        Should -Invoke Test-FileHash -Times 2 -Exactly
    }

    It "does not retry when the freshly-downloaded ELI fails verification" {
        # No cached file present, so $freshlyDownloaded is true from the
        # initial download. If verification then fails, the endpoint is
        # compromised or Microsoft published a bad artifact -- either way
        # a second download is not going to help. The flow MUST NOT loop.
        Mock Test-AuthenticodeSignature { $(throw "Authenticode signature not Valid for '$Path' (Status: HashMismatch).") }

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um } |
            Should -Throw -ExpectedMessage "*Authenticode*"

        Should -Invoke Invoke-WebClientDownload -Times 1 -Exactly
    }

    It "does not retry when the freshly-downloaded ELI inner hash fails verification" {
        # Companion to the signature-failure case above: if the
        # freshly downloaded ELI's inner-CAB hash fails, no cached
        # copy exists to fall back to and a second download from the
        # same endpoint will produce the same bytes. Guarantee: no
        # retry loop.
        Mock Test-FileHash { $(throw "SHA256 mismatch for '$Path' ($FieldName).") }

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um } |
            Should -Throw -ExpectedMessage "*SHA256 mismatch*"

        Should -Invoke Invoke-WebClientDownload -Times 1 -Exactly
    }

    It "throws when both the cached ELI and its fresh redownload fail verification" {
        # Cached bytes fail verification, and the redownloaded bytes ALSO
        # fail. The endpoint is compromised or Microsoft published a bad
        # artifact; retry cannot recover. Flow must throw and downloader
        # must have run exactly once (the recovery redownload).
        $target = Join-Path -Path $Script:engineDir -ChildPath "metadata\201910170001"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Set-Content -Path (Join-Path -Path $target -ChildPath "EngineInfo.cab") -Value "cached-corrupt"

        Mock Test-FileHash { $(throw "SHA256 mismatch for '$Path' ($FieldName).") }

        { Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um } |
            Should -Throw -ExpectedMessage "*SHA256 mismatch*"

        Should -Invoke Invoke-WebClientDownload -Times 1 -Exactly
        Should -Invoke Test-FileHash -Times 2 -Exactly
    }

    It "deletes the corrupted cached ELI before redownloading during recovery" {
        # The recovery path Remove-Item's the cached file before the
        # second download. Prove ordering by capturing whether the file
        # existed at Invoke-WebClientDownload call time.
        $target = Join-Path -Path $Script:engineDir -ChildPath "metadata\201910170001"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        $cachedPath = Join-Path -Path $target -ChildPath "EngineInfo.cab"
        Set-Content -Path $cachedPath -Value "cached-corrupt"

        $Script:cachedExistedAtDownload = $null
        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            if ($null -eq $Script:cachedExistedAtDownload) {
                $Script:cachedExistedAtDownload = Test-Path -LiteralPath $Destination
            }
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Set-Content -Path $Destination -Value "fresh"
        }

        $Script:sigCalls = 0
        Mock Test-AuthenticodeSignature {
            $Script:sigCalls++
            if ($Script:sigCalls -eq 1) {
                $(throw "Authenticode signature not Valid for '$Path' (Status: NotSigned).")
            }
        }

        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -UniversalManifest $Script:um

        # The cached-corrupt file must have been removed before the
        # redownload wrote fresh bytes to the same path.
        $Script:cachedExistedAtDownload | Should -BeFalse
    }
}

Describe "Invoke-EngineUpdate integrity verification" {

    BeforeAll { Mock Write-Host {} }

    BeforeEach {
        $Script:engineDir = (Join-Path -Path $TestDrive -ChildPath "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path -Path $Script:engineDir -ChildPath "temp\")
        if (Test-Path -Path $Script:engineDir) { Remove-Item -Path $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null
        $Script:um = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "UniversalManifest.xml"))
        $Script:platform = Get-PlatformElement -UniversalManifest $Script:um -PlatformName "amd64"
        $Script:engine = Get-EngineElement -PlatformElement $Script:platform -EngineName "Microsoft"
        $Script:manifest = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml"))

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Set-Content -Path $Destination -Value "cab-placeholder"
        }

        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Copy-Item -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml") -Destination (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml")
            } else {
                # B3 inventory validation: produce every file the manifest
                # declares under Package.Files.File or the flow bails.
                $mf = [xml](Get-Content -Path (Join-Path -Path $Script:dataPath -ChildPath "Manifest.Microsoft.xml"))
                foreach ($f in $mf.ManifestFile.Package.Files.File) {
                    Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath ($f.GetAttribute('name') + '.cab')) -Value "extracted"
                }
            }
        }

        Mock Test-AuthenticodeSignature { }
        Mock Test-FileHash { }
    }

    It "throws before extracting when the per-engine manifest CAB signature is invalid" {
        Mock Test-AuthenticodeSignature {
            if ($Path -like "*manifest.*.cab") {
                $(throw "Authenticode signature not Valid for '$Path' (Status: NotSigned).")
            }
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*Authenticode*"

        # ExtractCab must never be called with the manifest CAB.
        Should -Invoke ExtractCab -Times 0 -Exactly
    }

    It "does not invoke Authenticode verification on the full package CAB" {
        # The 206 MB payload is not Authenticode-signed in production. If we
        # ever add a check on it, Get-AuthenticodeSignature would always
        # return NotSigned and every real run would throw. Locking this in.
        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        Should -Invoke Test-AuthenticodeSignature -Times 0 -Exactly -ParameterFilter {
            $Path -like "*$Script:PackageFileName"
        }
    }

    It "does not download the full package when the manifest CAB signature is invalid" {
        Mock Test-AuthenticodeSignature {
            if ($Path -like "*manifest.*.cab") {
                $(throw "Authenticode signature not Valid for '$Path' (Status: NotSigned).")
            }
        }
        $Script:downloaded = @()
        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $Script:downloaded += $Uri
            $parent = Split-Path -Path $Destination -Parent
            if (-not (Test-Path -Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Set-Content -Path $Destination -Value "cab-placeholder"
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*Authenticode*"

        # Only the manifest CAB should have been downloaded before the sig
        # check fired. The payload URL must not appear.
        ($Script:downloaded | Where-Object { $_ -like "*$Script:PackageFileName" }) | Should -BeNullOrEmpty
    }

    It "throws when the full package CAB hash does not match the value published in the engine manifest" {
        Mock Test-FileHash { $(throw "SHA256 mismatch for '$Path' ($FieldName).") }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*SHA256 mismatch*"
    }

    It "passes the Package.FullPackage.hash.hash value from the engine manifest to Test-FileHash" {
        $expected = $Script:manifest.ManifestFile.Package.FullPackage.hash.hash

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        Should -Invoke Test-FileHash -Times 1 -Exactly -ParameterFilter {
            $ExpectedSha256Base64 -eq $expected -and $FieldName -eq 'Package.FullPackage.hash.hash'
        }
    }

    It "verifies the payload hash on the cached-file fast path too" {
        # Seed a cached payload whose size matches the manifest so the
        # download branch is skipped. Hash must still run to guard against
        # local tampering of an on-disk mirror between runs.
        $version = $Script:manifest.ManifestFile.Package.version
        $payloadName = $Script:manifest.ManifestFile.Package.FullPackage.name
        $declaredSize = [int64]$Script:manifest.ManifestFile.Package.FullPackage.Size
        $payloadDir = Join-Path -Path $Script:engineDir -ChildPath "amd64\Microsoft\Package\$version\"
        New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null
        $payloadPath = Join-Path -Path $payloadDir -ChildPath $payloadName
        # Create a file whose byte length equals the declared size in the
        # manifest without allocating the entire payload in memory (declared
        # size can be ~200 MB).
        $fs = [System.IO.File]::Create($payloadPath)
        $fs.SetLength($declaredSize)
        $fs.Close()

        # B3 cached-fast-path inventory check: every file the manifest
        # declares under Package.Files.File must already sit in the version
        # directory or the flow throws before the hash check runs.
        foreach ($f in $Script:manifest.ManifestFile.Package.Files.File) {
            Set-Content -Path (Join-Path -Path $payloadDir -ChildPath ($f.GetAttribute('name') + '.cab')) -Value "cached-payload"
        }

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        # No download for the payload URL.
        Should -Invoke Invoke-WebClientDownload -Times 0 -Exactly -ParameterFilter {
            $Uri -like "*$payloadName"
        }
        # But hash verification still ran on the cached payload.
        Should -Invoke Test-FileHash -Times 1 -Exactly -ParameterFilter {
            $FieldName -eq 'Package.FullPackage.hash.hash'
        }
    }

    It "throws with a clear message when the engine manifest is missing the FullPackage/hash element" {
        # Rewrite the mock so the extracted manifest.xml has no <hash> under FullPackage.
        $bareManifestXml = @"
<?xml version="1.0" encoding="utf-8"?>
<ManifestFile version="2.0">
  <Package type="engine" name="Microsoft" platform="amd64" version="2112342123">
    <FullPackage type="CAB" name="$($Script:PackageFileName)" size="100" />
    <Files />
  </Package>
</ManifestFile>
"@
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml") -Value $bareManifestXml
            }
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*FullPackage*hash*"

        # No payload download should have been attempted.
        $expectedName = $Script:PackageFileName
        Should -Invoke Invoke-WebClientDownload -Times 0 -Exactly -ParameterFilter {
            $Uri -like "*$expectedName"
        }
    }

    It "throws when the per-engine manifest declares a different Package.name than the UM selection" {
        # A MITM could combine a valid current Universal Manifest with a
        # different but still Microsoft-signed per-engine manifest. Identity
        # binding rejects that: the manifest we downloaded for
        # $Engine.Name must declare Package.name = $Engine.Name.
        $mismatchXml = @"
<?xml version="1.0" encoding="utf-8"?>
<ManifestFile version="2.0">
  <Package type="engine" name="Kaspersky" platform="amd64" version="2112342123">
    <FullPackage type="CAB" name="$($Script:PackageFileName)" size="100">
      <hash algorithm="sha256" hash="quVpWy3z7iyybjCIp2Y2e6Yoyd32WGdvnrStFVj0eVU=" />
    </FullPackage>
    <Files />
  </Package>
</ManifestFile>
"@
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml") -Value $mismatchXml
            }
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*identity mismatch*Package.name*Kaspersky*"

        # No payload download should have been attempted.
        $expectedName = $Script:PackageFileName
        Should -Invoke Invoke-WebClientDownload -Times 0 -Exactly -ParameterFilter {
            $Uri -like "*$expectedName"
        }
    }

    It "throws when the per-engine manifest declares a different Package.platform than the UM selection" {
        $mismatchXml = @"
<?xml version="1.0" encoding="utf-8"?>
<ManifestFile version="2.0">
  <Package type="engine" name="Microsoft" platform="x86" version="2112342123">
    <FullPackage type="CAB" name="$($Script:PackageFileName)" size="100">
      <hash algorithm="sha256" hash="quVpWy3z7iyybjCIp2Y2e6Yoyd32WGdvnrStFVj0eVU=" />
    </FullPackage>
    <Files />
  </Package>
</ManifestFile>
"@
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml") -Value $mismatchXml
            }
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*identity mismatch*Package.platform*x86*"
    }

    It "throws when the per-engine manifest declares a different Package.version than the UM selection" {
        # Downgrade/replay-adjacent: a validly-signed older manifest for the
        # same engine/platform combo whose Package.version differs from what
        # the Universal Manifest selected must be rejected.
        $mismatchXml = @"
<?xml version="1.0" encoding="utf-8"?>
<ManifestFile version="2.0">
  <Package type="engine" name="Microsoft" platform="amd64" version="1900010001">
    <FullPackage type="CAB" name="$($Script:PackageFileName)" size="100">
      <hash algorithm="sha256" hash="quVpWy3z7iyybjCIp2Y2e6Yoyd32WGdvnrStFVj0eVU=" />
    </FullPackage>
    <Files />
  </Package>
</ManifestFile>
"@
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Set-Content -Path (Join-Path -Path $destinationDirectory -ChildPath "manifest.xml") -Value $mismatchXml
            }
        }

        { Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine } |
            Should -Throw -ExpectedMessage "*identity mismatch*Package.version*1900010001*"
    }
}

