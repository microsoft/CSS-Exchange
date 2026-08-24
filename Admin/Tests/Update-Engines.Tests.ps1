# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = Split-Path -Parent $PSScriptRoot
    $Script:scriptPath = Join-Path $Script:parentPath "Update-Engines.ps1"
    $Script:dataPath = Join-Path $PSScriptRoot "Data"

    # Load only the function definitions from Update-Engines.ps1.
    # The script has a param() block and a main-script body that would run on
    # dot-source and try to hit the network. Extracting just the functions via
    # AST avoids triggering the main body while still exposing every function
    # under test to Pester.
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Script:scriptPath, [ref]$null, [ref]$null)
    $functionDefs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
    foreach ($fn in $functionDefs) {
        . ([ScriptBlock]::Create($fn.Extent.Text))
    }

    # The functions expect these file-scope constants, which are declared in the
    # main-script section we deliberately skipped. Re-declare them here.
    $Script:UmFileName = "UniversalManifest.cab"
    $Script:EliFileName = "EngineInfo.cab"

    # Derive engine-manifest values (full-package filename, package version) from
    # the fixture manifest so tests are not coupled to the specific literal
    # filename Microsoft happens to ship today.
    $manifestFixture = [xml](Get-Content (Join-Path $Script:dataPath "Manifest.Microsoft.xml"))
    $Script:PackageFileName = $manifestFixture.ManifestFile.Package.FullPackage.name
    $Script:PackageVersion = $manifestFixture.ManifestFile.Package.version

    function Get-FakeWebClient {
        # A stand-in for [System.Net.WebClient] that satisfies the parameter
        # type constraint on the download functions. Never actually reached
        # because Invoke-WebClientDownload is always mocked.
        return New-Object System.Net.WebClient
    }
}

Describe "CreatePath" {

    It "creates the directory when it does not exist" {
        $target = Join-Path $TestDrive "new-dir"
        Test-Path $target | Should -BeFalse
        CreatePath -path $target | Out-Null
        Test-Path $target | Should -BeTrue
    }

    It "is a no-op when the directory already exists" {
        $target = Join-Path $TestDrive "existing-dir"
        New-Item -ItemType Directory -Path $target | Out-Null
        Mock New-Item {}
        CreatePath -path $target | Out-Null
        Should -Invoke New-Item -Times 0 -Exactly
    }
}

Describe "CleanUpFolder" {

    It "keeps the newest N directories and removes the rest" {
        $root = Join-Path $TestDrive "cleanup"
        New-Item -ItemType Directory -Path $root | Out-Null
        # Create 5 subdirectories with staggered creation times so the sort is deterministic.
        for ($i = 1; $i -le 5; $i++) {
            $sub = New-Item -ItemType Directory -Path (Join-Path $root "v$i")
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
        $result = Read-Manifest -Path (Join-Path $Script:dataPath "UniversalManifest.xml")
        $result | Should -BeOfType [System.Xml.XmlDocument]
        $result.UniversalManifest.licenseInfoVersion | Should -Be "201910170001"
    }
}

Describe "Get-PlatformElement" {

    BeforeAll {
        $Script:um = [xml](Get-Content (Join-Path $Script:dataPath "UniversalManifest.xml"))
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
        { Get-PlatformElement -UniversalManifest $Script:um -PlatformName "arm64" } | Should -Throw
    }
}

Describe "Get-EngineElement" {

    BeforeAll {
        $Script:um = [xml](Get-Content (Join-Path $Script:dataPath "UniversalManifest.xml"))
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

    BeforeEach {
        $Script:engineDir = (Join-Path $TestDrive "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path $Script:engineDir "temp\")
        if (Test-Path $Script:engineDir) { Remove-Item $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $Script:capturedUri = $Uri
            $Script:capturedDest = $Destination
            Copy-Item -Path (Join-Path $Script:dataPath "UniversalManifest.xml") -Destination $Destination
        }

        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            Copy-Item -Path (Join-Path $Script:dataPath "UniversalManifest.xml") -Destination (Join-Path $destinationDirectory "UniversalManifest.xml")
        }
    }

    It "downloads the Universal Manifest from the correct URL to the correct destination" {
        Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://forefrontdl.microsoft.com/server/scanengineupdate/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir | Out-Null

        $Script:capturedUri | Should -Be "http://forefrontdl.microsoft.com/server/scanengineupdate/metadata/UniversalManifest.cab"
        $Script:capturedDest | Should -Be ($Script:engineDir + "metadata\UniversalManifest.cab")
    }

    It "creates the metadata and temp directories" {
        Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir | Out-Null

        Test-Path (Join-Path $Script:engineDir "metadata") | Should -BeTrue
        Test-Path $Script:tempDir | Should -BeTrue
    }

    It "clears stale files from the temp directory before extracting" {
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null
        Set-Content -Path (Join-Path $Script:tempDir "stale.tmp") -Value "old"

        Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir | Out-Null

        Test-Path (Join-Path $Script:tempDir "stale.tmp") | Should -BeFalse
    }

    It "returns a parsed XmlDocument for the Universal Manifest" {
        $result = Invoke-UniversalManifestDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir
        $result | Should -BeOfType [System.Xml.XmlDocument]
        $result.UniversalManifest.licenseInfoVersion | Should -Be "201910170001"
    }
}

Describe "Invoke-EngineLicenseInfoDownload" {

    BeforeEach {
        $Script:engineDir = (Join-Path $TestDrive "engines\") -replace '/', '\'
        if (Test-Path $Script:engineDir) { Remove-Item $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null
        $Script:um = [xml](Get-Content (Join-Path $Script:dataPath "UniversalManifest.xml"))

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $Script:capturedUri = $Uri
            $Script:capturedDest = $Destination
            # Create a placeholder file so subsequent Test-Path returns $true.
            $parent = Split-Path -Parent $Destination
            if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Set-Content -Path $Destination -Value "placeholder"
        }
    }

    It "creates the versioned metadata directory" {
        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -UniversalManifest $Script:um

        Test-Path (Join-Path $Script:engineDir "metadata\201910170001") | Should -BeTrue
    }

    It "downloads the Engine License Info when it is missing" {
        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -UniversalManifest $Script:um

        Should -Invoke Invoke-WebClientDownload -Times 1 -Exactly
        $Script:capturedUri | Should -Be "http://x/\metadata\201910170001/EngineInfo.cab"
        $Script:capturedDest | Should -Be ($Script:engineDir + "metadata\201910170001\EngineInfo.cab")
    }

    It "skips the download when the Engine License Info is already present" {
        $target = Join-Path $Script:engineDir "metadata\201910170001"
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Set-Content -Path (Join-Path $target "EngineInfo.cab") -Value "already-here"

        Invoke-EngineLicenseInfoDownload -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -UniversalManifest $Script:um

        Should -Invoke Invoke-WebClientDownload -Times 0 -Exactly
    }
}

Describe "Invoke-EngineUpdate" {

    BeforeEach {
        $Script:engineDir = (Join-Path $TestDrive "engines\") -replace '/', '\'
        $Script:tempDir = (Join-Path $Script:engineDir "temp\")
        if (Test-Path $Script:engineDir) { Remove-Item $Script:engineDir -Recurse -Force }
        New-Item -ItemType Directory -Path $Script:engineDir | Out-Null
        New-Item -ItemType Directory -Path $Script:tempDir | Out-Null
        $Script:um = [xml](Get-Content (Join-Path $Script:dataPath "UniversalManifest.xml"))
        $Script:platform = Get-PlatformElement -UniversalManifest $Script:um -PlatformName "amd64"
        $Script:engine = Get-EngineElement -PlatformElement $Script:platform -EngineName "Microsoft"

        # Track every URI the code asked to download.
        $Script:downloads = New-Object System.Collections.Generic.List[hashtable]

        Mock Invoke-WebClientDownload {
            param($WebClient, $Uri, $Destination)
            $Script:downloads.Add(@{ Uri = $Uri; Destination = $Destination })
            $parent = Split-Path -Parent $Destination
            if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
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
            # write a couple of files to prove the flow reached that point.
            if ($sourceCabPath -like "*manifest.*.cab") {
                Copy-Item -Path (Join-Path $Script:dataPath "Manifest.Microsoft.xml") -Destination (Join-Path $destinationDirectory "manifest.xml")
            } else {
                Set-Content -Path (Join-Path $destinationDirectory "update.ini") -Value "extracted"
            }
        }
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
        Test-Path (Join-Path $Script:engineDir "amd64\Microsoft\Package\$Script:PackageVersion\manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab") | Should -BeTrue
    }

    It "skips the full-package download when the file is already present and the size matches" {
        # Pre-create the destination with the exact declared size.
        $pkgDir = Join-Path $Script:engineDir "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        $pkgPath = Join-Path $pkgDir $Script:PackageFileName
        # 214529388 is the declared size in the manifest fixture.
        $fs = [System.IO.File]::Create($pkgPath)
        $fs.SetLength(214529388)
        $fs.Close()

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        # Manifest CAB is always downloaded; the full package is not.
        $fullCall = $Script:downloads | Where-Object { $_.Uri -like "*/$Script:PackageFileName" }
        $fullCall | Should -BeNullOrEmpty
    }

    It "re-downloads the full package when the file is present but the size does not match" {
        $pkgDir = Join-Path $Script:engineDir "amd64\Microsoft\Package\$Script:PackageVersion"
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
        Set-Content -Path (Join-Path $pkgDir $Script:PackageFileName) -Value "wrong-size"

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        $fullCall = $Script:downloads | Where-Object { $_.Uri -like "*/$Script:PackageFileName" }
        $fullCall | Should -Not -BeNullOrEmpty
    }

    It "creates the subdirectories declared by <Files><Dir> in the manifest" {
        # Override ExtractCab to hand back a manifest that includes <Dir> entries.
        Mock ExtractCab {
            param($sourceCabPath, $destinationDirectory)
            if ($sourceCabPath -like "*manifest.*.cab") {
                Copy-Item -Path (Join-Path $Script:dataPath "Manifest.WithDirs.xml") -Destination (Join-Path $destinationDirectory "manifest.xml")
            }
        }

        Invoke-EngineUpdate -WebClient (Get-FakeWebClient) -UpdatePathUrl "http://x/" -EngineDirPath $Script:engineDir -TempFilePath $Script:tempDir -Platform $Script:platform -Engine $Script:engine

        $pkgDir = Join-Path $Script:engineDir "amd64\Microsoft\Package\2112342123"
        Test-Path (Join-Path $pkgDir "sub1") | Should -BeTrue
        Test-Path (Join-Path $pkgDir "sub2") | Should -BeTrue
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
}

