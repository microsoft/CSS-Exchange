[CmdletBinding()]
param (

)

$repoRoot = Get-Item "$PSScriptRoot\.."

<#
    Create the dist folder. Wipe and recreate if it exists.
#>

$distFolder = "$repoRoot\dist"

if (Test-Path $distFolder) {
    try {
        Remove-Item $distFolder -Recurse -Force
    } catch {
        return
    }
}

New-Item -Path $distFolder -ItemType Directory | Out-Null

<#
    File names must be unique across the repo since we release in a flat structure.
#>

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory |
    Where-Object { $_.Name -ne ".build" } |
    ForEach-Object { Get-ChildItem -Path $_.FullName *.ps1 -Recurse } |
    Sort-Object Name |
    ForEach-Object { $_.FullName }

$otherFiles = Get-ChildItem -Path $repoRoot -Directory |
    Where-Object { $_.Name -ne ".build" } |
    ForEach-Object { Get-ChildItem -Path $_.FullName *.nse -Recurse } |
    Sort-Object Name |
    ForEach-Object { $_.FullName }

$nonUnique = @($scriptFiles | ForEach-Object { [IO.Path]::GetFileName($_) } | Group-Object | Where-Object { $_.Count -gt 1 })
if ($nonUnique.Count -gt 0) {
    $nonUnique | ForEach-Object {
        Write-Error "Ambiguous filename: $($_.Name)"
    }

    return
}

<#
    Remove from the list any files that are dot-sourced by other files.
#>

$scriptFiles = $scriptFiles | Where-Object {
    $scriptName = [IO.Path]::GetFileName($_)
    $pattern = "\. .*\\$scriptName"
    $m = $scriptFiles | Get-Item | Select-String -Pattern $pattern
    $m.Count -lt 1
}

<#
    Copy the remaining files to dist, expand dot-sourced files,
    add disclaimer and version.
#>

$disclaimer = [IO.File]::ReadAllLines("$repoRoot\.build\disclaimer.txt")

$versionFile = "$distFolder\ScriptVersions.txt"
New-Item -Path $versionFile -ItemType File | Out-Null
"# Script Versions" | Out-File $versionFile -Append
"Script | Version" | Out-File $versionFile -Append
"-------|--------" | Out-File $versionFile -Append

$scriptFiles | ForEach-Object {
    $scriptContent = New-Object 'System.Collections.Generic.List[string]'
    $scriptContent.AddRange([IO.File]::ReadAllLines($_))

    $commitTime = [DateTime]::Parse((git log -n 1 --format="%ad" --date=rfc $_))

    # Expand dot-sourced files
    for ($i = 0; $i -lt $scriptContent.Count; $i++) {
        $line = $scriptContent[$i].Trim()
        $m = $line | Select-String "\. \.\\(.*).ps1"

        if ($m.Matches.Count -gt 0) {
            $parentPath = [IO.Path]::GetDirectoryName($_)
            $dotloadedScriptPath = [IO.Path]::Combine($parentPath, $m.Matches[0].Groups[1].Value + ".ps1")
            $dotloadedScriptContent = [IO.File]::ReadAllLines($dotloadedScriptPath)
            $scriptContent.RemoveAt($i)
            $scriptContent.InsertRange($i, $dotloadedScriptContent)
            $commitTimeTest = [DateTime]::Parse((git log -n 1 --format="%ad" --date=rfc $dotloadedScriptPath))

            if ($commitTimeTest -gt $commitTime) {
                $commitTime = $commitTimeTest
                Write-Host ("Changing commit time to: $($commitTime.ToString("yy.MM.dd.HHmm"))")
            }
        }
    }

    # Expand Get-Content calls for local files that are marked -AsByteStream -Raw
    for ($i = 0; $i -lt $scriptContent.Count; $i++) {
        $line = $scriptContent[$i].Trim()
        $m = $line | Select-String "\`$(.+) = Get-Content `"?(\`$PSScriptRoot|\.)\\([\w|\d|\.|\\]+)`"? -AsByteStream -Raw"
        if ($m.Matches.Count -gt 0) {
            $parentPath = [IO.Path]::GetDirectoryName($_)
            $filePath = [IO.Path]::Combine($parentPath, $m.Matches[0].Groups[3].Value)
            $fileAsBase64 = [Convert]::ToBase64String(([IO.File]::ReadAllBytes($filePath)), "InsertLineBreaks")
            $scriptContent.RemoveAt($i)
            [string[]]$linesToInsert = @()
            $linesToInsert += "`$$($m.Matches[0].Groups[1].Value)Base64 = @'"
            $linesToInsert += $fileAsBase64
            $linesToInsert += "'@"
            $linesToInsert += ""
            $linesToInsert += "`$$($m.Matches[0].Groups[1].Value) = [Convert]::FromBase64String(`$$($m.Matches[0].Groups[1].Value)Base64)"
            $scriptContent.InsertRange($i, $linesToInsert)
            $commitTimeTest = [DateTime]::Parse((git log -n 1 --format="%ad" --date=rfc $dotloadedScriptPath))

            if ($commitTimeTest -gt $commitTime) {
                $commitTime = $commitTimeTest
                Write-Host ("Changing commit time to: $($commitTime.ToString("yy.MM.dd.HHmm"))")
            }
        }
    }

    Write-Host ("Setting version for script '$_' to '$($commitTime.ToString("yy.MM.dd.HHmm"))'")
    $version = "# Version $($commitTime.ToString("yy.MM.dd.HHmm"))"
    # Stamp version
    $scriptContent.Insert(0, "")
    $scriptContent.Insert(0, $version)

    # Add disclaimer
    $scriptContent.Insert(0, "")
    $scriptContent.InsertRange(0, $disclaimer)

    "$([IO.Path]::GetFileName($_)) | v$($commitTime.ToString("yy.MM.dd.HHmm"))" | Out-File $versionFile -Append

    Set-Content -Path ([IO.Path]::Combine($distFolder, [IO.Path]::GetFileName($_))) -Value $scriptContent
}

$otherFiles | ForEach-Object {
    Copy-Item $_ $distFolder
}
