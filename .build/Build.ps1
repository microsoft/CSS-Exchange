[CmdletBinding()]
param (

)

$repoRoot = Get-Item "$PSScriptRoot\.."

Set-Location $repoRoot

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

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory | Where-Object { $_.Name -ne ".build" } | ForEach-Object { Get-ChildItem -Path $_.Name *.ps1 -Recurse } | Foreach-Object { $_.FullName }

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

$version = "# Version " + [DateTime]::Now.ToString("yy.MM.dd.HHmm")
$disclaimer = [IO.File]::ReadAllLines("$repoRoot\.build\disclaimer.txt")

$scriptFiles | Foreach-Object {
    $scriptContent = New-Object 'System.Collections.Generic.List[string]'
    $scriptContent.AddRange([IO.File]::ReadAllLines($_))

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
        }
    }

    # Stamp version
    $scriptContent.Insert(0, "")
    $scriptContent.Insert(0, $version)

    # Add disclaimer
    $scriptContent.Insert(0, "")
    $scriptContent.InsertRange(0, $disclaimer)

    Set-Content -Path ([IO.Path]::Combine($distFolder, [IO.Path]::GetFileName($_))) -Value $scriptContent
}
