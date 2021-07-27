# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param (

)

#Requires -Version 7

. $PSScriptRoot\BuildFunctions\Get-ScriptProjectMostRecentCommit.ps1
. $PSScriptRoot\BuildFunctions\Get-ExpandedScriptContent.ps1

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
    Never release scripts in these folders
#>

$excludedFolders = @(".build", "dist", "Shared")

<#
    File names must be unique across the repo since we release in a flat structure.
#>

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory |
    Where-Object { -not $excludedFolders.Contains($_.Name) } |
    ForEach-Object { Get-ChildItem -Path $_.FullName *.ps1 -Recurse } |
    Where-Object { -not $_.Name.Contains(".Tests.ps1") -and
        -not $_.Name.Contains(".NotPublished.ps1") } |
    Sort-Object Name |
    ForEach-Object { $_.FullName }

<#
    Remove from the list any files that are dot-sourced by other files.
#>

$scriptFiles = $scriptFiles | Where-Object {
    $fullName = $_
    $scriptName = [IO.Path]::GetFileName($_)
    $pattern = "\. .*\\$scriptName"
    $m = $scriptFiles | Get-Item | Select-String -Pattern $pattern
    $r = $m | Where-Object { $_.Path -ne $fullName }
    $r.Count -lt 1
}

$nonUnique = @($scriptFiles | ForEach-Object { [IO.Path]::GetFileName($_) } | Group-Object | Where-Object { $_.Count -gt 1 })
if ($nonUnique.Count -gt 0) {
    $nonUnique | ForEach-Object {
        Write-Error "Ambiguous filename: $($_.Name)"
    }

    return
}

# Build the files

$scriptVersions = @()

$disclaimer = [IO.File]::ReadAllLines("$PSScriptRoot\..\LICENSE")

$scriptFiles | ForEach-Object {
    $scriptName = [IO.Path]::GetFileName($_)

    # Expand the embedded files
    $expandedScript = Get-ExpandedScriptContent $_

    # Add the version information
    $commitTime = Get-ScriptProjectMostRecentCommit $_
    $buildVersionString = $commitTime.ToString("yy.MM.dd.HHmm")
    Write-Host ("Setting version for script '$_' to $buildVersionString")

    # Set version variable if present
    for ($i = 0; $i -lt $expandedScript.Count; $i++) {
        $line = $expandedScript[$i]
        if ($line.Contains("`$BuildVersion = `"`"")) {
            $newLine = $line.Replace("`$BuildVersion = `"`"", "`$BuildVersion = `"$buildVersionString`"")
            Write-Host $newLine
            $expandedScript.RemoveAt($i)
            $expandedScript.Insert($i, $newLine)
        }
    }


    #Remove common comments
    $linesToRemove = @("# Copyright (c) Microsoft Corporation.", "# Licensed under the MIT License.")

    foreach ($comment in $linesToRemove) {

        while ($expandedScript.Contains($comment)) {
            $expandedScript.RemoveAt($expandedScript.IndexOf($comment))
        }
    }

    # Stamp version in comments
    if (-not ([string]::IsNullOrWhiteSpace($expandedScript[0]))) {
        $expandedScript.Insert(0, "")
    }

    $expandedScript.Insert(0, "# Version $buildVersionString")

    # Add disclaimer
    $expandedScript.Insert(0, "")
    $expandedScript.Insert(0, "#>")
    $expandedScript.InsertRange(0, $disclaimer)
    $expandedScript.Insert(0, "<#")

    Set-Content -Path (Join-Path $distFolder $scriptName) -Value $expandedScript -Encoding utf8BOM
    $scriptVersions += [PSCustomObject]@{
        File    = $scriptName
        Version = $buildVersionString
    }
}

# Generate version text for release description

$versionFile = "$distFolder\ScriptVersions.txt"
New-Item -Path $versionFile -ItemType File | Out-Null
"Script | Version" | Out-File $versionFile -Append
"-------|--------" | Out-File $versionFile -Append
foreach ($script in $scriptVersions) {
    "$($script.File) | $($script.Version)" | Out-File $versionFile -Append
}

# Generate version CSV for script version checks

$scriptVersions | Export-Csv -Path "$distFolder\ScriptVersions.csv" -NoTypeInformation

$otherFiles = Get-ChildItem -Path $repoRoot -Directory |
    Where-Object { $_.Name -ne ".build" } |
    ForEach-Object { Get-ChildItem -Path $_.FullName *.nse -Recurse } |
    Sort-Object Name |
    ForEach-Object { $_.FullName }

$otherFiles | ForEach-Object {
    Copy-Item $_ $distFolder
}
