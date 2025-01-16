# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param (

)

#Requires -Version 7

Set-StrictMode -Version Latest

. $PSScriptRoot\BuildFunctions\Get-ScriptProjectMostRecentCommit.ps1
. $PSScriptRoot\BuildFunctions\Get-ExpandedScriptContent.ps1
. $PSScriptRoot\BuildFunctions\Get-ScriptDependencyHashtable.ps1
. $PSScriptRoot\BuildFunctions\Get-FileTimestampHashtable.ps1
. $PSScriptRoot\BuildFunctions\Get-ScriptDependencyTree.ps1
. $PSScriptRoot\BuildFunctions\Show-ScriptDependencyTree.ps1

Write-Host "Build process is running on: Windows? $IsWindows - MacOS? $IsMacOS - Linux? $IsLinux"

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
    Never release scripts in these folders. We don't included
    Shared here, because we still want to check if those scripts
    are referenced.
#>

$excludedFolders = @(".build", "dist")

$allScriptFiles = Get-ChildItem -Path $repoRoot -Directory |
    Where-Object { -not $excludedFolders.Contains($_.Name) } |
    ForEach-Object { Get-ChildItem -Path $_.FullName *.ps1 -Recurse } |
    Where-Object { -not $_.Name.Contains(".Tests.ps1") } |
    Sort-Object Name |
    ForEach-Object { $_.FullName }

<#
    Build the table of dependencies, and a separate table of commit times.
#>

$dependencyHashtable = Get-ScriptDependencyHashtable -FileNames $allScriptFiles

# In this file, the key is the script, and the value is the list of files that it imports.
$dependencyHashtable | Export-Clixml -Path "$distFolder\dependencyHashtable.xml"

$dependentHashtable = @{}
foreach ($k in $dependencyHashtable.Keys) {
    foreach ($script in $dependencyHashtable[$k]) {
        if ($dependentHashtable.ContainsKey($script)) {
            $dependentHashtable[$script] += $k
        } else {
            $dependentHashtable[$script] = @($k)
        }
    }
}

# In this file, the key is the script, and the value is the list of files that import it.
$dependentHashtable | Export-Clixml -Path "$distFolder\dependentHashtable.xml"

$commitTimeHashtable = Get-FileTimestampHashtable -DependencyHashtable $dependencyHashtable

$commitTimeHashtable | Export-Clixml -Path "$distFolder\commitTimeHashtable.xml"

Write-Verbose $commitTimeHashtable | Format-Table -AutoSize

<#
    Unreferenced scripts are scripts that are not imported into any other script.
#>

$unreferencedScriptFiles = @($allScriptFiles | Where-Object {
        foreach ($k in $dependencyHashtable.Keys) {
            if ($dependencyHashtable[$k] -contains $_) {
                return $false
            }
        }

        return $true
    })

$unreferencedSharedScriptFiles = @($unreferencedScriptFiles | Where-Object {
        $_.StartsWith("$repoRoot\Shared\")
    })

<#
    Get the names of all doc files and determine which scripts are documented.
    Only documented script files will be included in the release. We remove
    top-level Shared scripts from both of these lists, as doc state is not
    relevant for those.
#>

$docFileNames = Get-ChildItem -Path $repoRoot\docs\*.md -Recurse | ForEach-Object {
    if ($_.Name -ne "index.md") {
        [IO.Path]::GetFileNameWithoutExtension($_.Name)
    } else {
        $_.Directory.Name
    }
}

$undocumentedScriptFiles = @($allScriptFiles | Where-Object {
        $scriptName = [IO.Path]::GetFileNameWithoutExtension($_)
        -not $_.StartsWith("$repoRoot\Shared") -and -not $docFileNames.Contains("$scriptName")
    })

$documentedScriptFiles = @($allScriptFiles | Where-Object {
        $scriptName = [IO.Path]::GetFileNameWithoutExtension($_)
        -not $_.StartsWith("$repoRoot\Shared") -and $docFileNames.Contains("$scriptName")
    })

<#
    File names must be unique for documented script files, because we release in a flat structure.
#>

$nonUnique = @($documentedScriptFiles | ForEach-Object { [IO.Path]::GetFileName($_) } | Group-Object | Where-Object { $_.Count -gt 1 })
if ($nonUnique.Count -gt 0) {
    $nonUnique | ForEach-Object {
        Write-Error "Ambiguous filename: $($_.Name)"
    }

    return
}

# Build the files

$scriptVersions = @()

$disclaimer = [IO.File]::ReadAllLines([IO.Path]::Combine($PSScriptRoot, "..", "LICENSE"))

$documentedScriptFiles | ForEach-Object {
    $scriptName = [IO.Path]::GetFileName($_)

    # Show the dependency tree for this script
    Write-Host "`nDependency tree for $scriptName"
    $depTree = Get-ScriptDependencyTree -File $_ -DependencyHashtable $dependencyHashtable -Depth 0
    Show-ScriptDependencyTree -DependencyTree $depTree -Timestamps $commitTimeHashtable -Depth 0 | Format-Table
    Write-Host

    # Expand the embedded files
    $expandedScript = Get-ExpandedScriptContent $_

    # Add the version information
    $commitTime = Get-ScriptProjectMostRecentCommit $_ $commitTimeHashtable $dependencyHashtable
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

<#
    Warn about unreferenced Shared scripts, just so we don't leave dead code lying around
    unnoticed.
#>

if ($unreferencedSharedScriptFiles.Count -gt 0) {
    Write-Host
    Write-Warning "The following scripts are unreferenced and in the root Shared folder:"
    $unreferencedSharedScriptFiles | ForEach-Object { Write-Warning $_ }
}

<#
    Warn about scripts that are both undocumented and unreferenced if they are not explicitly
    excluded from publishing via the filename.
#>

$unreferencedAndUndocumentedScriptFiles = @($unreferencedScriptFiles | Where-Object {
        $undocumentedScriptFiles.Contains($_) -and -not $_.Contains(".NotPublished.")
    })

if ($unreferencedAndUndocumentedScriptFiles.Count -gt 0) {
    Write-Host
    Write-Warning "The following scripts are undocumented, unreferenced, and do not declare NotPublished in the filename:"
    $unreferencedAndUndocumentedScriptFiles | ForEach-Object { Write-Warning $_ }
}
