[CmdletBinding()]
param (

)

<#
.SYNOPSIS
    Returns the dot-sourced script path from this line of PowerShell
    script, if any.
#>
function Get-DotSourcedScriptName {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Line
    )

    process {
        $m = $Line | Select-String "\. (?:\.|\`$PSScriptRoot)\\(.*).ps1"
        if ($m.Matches.Count -gt 0) {
            $dotloadedScriptPath = $m.Matches[0].Groups[1].Value + ".ps1"
            $dotloadedScriptPath
        }
    }
}

<#
.SYNOPSIS
    Returns the embedded data file info from this line of PowerShell
    script, including the file path and variable name it is assigned to.
#>
function Get-EmbeddedFileInfo {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Line
    )

    process {
        $m = $Line | Select-String "\`$(.+) = Get-Content `"?(\`$PSScriptRoot|\.)\\([\w|\d|\.|\\]+)`"? -AsByteStream -Raw"
        if ($m.Matches.Count -gt 0) {
            [PSCustomObject]@{
                FilePath     = $m.Matches[0].Groups[3].Value
                VariableName = $m.Matches[0].Groups[1].Value
            }
        }
    }
}

<#
.SYNOPSIS
    Returns the embedded file path from this line of PowerShell
    script, if any. This could be a script or a data file.
#>
function Get-EmbeddedFile {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $Line
    )

    process {
        $dotSourcedScript = Get-DotSourcedScriptName $Line
        if ($null -ne $dotSourcedScript) {
            $dotSourcedScript
            return
        }

        $dotSourcedData = Get-EmbeddedFileInfo $Line
        if ($null -ne $dotSourcedData) {
            $dotSourcedData.FilePath
            return
        }
    }
}

<#
.SYNOPSIS
    Gets the list of all embedded scripts and data files in this
    script.
#>
function Get-EmbeddedFileList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter()]
        [string]
        $File,

        [Parameter()]
        [System.Collections.Generic.HashSet[string]]
        $FilesAlreadyAdded = (New-Object 'System.Collections.Generic.HashSet[string]')
    )

    process {
        $files = New-Object 'System.Collections.Generic.List[string]'
        $directoryOfCurrentFile = (Get-Item $File).Directory
        Get-Content $File | Get-EmbeddedFile | ForEach-Object {
            $absolutePath = (Get-Item (Join-Path $directoryOfCurrentFile $_)).FullName
            if ($FilesAlreadyAdded.Add($absolutePath)) {
                $files.Add($absolutePath)
                if ($_ -like "*.ps1") {
                    Get-EmbeddedFileList $absolutePath $FilesAlreadyAdded | ForEach-Object {
                        $files.Add($_)
                    }
                }
            }
        }

        if ($files.Count -gt 0) {
            $files
        }
    }
}

<#
.SYNOPSIS
    Gets the most recent commit, considering all files related to the specified script,
    including any embedded dot-sourced scripts or other files.
#>
function Get-ScriptProjectMostRecentCommit {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $File
    )

    process {
        Write-Verbose "Get-ScriptProjectMostRecentCommit called for file $File"
        $mostRecentCommit = [DateTime]::MinValue
        if ([DateTime]::TryParse((git log -n 1 --format="%ad" --date=rfc $File), [ref] $mostRecentCommit)) {
            Get-EmbeddedFileList $File | ForEach-Object {
                Write-Verbose "Getting commit time for $_"
                $commitTime = [DateTime]::Parse((git log -n 1 --format="%ad" --date=rfc $_))
                if ($commitTime -gt $mostRecentCommit) {
                    $mostRecentCommit = $commitTime
                    Write-Host ("Changing commit time to: $($commitTime.ToString("yy.MM.dd.HHmm"))")
                }
            }
        }

        $mostRecentCommit
    }
}

<#
.SYNOPSIS
    Gets the content of the designated file, embedding the content of
    any dot-sourced scripts or embedded data files.
#>
function Get-ExpandedScriptContent {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[string]])]
    param (
        [Parameter()]
        [string]
        $File,

        [Parameter()]
        [System.Collections.Generic.HashSet[string]]
        $ScriptsAlreadyEmbedded = (New-Object 'System.Collections.Generic.HashSet[string]')
    )

    begin {
        $currentFolder = (Get-Item $File).DirectoryName
        Write-Verbose "Get-ExpandedScriptContent called for file $File"
    }

    process {
        $scriptContent = New-Object 'System.Collections.Generic.List[string]'
        $scriptContent.AddRange([IO.File]::ReadAllLines($File))
        for ($i = 0; $i -lt $scriptContent.Count; $i++) {
            $line = $scriptContent[$i]
            $dotSourcedFile = $line | Get-DotSourcedScriptName
            if ($null -ne $dotSourcedFile) {
                $scriptContent.RemoveAt($i)
                $dotSourcedFile = (Get-Item (Join-Path $currentFolder $dotSourcedFile))
                # Scripts must only be embedded once
                if ($ScriptsAlreadyEmbedded.Add($dotSourcedFile)) {
                    $dotSourcedFileContent = Get-ExpandedScriptContent $dotSourcedFile $ScriptsAlreadyEmbedded
                    $scriptContent.InsertRange($i, $dotSourcedFileContent)
                }
            } else {
                $embeddedFile = $line | Get-EmbeddedFileInfo
                if ($null -ne $embeddedFile) {
                    $absolutePath = (Get-Item (Join-Path $currentFolder $embeddedFile.FilePath)).FullName
                    $fileAsBase64 = [Convert]::ToBase64String(([IO.File]::ReadAllBytes($absolutePath)), "InsertLineBreaks")
                    $scriptContent.RemoveAt($i)
                    [string[]]$linesToInsert = @()
                    $linesToInsert += "`$$($embeddedFile.VariableName)Base64 = @'"
                    $linesToInsert += $fileAsBase64
                    $linesToInsert += "'@"
                    $linesToInsert += ""
                    $linesToInsert += "`$$($embeddedFile.VariableName) = [Convert]::FromBase64String(`$$($embeddedFile.VariableName)Base64)"
                    $scriptContent.InsertRange($i, $linesToInsert)
                }
            }
        }

        Write-Output -NoEnumerate $scriptContent
    }
}

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

# Build the files

$scriptVersions = @()

$disclaimer = [IO.File]::ReadAllLines("$PSScriptRoot\disclaimer.txt")

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

    # Stamp version in comments
    $expandedScript.Insert(0, "")
    $expandedScript.Insert(0, "# Version $buildVersionString")

    # Add disclaimer
    $expandedScript.Insert(0, "")
    $expandedScript.InsertRange(0, $disclaimer)

    Set-Content -Path (Join-Path $distFolder $scriptName) -Value $expandedScript
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
