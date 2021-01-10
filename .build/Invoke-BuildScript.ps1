[CmdletBinding()]
param (
    [array]$ScriptFiles,
    [string]$NewScriptVersion
)

<#
    Create the dist folder. Wipe and recreate if it exists.
#>

$distFolder = "$PSScriptRoot\dist"

if (Test-Path $distFolder) {
    try {
        Remove-Item $distFolder -Recurse -Force
    } catch {
        return
    }
}

New-Item -Path $distFolder -ItemType Directory | Out-Null

<#
    Remove from the list any files that are dot-sourced by other files.
#>

$scriptFiles = $ScriptFiles | Where-Object {
    $scriptName = [IO.Path]::GetFileName($_)
    $pattern = "\. .*\\$scriptName"
    $m = $scriptFiles | Get-Item | Select-String -Pattern $pattern
    $m.Count -lt 1
}

$scriptFiles | ForEach-Object {
    $scriptContent = New-Object 'System.Collections.Generic.List[string]'
    $scriptContent.AddRange([IO.File]::ReadAllLines($_))

    # Expand dot-sourced files
    for ($i = 0; $i -lt $scriptContent.Count; $i++) {
        $line = $scriptContent[$i].Trim()
        $m = $line | Select-String "\. \.\\(.*).ps1"

        if ($m.Matches.Count -gt 0) {
            $parentPath = [IO.Path]::GetDirectoryName($_)
            $dotLoadedScriptPath = [IO.Path]::Combine($parentPath, $m.Matches[0].Groups[1].Value + ".ps1")
            $dotLoadedScriptContent = [IO.File]::ReadAllLines($dotLoadedScriptPath)
            $scriptContent.RemoveAt($i)
            $scriptContent.InsertRange($i, $dotLoadedScriptContent)
        }

        if (![string]::IsNullOrEmpty($NewScriptVersion) -and
            $line -eq '$scriptVersion = "1.0.0"') {
            $scriptContent.RemoveAt($i)
            $scriptContent.Insert($i, "`$scriptVersion = `"$NewScriptVersion`"")
        }
    }

    $outputLocation = ([IO.Path]::Combine($distFolder, [IO.Path]::GetFileName($_)))
    Set-Content -Path $outputLocation -Value $scriptContent
    Set-Content -Path ($outputLocation.Replace(".ps1", ".txt")) -Value $scriptContent
}