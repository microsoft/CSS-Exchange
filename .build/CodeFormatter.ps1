[CmdletBinding()]
param(
    [Switch]
    $Save
)

#Requires -Version 7

if ($null -eq (Get-Module -Name PSScriptAnalyzer)) {
    Install-Module -Name PSScriptAnalyzer -Force
}

$repoRoot = Get-Item "$PSScriptRoot\.."

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory | Where-Object {
    $_.Name -ne "dist" } | ForEach-Object { Get-ChildItem -Path $_.FullName -Include "*.ps1", "*.psm1" -Recurse } | ForEach-Object { $_.FullName }
$filesFailed = $false

foreach ($file in $scriptFiles) {

    $before = Get-Content $file -Raw
    $after = Invoke-Formatter -ScriptDefinition (Get-Content $file -Raw) -Settings $repoRoot\PSScriptAnalyzerSettings.psd1

    if ($before -ne $after) {
        Write-Warning ("{0}:" -f $file)
        Write-Warning ("Failed to follow the same format defined in the repro")
        if ($Save) {
            try {
                Set-Content -Path $file -Value $after -Encoding utf8NoBOM
                Write-Information "Saved $file with formatting corrections."
            } catch {
                $filesFailed = $true
                Write-Warning "Failed to save $file with formatting corrections."
            }
        } else {
            $filesFailed = $true
            git diff ($($before) | git hash-object -w --stdin) ($($after) | git hash-object -w --stdin)
        }
    }

    $analyzerResults = Invoke-ScriptAnalyzer -Path $file -Settings $repoRoot\PSScriptAnalyzerSettings.psd1
    if ($null -ne $analyzerResults) {
        $filesFailed = $true
        $analyzerResults | Format-Table -AutoSize
    }
}

if ($filesFailed) {
    throw "Failed to match coding formatting requirements"
}
