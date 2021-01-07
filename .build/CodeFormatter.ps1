[CmdletBinding()]
param(
)

$repoRoot = Get-Item "$PSScriptRoot\.."

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory | Where-Object { $_.Name -ne ".build" } | ForEach-Object { Get-ChildItem -Path $_.FullName *.ps1 -Recurse } | ForEach-Object { $_.FullName }
$filesFailed = $false

foreach ($file in $scriptFiles) {

    $scriptFormatter = .\Invoke-CodeFormatter.ps1 -ScriptLocation $file -CodeFormattingLocation .\CodeFormatting.psd1 -ScriptAnalyzer

    if ($scriptFormatter.StringContent -ne $scriptFormatter.FormattedScript -or
        $null -ne $scriptFormatter.AnalyzedResults) {

        $filesFailed = $true
        Write-Host ("{0}:" -f $file)

        if ($scriptFormatter.StringContent -ne $scriptFormatter.FormattedScript) {
            Write-Host ("Failed to follow the same format defined in the repro")
        }
        
        if ($null -ne $scriptFormatter.AnalyzedResults) {
            Write-Host ("Failed Results from Invoke-PSScriptAnalyzer:")
            $scriptFormatter.AnalyzedResults | Format-Table -AutoSize
        }

        Write-Host ("`r`n")
    }
}

if ($filesFailed) {
    throw "Failed to match coding formatting requirements for the project"
}