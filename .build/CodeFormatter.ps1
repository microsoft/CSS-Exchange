[CmdletBinding()]
param(
)

$repoRoot = Get-Item "$PSScriptRoot\.."

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory | Where-Object { $_.Name -ne ".build" -and
    $_.Name -ne "dist"} | ForEach-Object { Get-ChildItem -Path $_.FullName *.ps1 -Recurse } | ForEach-Object { $_.FullName }
$filesFailed = $false

foreach ($file in $scriptFiles) {

    $scriptFormatter = & $PSScriptRoot\Invoke-CodeFormatter.ps1 -ScriptLocation $file -CodeFormattingLocation $PSScriptRoot\CodeFormatting.psd1 -ScriptAnalyzer -ExcludeRules PSAvoidUsingWriteHost

    if ($scriptFormatter.StringContent -cne $scriptFormatter.FormattedScript -or
        $null -ne $scriptFormatter.AnalyzedResults) {

        $filesFailed = $true
        Write-Host ("{0}:" -f $file)

        if ($scriptFormatter.StringContent -cne $scriptFormatter.FormattedScript) {
            Write-Host ("Failed to follow the same format defined in the repro")
            git diff ($($scriptFormatter.StringContent) | git hash-object -w --stdin) ($($scriptFormatter.FormattedScript) | git hash-object -w --stdin)
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