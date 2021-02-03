# Invoke-BuildPipeline.ps1 - used to start the build and test process from a single script.
param(
    [switch]$CodeFormatCheck,
    [bool]$BuildScript = $true,
    [string]$ConfigFile,
    [object]$ScriptVersion
)

if ([string]::IsNullOrEmpty($ConfigFile)) {
    $ConfigFile = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace ".ps1", ".config.json"
}

if (!(Test-Path $ConfigFile)) {
    throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid ConfigFile"
}

$content = Get-Content $ConfigFile
$jsonConfig = $content | ConvertFrom-Json

$repoRoot = Get-Item "$PSScriptRoot\.."

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory | Where-Object {
    $_.Name -ne ($PSScriptRoot.Replace("$([IO.Path]::GetDirectoryName($PSScriptRoot))\", "")) } | ForEach-Object { 
    Get-ChildItem -Path $_.FullName *.ps1 -Recurse } | ForEach-Object { $_.FullName }

if ($CodeFormatCheck) {

    $filesFailed = $false
    foreach ($file in $scriptFiles) {

        $scriptFormatter = .\Invoke-CodeFormatter.ps1 -ScriptLocation $file -CodeFormattingLocation .\CodeFormatting.psd1 -ScriptAnalyzer -ExcludeRules $jsonConfig.ScriptAnalyzerExcludeRules.RuleName

        if ($scriptFormatter.StringContent -ne $scriptFormatter.FormattedScript -or
            $null -ne $scriptFormatter.AnalyzedResults) {

            $filesFailed = $true
            Write-Host ("{0}:" -f $file)

            if ($scriptFormatter.StringContent -ne $scriptFormatter.FormattedScript) {
                Write-Host ("Failed to follow the same format defined in the repro")
            }
            
            if ($null -ne $scriptFormatter.AnalyzedResults) {
                Write-Host ("Failed Results from Invoke-PSScriptAnalyzer:")
            }
            $scriptFormatter.AnalyzedResults | Format-Table -AutoSize
            Write-Host("`r`n`r`n")
        }
    }

    if ($filesFailed) {

        throw "Failed to match coding formatting requirements for the project"
    }
}

if ($BuildScript) {
    foreach ($configItem in $jsonConfig) {
        if (!$configItem.BuildScriptDisabled) {

            if ($null -ne $ScriptVersion) {
                .\Invoke-BuildScript.ps1 -ScriptFiles $scriptFiles -NewScriptVersion ("$($ScriptVersion.Major).$($ScriptVersion.Minor).$($ScriptVersion.BuildRevision)")
            } else {
                .\Invoke-BuildScript.ps1 -ScriptFiles $scriptFiles
            }
        }
    }
}
