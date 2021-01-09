# Invoke-BuildPipeline.ps1 - used to start the build and test process from a single script.
param(
    [switch]$CodeFormatCheck,
    [bool]$BuildScript = $true,
    [string]$ConfigFile
)

if ([string]::IsNullOrEmpty($ConfigFile)) {
    $ConfigFile = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace ".ps1", ".config.json"
}

if (!(Test-Path $ConfigFile)) {
    throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid ConfigFile"
}

$content = Get-Content $ConfigFile
$jsonConfig = $content | ConvertFrom-Json

if ($CodeFormatCheck) {

    $allFiles = @()

    foreach ($configItem in $jsonConfig.FilePaths) {
        [string]$path = $configItem.Path
        
        if ($path.EndsWith("\")) {

            if ($configItem.IncludeRecurse) {
                $files = Get-ChildItem $path -Recurse | Where-Object { $_.Name.EndsWith(".ps1") }
            } else {
                $files = Get-ChildItem $path | Where-Object { $_.Name.EndsWith(".ps1") }
            }
            
            foreach ($item in $files) {
                if (!$allFiles.Contains($item.VersionInfo.FileName)) {
                    $allFiles += $item.VersionInfo.FileName
                }
            }
        } elseif (!$allFiles.Contains($path)) {
            $allFiles += (Get-ChildItem $path).VersionInfo.FileName
        }
    }

    $filesFailed = $false
    foreach ($file in $allFiles) {

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
            }
            
            Write-Output("{0}`r`n`r`n" -f $scriptFormatter.AnalyzedResults)
        }
    }

    if ($filesFailed) {

        throw "Failed to match coding formatting requirements for the project"
    }
}

if ($BuildScript) {
    foreach ($configItem in $jsonConfig) {
        if (!$configItem.BuildScriptDisabled) {
            .\Invoke-BuildScript.ps1 -Configuration $configItem
        }
    }
}
