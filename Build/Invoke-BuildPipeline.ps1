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
            $files = Get-ChildItem $path | Where-Object { $_.Name.EndsWith(".ps1") }
            foreach ($item in $files) {
                if (!$allFiles.Contains($item.VersionInfo.FileName)) {
                    $allFiles += $item.VersionInfo.FileName
                }
            }
        }
        elseif ($allFiles.Contains($path)) {
            $allFiles += (Get-ChildItem $path).VersionInfo.FileName
        }
    }

    $failedFiles = @()

    foreach ($file in $allFiles) {

        $testFormat = .\Invoke-CodeFormatter.ps1 -ScriptLocation $file -CodeFormattingLocation .\CodeFormatting.psd1 -ReturnFormattedScript

        $content = Get-Content $file

        if ($testFormat -ne $content) {
            $failedFiles += $file
        }
    }

    if ($failedFiles.Count -ge 1) {
        foreach ($failedFile in $failedFiles) {
            Write-Host $failedFile
        }

        throw "Failed to match coding formatting requirements for the project"
    }
}

if ($BuildScript) {
    foreach ($configItem in $jsonConfig) {
        .\Invoke-BuildScript.ps1 -Configuration $configItem
    }
}
