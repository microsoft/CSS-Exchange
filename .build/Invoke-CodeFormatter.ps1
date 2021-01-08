# Invoke-CodeFormatter.ps1 - used for formatting code and to verify that the code that is attempted to be checked in, passes the formatting structure of the project.
param(
    [string]$ScriptLocation,
    [string]$CodeFormattingLocation,
    [switch]$OutputFormattedScript,
    [switch]$ScriptAnalyzer,
    [array]$ExcludeRules
)

if (!(Test-Path $ScriptLocation)) {
    throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid ScriptLocation"
}

if (!(Test-Path $CodeFormattingLocation)) {
    throw [System.Management.Automation.ParameterBindingException] "Failed to provide valid CodeFormattingLocation"
}

$content = Get-Content $ScriptLocation
$stringContent = [string]::Empty

foreach ($line in $content) {
    $stringContent += "{0}`r`n" -f $line
}

$stringContent = $stringContent.Trim()

try {

    if ($null -eq (Get-Module -Name PSScriptAnalyzer)) {
        Install-Module -Name PSScriptAnalyzer -Force
    }

    $formattedScript = Invoke-Formatter $stringContent -Settings $CodeFormattingLocation
    $formattedScript = $formattedScript.TrimEnd()

    if ($OutputFormattedScript) {
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($ScriptLocation)
        $directory = [System.IO.Path]::GetDirectoryName($ScriptLocation)
        $formattedScript | Out-File -FilePath ("{0}\{1}" -f $directory, $fileName.Replace($fileName, ($fileName + ".Formatted.ps1")))
        return
    }

    $analyzedResults = $null
    if ($ScriptAnalyzer) {
        $params = @{
            Path = $ScriptLocation
        }
        if ($null -ne $ExcludeRules -and
            $ExcludeRules.Count -gt 0) {
                $params.Add("ExcludeRule", $ExcludeRules)
            }
        $analyzedResults = Invoke-ScriptAnalyzer @params
    }

    $results = [PSCustomObject]@{
        StringContent   = $stringContent
        FormattedScript = $formattedScript
        AnalyzedResults = $analyzedResults
    }

    return $results
} catch {
    throw
}
