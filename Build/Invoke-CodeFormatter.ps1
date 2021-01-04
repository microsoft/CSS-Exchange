# Invoke-CodeFormatter.ps1 - used for formatting code and to verify that the code that is attempted to be checked in, passes the formatting structure of the project.
param(
    [string]$ScriptLocation,
    [string]$CodeFormattingLocation,
    [switch]$ReturnFormattedScript
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

try {

    if ($null -eq (Get-Module -Name PSScriptAnalyzer)) {
        Install-Module -Name PSScriptAnalyzer -Force
    }

    $formattedScript = Invoke-Formatter $stringContent -Settings $CodeFormattingLocation

    if ($ReturnFormattedScript) {
        return $formattedScript
    }

    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($ScriptLocation)
    $formattedScript | Out-File -FilePath ($ScriptLocation.Replace($fileName, ($fileName + ".Formatted")))
}
catch {
    throw
}
