# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = '$filesFailed is being used.')]
[CmdletBinding()]
param(
    [Switch]
    $Save
)

#Requires -Version 7

. $PSScriptRoot\Load-Module.ps1

if (-not (Load-Module -Name PSScriptAnalyzer -MinimumVersion "1.20")) {
    throw "PSScriptAnalyzer module could not be loaded"
}

if (-not (Load-Module -Name EncodingAnalyzer)) {
    throw "EncodingAnalyzer module could not be loaded"
}

$repoRoot = Get-Item "$PSScriptRoot\.."

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory | Where-Object {
    $_.Name -ne "dist" } | ForEach-Object { Get-ChildItem -Path $_.FullName -Include "*.ps1", "*.psm1" -Recurse } | ForEach-Object { $_.FullName }
$filesFailed = $false

# MD files must NOT have a BOM
Get-ChildItem -Path $repoRoot -Include *.md -Recurse | ForEach-Object {
    $encoding = Get-PsOneEncoding $_
    if ($encoding.BOM) {
        Write-Warning "MD file has BOM: $($_.FullName)"
        if ($Save) {
            try {
                $content = Get-Content $_
                Set-Content -Path $_.FullName -Value $content -Encoding utf8NoBOM -Force
                Write-Warning "Saved $($_.FullName) without BOM."
            } catch {
                $filesFailed = $true
                throw
            }
        } else {
            $filesFailed = $true
        }
    }
}

foreach ($file in $scriptFiles) {
    # PS1 files must have a BOM
    $encoding = Get-PsOneEncoding $file
    if (-not $encoding.BOM) {
        Write-Warning "File has no BOM: $file"
        if ($Save) {
            try {
                $content = Get-Content $file
                Set-Content -Path $file -Value $content -Encoding utf8BOM -Force
                Write-Warning "Saved $file with BOM."
            } catch {
                $filesFailed = $true
                throw
            }
        } else {
            $filesFailed = $true
        }
    }

    #Check for compliance
    $scriptContent = New-Object 'System.Collections.Generic.List[string]'
    $scriptContent.AddRange([IO.File]::ReadAllLines($file))

    if (-not ($scriptContent[0].Contains("# Copyright (c) Microsoft Corporation.")) -or
        -not ($scriptContent[1].Contains("# Licensed under the MIT License."))) {

        Write-Warning "File doesn't have header compliance set: $file"
        if ($Save) {
            try {
                $scriptContent.Insert(0, "")
                $scriptContent.Insert(0, "# Licensed under the MIT License.")
                $scriptContent.Insert(0, "# Copyright (c) Microsoft Corporation.")
                Set-Content -Path $file -Value $scriptContent -Encoding utf8BOM
            } catch {
                $filesFailed = $true
                throw
            }
        } else {
            $filesFailed = $true
        }
    }

    $reloadFile = $false
    $before = Get-Content $file -Raw
    $after = Invoke-Formatter -ScriptDefinition $before -Settings $repoRoot\PSScriptAnalyzerSettings.psd1

    if ($before -ne $after) {
        Write-Warning ("{0}:" -f $file)
        Write-Warning ("Failed to follow the same format defined in the repro")
        if ($Save) {
            try {
                Set-Content -Path $file -Value $after -Encoding utf8NoBOM
                Write-Information "Saved $file with formatting corrections."
                $reloadFile = $true
            } catch {
                $filesFailed = $true
                Write-Warning "Failed to save $file with formatting corrections."
            }
        } else {
            $filesFailed = $true
            git diff ($($before) | git hash-object -w --stdin) ($($after) | git hash-object -w --stdin)
        }
    }

    if ($reloadFile) {
        $before = Get-Content -Path $file -Raw
    }

    if (-not ([string]::IsNullOrWhiteSpace($before[-1]))) {
        Write-Warning $file
        Write-Warning "Failed to have a whitespace at the end of the file"
        $filesFailed = $true
    }

    $maxRetries = 5

    for ($i = 0; $i -lt $maxRetries; $i++) {

        try {
            $analyzerResults = Invoke-ScriptAnalyzer -Path $file -Settings $repoRoot\PSScriptAnalyzerSettings.psd1 -ErrorAction Stop
            if ($null -ne $analyzerResults) {
                $filesFailed = $true
                $analyzerResults | Format-Table -AutoSize
            }
            break
        } catch {
            Write-Warning "Invoke-ScriptAnalyer failed. Error:"
            $_.Exception | Format-List | Out-Host
            Write-Warning "Retrying in 5 seconds."
            Start-Sleep -Seconds 5
        }
    }

    if ($i -eq $maxRetries) {
        $filesFailed = $true
    }
}

if ($filesFailed) {
    throw "Failed to match coding formatting requirements"
}
