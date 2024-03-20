# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckContainsCurlyQuotes {
    [CmdletBinding()]
    [OutputType([boolean])]
    param (
        [Parameter()]
        [System.IO.FileInfo]
        $FileInfo,

        [Parameter()]
        [boolean]
        $Save
    )

    # Skip this file
    if ($FileInfo.FullName -eq "$PSScriptRoot\CheckContainsCurlyQuotes.ps1") {
        return $false
    }

    $curlyQuotes = $FileInfo | Select-String "‘|’|`“|`”"
    if ($curlyQuotes) {
        $content = Get-Content -Path $FileInfo.FullName -Raw
        if ($Save) {
            try {
                $content = $content -replace "‘", "'"
                $content = $content -replace "’", "'"
                $content = $content -replace "`“", '"'
                $content = $content -replace "`”", '"'
                if ($FileInfo.Extension -eq ".ps1") {
                    Set-Content -Path $FileInfo.FullName -Value $content.TrimEnd() -Encoding utf8BOM
                } else {
                    Set-Content -Path $FileInfo.FullName -Value $content.TrimEnd() -Encoding utf8NoBOM
                }

                Write-Host "Saved with curly quotes replaced: $($FileInfo.FullName)"
                $false
            } catch {
                Write-Warning "Failed to save with curly quotes replaced: $($FileInfo.FullName). Error: $_"
                $true
            }
        } else {
            Write-Warning "File contains curly quotes: $($FileInfo.FullName)"
            $curlyQuotes | Out-Host
            $true
        }
    } else {
        $false
    }
}
