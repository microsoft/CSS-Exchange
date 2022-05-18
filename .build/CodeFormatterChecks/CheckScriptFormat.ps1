# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckScriptFormat {
    [CmdletBinding()]
    [OutputType([boolean], [string], [string])]
    param (
        [Parameter()]
        [System.IO.FileInfo]
        $FileInfo,

        [Parameter()]
        [boolean]
        $Save
    )

    if ($FileInfo.Extension -eq ".ps1" -or $FileInfo.Extension -eq ".psm1") {
        $before = Get-Content $FileInfo.FullName -Raw
        $after = Invoke-Formatter -ScriptDefinition $before -Settings $PSScriptRoot\..\..\PSScriptAnalyzerSettings.psd1

        if ($before -ne $after) {
            if ($Save) {
                try {
                    # Invoke-Formatter likes to put two newlines at the end of the file. So, here we TrimEnd(),
                    # and then we let Set-Content automatically add a single newline.
                    $after = $after.TrimEnd()
                    Set-Content -Path $FileInfo.FullName -Value $after -Encoding utf8BOM
                    Write-Host "Saved with formatting corrections: $($FileInfo.FullName)"
                    $false
                } catch {
                    Write-Warning "Failed to save with formatting corrections: $($FileInfo.FullName)"
                    $true
                }
            } else {
                Write-Warning "Code format does not meet requirements: $($FileInfo.FullName)"
                $true
                $before
                $after
            }
        } else {
            $false
        }
    } else {
        $false
    }
}
