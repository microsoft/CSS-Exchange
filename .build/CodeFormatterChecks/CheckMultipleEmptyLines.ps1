# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckMultipleEmptyLines {
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

    if ($FileInfo.Extension -eq ".ps1" -or $FileInfo.Extension -eq ".psm1") {
        $content = Get-Content -Path $FileInfo.FullName -Raw
        $errorsReturned = $null
        $tokens = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errorsReturned)
        if ($errorsReturned.Count -gt 0) {
            Write-Warning "Failed to tokenize script: $($FileInfo.FullName)."
            return $true
        }

        $newLineTokens = $tokens | Where-Object { $_.Type -eq "NewLine" }
        $index = 0
        $foundProblem = $false
        $locationPadding = 0
        while ($index -lt $newLineTokens.Count) {
            $current = $newLineTokens[$index]

            if ($current.StartColumn -eq 1 -and
            ($index + 1) -lt $newLineTokens.Count -and
                $newLineTokens[$index + 1].StartColumn -eq 1 -and
                $newLineTokens[$index + 1].Start -eq ($current.Start + 2)) {
                $foundProblem = $true
                if (-not $Save) {
                    Write-Warning "Multiple New Lines starting at position $($current.Start) in file $($FileInfo.FullName)"
                } else {
                    $content = $content.Remove($current.Start - $locationPadding, 2)
                    Write-Host "Removed line entry at position $($current.Start) with padding of $locationPadding"
                    $locationPadding += 2
                }
            }
            $index++
        }

        if ($foundProblem) {
            if ($Save) {
                Set-Content -Path $FileInfo.FullName -Value $content.TrimEnd() -Encoding utf8BOM
                return $true
            } else {
                return $true
            }
        }
    }
    return $false
}
