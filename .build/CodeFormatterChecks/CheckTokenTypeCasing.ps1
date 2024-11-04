# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckTokenTypeCasing {
    [CmdletBinding()]
    [OutputType([boolean])]
    param (
        [Parameter()]
        [System.IO.FileInfo]
        $FileInfo,

        [Parameter()]
        [boolean]
        $Save,

        [Parameter()]
        [ValidateSet("Operator", "Keyword")]
        [string]
        $Type
    )

    if ($FileInfo.Extension -eq ".ps1" -or $FileInfo.Extension -eq ".psm1") {
        $content = Get-Content -Path $FileInfo.FullName -Raw
        $errorsReturned = $null
        $tokens = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errorsReturned)
        if ($errorsReturned.Count -gt 0) {
            Write-Warning "Failed to tokenize script: $($FileInfo.FullName)."
            return $true
        }

        $keywordWrongCase = @()
        foreach ($t in $tokens) {
            if ($t.Type -eq $Type) {
                if (-not $t.Content.Equals($t.Content.ToLower(), "Ordinal")) {
                    $keywordWrongCase += $t

                    if ($Save) {
                        $content = $content.Remove($t.Start, $t.Length).Insert($t.Start, $t.Content.ToLower())
                        Write-Host "Corrected case of $Type`: $($t.Content) at position $($t.Start) in $($FileInfo.FullName)"
                    } else {
                        Write-Warning "$Type $($t.Content) at position $($t.Start) in $($FileInfo.FullName) is not lowercase."
                    }
                }
            }
        }

        if ($keywordWrongCase.Length -gt 0) {
            if ($Save) {
                Set-Content -Path $FileInfo.FullName -Value $content.TrimEnd() -Encoding utf8BOM
                return $false
            } else {
                return $true
            }
        }
    }

    return $false
}
