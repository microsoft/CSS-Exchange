# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckMarkdownFileHasNoBOM {
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

    if ($FileInfo.Extension -eq ".md") {
        $encoding = Get-PsOneEncoding $FileInfo
        if ($encoding.BOM) {
            if ($Save) {
                try {
                    $content = Get-Content $FileInfo.FullName
                    Set-Content -Path $FileInfo.FullName -Value $content -Encoding utf8NoBOM -Force
                    Write-Host "Removed BOM: $($FileInfo.FullName)"
                    $false
                } catch {
                    Write-Warning "MD file has BOM and couldn't be fixed automatically: $($FileInfo.FullName). Exception: $($_.Exception)"
                    $true
                }
            } else {
                Write-Warning "Markdown file has BOM: $($FileInfo.FullName)"
                $true
            }
        }
    } else {
        $false
    }
}
