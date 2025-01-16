# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckScriptFileHasBOM {
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

    <#
        We require scripts to have a BOM because:

        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding

        "If you need to use non-ASCII characters in your scripts, save them as UTF-8 with BOM.
        Without the BOM, Windows PowerShell misinterprets your script as being encoded in the
        legacy "ANSI" CodePage. Conversely, files that do have the UTF-8 BOM can be problematic
        on Unix-like platforms."

        Since these scripts are purely for Exchange and Exchange Online, we expect they will usually
        be run from Windows, so we require a BOM to ensure they are seen by Windows Powershell as
        Unicode, not ANSI.
    #>
    if ($FileInfo.Extension -eq ".ps1" -or $FileInfo.Extension -eq ".psm1") {
        $encoding = Get-PsOneEncoding $FileInfo
        if (-not $encoding.BOM) {
            if ($Save) {
                try {
                    $content = Get-Content $FileInfo.FullName
                    Set-Content -Path $FileInfo.FullName -Value $content -Encoding utf8BOM -Force
                    Write-Host "Added BOM: $($FileInfo.FullName)"
                    $false
                } catch {
                    Write-Warning "File has no BOM and couldn't be fixed automatically: $($FileInfo.FullName). Exception: $($_.Exception)"
                    $true
                }
            } else {
                Write-Warning "File has no BOM: $($FileInfo.FullName)"
                $true
            }
        }
    } else {
        $false
    }
}
