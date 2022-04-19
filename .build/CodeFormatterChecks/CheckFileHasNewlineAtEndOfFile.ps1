# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckFileHasNewlineAtEndOfFile {
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

    $content = Get-Content -Path $FileInfo.FullName -Raw

    <#
        If developing on Windows, we expect the file to end with `r`n. If developing on Linux, we expect the file to end with `n.
        Therefore, this check should work in both scenarios. In both cases, git should ensure that what is actually committed is
        a file with just `n, thanks to autocrlf which defaults to true on Windows.
    #>
    if (-not ("`n" -eq $content[-1])) {
        if ($Save) {
            try {
                # Set-Content automatically adds a newline, so we don't need to add it ourselves.
                Set-Content -Path $FileInfo.FullName -Value $content -Encoding utf8BOM
                Write-Host "Saved with newline at end of file: $($FileInfo.FullName)"
                $false
            } catch {
                Write-Warning "Failed to save with newline at end: $($FileInfo.FullName)"
                $true
            }
        } else {
            Write-Warning "File has no newline at end of file: $($FileInfo.FullName)"
            $true
        }
    }
}
