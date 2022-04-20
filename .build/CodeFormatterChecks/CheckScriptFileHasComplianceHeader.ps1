# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckScriptFileHasComplianceHeader {
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
        $scriptContent = New-Object 'System.Collections.Generic.List[string]'
        $scriptContent.AddRange([IO.File]::ReadAllLines($($FileInfo.FullName)))

        if (-not ($scriptContent[0].Contains("# Copyright (c) Microsoft Corporation.")) -or
            -not ($scriptContent[1].Contains("# Licensed under the MIT License."))) {

            if ($Save) {
                try {
                    $scriptContent.Insert(0, "")
                    $scriptContent.Insert(0, "# Licensed under the MIT License.")
                    $scriptContent.Insert(0, "# Copyright (c) Microsoft Corporation.")
                    Set-Content -Path $FileInfo.FullName -Value $scriptContent -Encoding utf8BOM
                    Write-Host "Added compliance header: $($FileInfo.FullName)"
                    $false
                } catch {
                    Write-Warning "Failed to add compliance header: $($FileInfo.FullName). Exception: $($_.Exception)"
                    $true
                }
            } else {
                Write-Warning "File has no compliance header: $($FileInfo.FullName)"
                $true
            }
        }
    } else {
        $false
    }
}
