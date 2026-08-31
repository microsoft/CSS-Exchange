# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CheckBacktickLineContinuation {
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

    if ($FileInfo.Extension -ne ".ps1" -and $FileInfo.Extension -ne ".psm1") {
        return $false
    }

    $content = Get-Content -Path $FileInfo.FullName -Raw
    $errorsReturned = $null
    $tokens = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errorsReturned)
    if ($errorsReturned.Count -gt 0) {
        Write-Warning "Failed to tokenize script: $($FileInfo.FullName)."
        return $true
    }

    $lineContinuations = @($tokens | Where-Object { $_.Type -eq "LineContinuation" })
    foreach ($token in $lineContinuations) {
        Write-Warning "Backtick line continuation at line $($token.StartLine) in file $($FileInfo.FullName)."
    }

    return $lineContinuations.Count -gt 0
}
