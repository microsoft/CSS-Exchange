# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-VSSWriter {
    [CmdletBinding()]
    param ()

    $writersText = vssadmin list writers
    if ($LASTEXITCODE) {
        Write-Warning $writersText
        throw "Unable to list vss writers"
    }

    $startIndex = 3

    if (-not ($writersText[$startIndex] -like "Writer name*")) {
        Write-Host "Finding the first writer..."
        for ($lineNumber = $startIndex; $lineNumber -lt $writersText.Count; $lineNumber++) {
            if ($writersText[$lineNumber] -like "Writer name*") {
                $startIndex = $lineNumber
                break
            }
        }
    }

    for ($lineNumber = $startIndex; $lineNumber -lt $writersText.Count; $lineNumber += 6) {
        [PSCustomObject]@{
            Name       = $writersText[$lineNumber].Substring($writersText[$lineNumber].IndexOf("'") + 1).TrimEnd("'")
            Id         = $writersText[$lineNumber + 1].Substring($writersText[$lineNumber + 1].IndexOf("{") + 1).TrimEnd("}")
            InstanceId = $writersText[$lineNumber + 2].Substring($writersText[$lineNumber + 2].IndexOf("{") + 1).TrimEnd("}")
            State      = $writersText[$lineNumber + 3].Substring($writersText[$lineNumber + 3].IndexOf(":") + 1).Trim()
            LastError  = $writersText[$lineNumber + 4].Substring($writersText[$lineNumber + 4].IndexOf(":") + 1).Trim()
        }
    }
}
