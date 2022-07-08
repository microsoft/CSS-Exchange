# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Test-CommandExists {
    param(
        [string]$command
    )

    try {
        if (Get-Command $command -ErrorAction Stop) {
            return $true
        }
    } catch {
        Invoke-CatchActions
        return $false
    }
}
