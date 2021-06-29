# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Write-ScriptDebug {
    param(
        [Parameter(Mandatory = $true)]$WriteString
    )
    Write-DebugLog $WriteString

    if ($PassedInfo.ScriptDebug -or $Script:ScriptDebug) {
        Write-Host("[{0} - Script Debug] : {1}" -f $env:COMPUTERNAME, $WriteString) -ForegroundColor Cyan
    }
}
