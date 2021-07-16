# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Write-ScriptHost {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString,
        [Parameter(Mandatory = $false)][bool]$ShowServer = $true,
        [Parameter(Mandatory = $false)][string]$ForegroundColor = "Gray",
        [Parameter(Mandatory = $false)][bool]$NoNewLine = $false
    )
    Write-DebugLog $WriteString

    if ($ShowServer) {

        if ($WriteString.StartsWith("[")) {
            Write-Host ($WriteString.Insert(1, "$env:COMPUTERNAME - ")) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
        } else {
            Write-Host("[{0}] : {1}" -f $env:COMPUTERNAME, $WriteString) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
        }
    } else {
        Write-Host("{0}" -f $WriteString) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
    }
}
