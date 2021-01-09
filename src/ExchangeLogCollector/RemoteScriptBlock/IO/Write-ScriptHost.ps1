Function Write-ScriptHost {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString,
        [Parameter(Mandatory = $false)][bool]$ShowServer = $true,
        [Parameter(Mandatory = $false)][string]$ForegroundColor = "Gray",
        [Parameter(Mandatory = $false)][bool]$NoNewLine = $false
    )
    if ($ShowServer) {
        Write-Host("[{0}] : {1}" -f $env:COMPUTERNAME, $WriteString) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
    } else {
        Write-Host("{0}" -f $WriteString) -ForegroundColor $ForegroundColor -NoNewline:$NoNewLine
    }
}