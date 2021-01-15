Function Write-ScriptDebug {
    param(
        [Parameter(Mandatory = $true)]$stringData
    )
    Write-DebugLog $stringData

    if ($PassedInfo.ScriptDebug -or $Script:ScriptDebug) {
        Write-Host("[{0} - Script Debug] : {1}" -f $env:COMPUTERNAME, $stringData) -ForegroundColor Cyan
    }
}