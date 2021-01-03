Function Remote-Functions {
    param(
        [Parameter(Mandatory = $true)][object]$PassedInfo
    )

    #Add Sub Functions Here
    
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try {
        $Script:VerboseFunctionCaller = ${Function:Write-ScriptDebug}
        $Script:HostFunctionCaller = ${Function:Write-ScriptHost}
        if ($PassedInfo.ByPass -ne $true) {
            Remote-Main
        } else {
            Write-ScriptDebug("Loading common functions")
        }
            
    } catch {
        Write-ScriptHost -WriteString ("An error occurred in Remote-Functions") -ForegroundColor "Red"
        Write-ScriptHost -WriteString ("Error Exception: {0}" -f $Error[0].Exception) -ForegroundColor "Red"
        Write-ScriptHost -WriteString ("Error Stack: {0}" -f $Error[0].ScriptStackTrace) -ForegroundColor "Red"
    } finally {
        $ErrorActionPreference = $oldErrorAction
        Write-ScriptDebug("Exiting: Remote-Functions")
        Write-ScriptDebug("[double]TotalBytesSizeCopied: {0} | [double]TotalBytesSizeCompressed: {1} | [double]AdditionalFreeSpaceCushionGB: {2} | [double]CurrentFreeSpaceGB: {3} | [double]FreeSpaceMinusCopiedAndCompressedGB: {4}" -f $Script:TotalBytesSizeCopied,
            $Script:TotalBytesSizeCompressed, 
            $Script:AdditionalFreeSpaceCushionGB, 
            $Script:CurrentFreeSpaceGB, 
            $Script:FreeSpaceMinusCopiedAndCompressedGB)
    }
}
    