#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Common/Write-HostWriters/Write-InvokeCommandReturnHostWriter.ps1
#v21.01.08.2133
Function Write-InvokeCommandReturnHostWriter {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($InvokeCommandReturnWriteArray) {
        $hashTable = @{"Host" = ("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString) }
        Set-Variable stringArray -Value ($Script:stringArray += $hashTable) -Scope Script
    } else {
        Write-HostWriter $WriteString
    }
}
