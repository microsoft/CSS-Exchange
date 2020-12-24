#Template Master: https://raw.githubusercontent.com/dpaulson45/PublicPowerShellScripts/master/Functions/Write-HostWriters/Write-InvokeCommandReturnHostWriter.ps1
#Function Version 1.1
Function Write-InvokeCommandReturnHostWriter {
param(
[Parameter(Mandatory=$true)][string]$WriteString
)
    if($InvokeCommandReturnWriteArray)
    {
        $hashTable = @{"Host"=("[Remote Server: {0}] : {1}" -f $env:COMPUTERNAME, $WriteString)}
        Set-Variable stringArray -Value ($Script:stringArray += $hashTable) -Scope Script
    }
    else 
    {
        Write-HostWriter $WriteString
    }
}