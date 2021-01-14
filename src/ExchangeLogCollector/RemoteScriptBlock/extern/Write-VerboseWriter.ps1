#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Common/Write-VerboseWriters/Write-VerboseWriter.ps1
#v21.01.11.1818
Function Write-VerboseWriter {
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $Script:Logger) {
        $Script:Logger.WriteVerbose($WriteString)
    } elseif ($null -eq $VerboseFunctionCaller) {
        Write-Verbose $WriteString
    } else {
        &$VerboseFunctionCaller $WriteString
    }
}
