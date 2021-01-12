#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Common/Write-HostWriters/Write-HostWriter.ps1
#v21.01.08.2133

Function Write-HostWriter {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Need to use Write Host')]
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $Script:Logger) {
        $Script:Logger.WriteHost($WriteString)
    } elseif ($null -eq $HostFunctionCaller) {
        Write-Host $WriteString
    } else {
        &$HostFunctionCaller $WriteString
    }
}
