#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Common/Write-HostWriters/Write-ScriptMethodHostWriter.ps1
#v21.01.08.2133
Function Write-ScriptMethodHostWriter {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Need to use Write Host')]
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $this.LoggerObject) {
        $this.LoggerObject.WriteHost($WriteString)
    } elseif ($null -eq $this.HostFunctionCaller) {
        Write-Host $WriteString
    } else {
        $this.HostFunctionCaller($WriteString)
    }
}
