#https://github.com/dpaulson45/PublicPowerShellScripts/blob/master/Functions/Common/Write-VerboseWriters/Write-ScriptMethodVerboseWriter.ps1
#v21.01.08.2133
Function Write-ScriptMethodVerboseWriter {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Need to use Write Host')]
    param(
        [Parameter(Mandatory = $true)][string]$WriteString
    )
    if ($null -ne $this.LoggerObject) {
        $this.LoggerObject.WriteVerbose($WriteString)
    } elseif ($null -eq $this.VerboseFunctionCaller -and
        $this.WriteVerboseData) {
        Write-Host $WriteString -ForegroundColor Cyan
    } elseif ($this.WriteVerboseData) {
        $this.VerboseFunctionCaller($WriteString)
    }
}
