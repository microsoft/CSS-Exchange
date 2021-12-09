# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Write-VerboseWriters/Write-ScriptMethodVerboseWriter.ps1
#v21.01.22.2212
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
