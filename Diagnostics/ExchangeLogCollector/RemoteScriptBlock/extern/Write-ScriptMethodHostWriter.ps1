# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Write-HostWriters/Write-ScriptMethodHostWriter.ps1
#v21.01.22.2212
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
