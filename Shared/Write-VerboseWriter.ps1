# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
