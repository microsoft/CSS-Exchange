# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-CatchActions {
    param(
        [object]$CopyThisError = $Error[0]
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $Script:ErrorsExcludedCount++
    $Script:ErrorsExcluded += $CopyThisError
    Write-Verbose "Error Excluded Count: $Script:ErrorsExcludedCount"
    Write-Verbose "Error Count: $($Error.Count)"
    Write-Verbose $CopyThisError

    if ($null -ne $CopyThisError.ScriptStackTrace) {
        Write-Verbose $CopyThisError.ScriptStackTrace
    }
}
