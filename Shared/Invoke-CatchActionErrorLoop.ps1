# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Invoke-CatchActionErrorLoop {
    [CmdletBinding()]
    param(
        [int]$CurrentErrors,
        [scriptblock]$CatchActionFunction
    )
    process {
        if ($null -ne $CatchActionFunction -and
            $Error.Count -ne $CurrentErrors) {
            $i = 0
            while ($i -lt ($Error.Count - $currentErrors)) {
                & $CatchActionFunction $Error[$i]
                $i++
            }
        }
    }
}
