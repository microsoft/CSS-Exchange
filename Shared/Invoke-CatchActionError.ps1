# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}
