# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-CatchBlockActions {
    Write-Verbose "Error Exception: $($Error[0].Exception)"
    Write-Verbose "Error Stack: $($Error[0].ScriptStackTrace)"
    [array]$Script:ErrorsHandled += $Error[0]
}
