# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Invoke-CatchBlockActions {
    Write-ScriptDebug -WriteString ("Error Exception: $($Error[0].Exception)")
    Write-ScriptDebug -WriteString ("Error Stack: $($Error[0].ScriptStackTrace)")
    [array]$Script:ErrorsHandled += $Error[0]
}
