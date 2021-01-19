Function Invoke-CatchBlockActions {
    Write-ScriptDebug -WriteString ("Error Exception: $($Error[0].Exception)")
    Write-ScriptDebug -WriteString ("Error Stack: $($Error[0].ScriptStackTrace)")
    $Script:ErrorsHandled += $Error[0]
}