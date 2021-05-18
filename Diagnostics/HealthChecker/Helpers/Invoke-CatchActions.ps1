Function Invoke-CatchActions {
    param(
        [object]$CopyThisError = $Error[0]
    )
    Write-VerboseOutput("Calling: Invoke-CatchActions")
    $Script:ErrorsExcludedCount++
    $Script:ErrorsExcluded += $CopyThisError
    Write-VerboseOutput("Error Excluded Count: $Script:ErrorsExcludedCount")
    Write-VerboseOutput("Error Count: $($Error.Count)")
    Write-VerboseOutput($CopyThisError)

    if ($null -ne $CopyThisError.ScriptStackTrace) {
        Write-VerboseOutput($CopyThisError.ScriptStackTrace)
    }
}
