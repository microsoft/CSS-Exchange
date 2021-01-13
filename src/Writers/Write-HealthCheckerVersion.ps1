Function Write-HealthCheckerVersion {

    if (([DateTime]::Parse($scriptBuildDate)).AddDays(10) -lt [DateTime]::Now) {
        $currentVersion = Test-ScriptVersion -ApiUri "api.github.com" -RepoOwner "dpaulson45" `
            -RepoName "HealthChecker" `
            -CurrentVersion $scriptVersion `
            -DaysOldLimit 90 `
            -CatchActionFunction ${Function:Invoke-CatchActions}
    } else { $currentVersion = $true }

    $Script:DisplayedScriptVersionAlready = $true

    if ($currentVersion) {
        Write-Green("Exchange Health Checker version {0}" -f $scriptVersion)
    } else {
        Write-Yellow("Exchange Health Checker version {0}. This script is probably outdated. Please verify before relying on the results." -f $scriptVersion)
    }
}