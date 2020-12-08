Function Invoke-CatchActions{
param(
[object]$CopyThisError
)
    
    Write-VerboseOutput("Calling: Invoke-CatchActions")
    $Script:ErrorsExcludedCount++
    if($CopyThisError -eq $null)
    {
        $Script:ErrorsExcluded += $Error[0]
    }
    else 
    {
        $Script:ErrorsExcluded += $CopyThisError
    }
}