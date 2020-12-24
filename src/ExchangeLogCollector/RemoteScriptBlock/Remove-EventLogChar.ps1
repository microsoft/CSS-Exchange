Function Remove-EventLogChar {
    param(
        [string]$location 
    )
    Get-ChildItem $location | Rename-Item -NewName { $_.Name -replace "%4", "-" }
}