Function Remove-EventLogChar {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Function name fits')]
    param(
        [string]$location
    )
    Get-ChildItem $location | Rename-Item -NewName { $_.Name -replace "%4", "-" }
}