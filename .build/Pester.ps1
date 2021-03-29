$scripts = @(
    "$PSScriptRoot\..\Setup\src\Tests\SetupLogReviewer.Tests.ps1"
)

foreach ($script in $scripts) {
    Invoke-Pester -Path $script
}