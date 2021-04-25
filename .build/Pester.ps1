$root = Get-Item "$PSScriptRoot\.."
$scripts = @(Get-ChildItem -Recurse $root |
        Where-Object { $_.Name -like "*.Tests.ps1" }).FullName

foreach ($script in $scripts) {
    Invoke-Pester -Path $script
}
