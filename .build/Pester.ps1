# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Load-Module.ps1

if (-not (Load-Module -Name Pester -MinimumVersion 5.2.0)) {
    throw "Pester module could not be loaded"
}

$root = Get-Item "$PSScriptRoot\.."
$scripts = @(Get-ChildItem -Recurse $root |
        Where-Object { $_.Name -like "*.Tests.ps1" }).FullName

$failPipeline = $false
foreach ($script in $scripts) {
    $result = Invoke-Pester -Path $script -PassThru

    if ($result.Result -eq "Failed") {
        $failPipeline = $true
    }
}

if ($failPipeline) {
    throw "Failed Pester Testing Results"
}
