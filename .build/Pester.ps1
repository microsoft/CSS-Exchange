# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Load-Module.ps1

if (-not (Load-Module -Name Pester -MinimumVersion 5.2.0)) {
    throw "Pester module could not be loaded"
}

$root = Get-Item "$PSScriptRoot\.."
$scripts = @(Get-ChildItem -Recurse $root |
        Where-Object { $_.Name -like "*.Tests.ps1" }).FullName

foreach ($script in $scripts) {
    Invoke-Pester -Path $script
}
