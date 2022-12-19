# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-HealthCheckFilesItemsFromLocation {
    ##This notation will break things if you have other xml files from runs with different parameters like exchangedccoreratio
    ##Filenames to exclude: *ExchangeDCCoreRatio* , all other reports generate txt-reports only
    $items = Get-ChildItem $XMLDirectoryPath | Where-Object { $_.Name -like "HealthChecker-*-*.xml" -and $_.Name -notlike "HealthChecker-ExchangeDCCoreRatio-*.xml"}

    if ($null -eq $items) {
        Write-Host("Doesn't appear to be any Health Check XML files here....stopping the script")
        exit
    }
    return $items
}
