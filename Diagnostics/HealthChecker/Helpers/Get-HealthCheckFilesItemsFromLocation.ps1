# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-HealthCheckFilesItemsFromLocation {
    $items = Get-ChildItem $XMLDirectoryPath | Where-Object { $_.Name -like "HealthChecker-*-*.xml" }

    if ($null -eq $items) {
        Write-Host("Doesn't appear to be any Health Check XML files here....stopping the script")
        exit
    }
    return $items
}
