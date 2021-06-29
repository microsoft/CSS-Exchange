# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-DisplayResultsGroupingKey {
    param(
        [string]$Name,
        [bool]$DisplayGroupName = $true,
        [int]$DisplayOrder,
        [int]$DefaultTabNumber = 1
    )
    $obj = New-Object HealthChecker.DisplayResultsGroupingKey
    $obj.Name = $Name
    $obj.DisplayGroupName = $DisplayGroupName
    $obj.DisplayOrder = $DisplayOrder
    $obj.DefaultTabNumber = $DefaultTabNumber
    return $obj
}
