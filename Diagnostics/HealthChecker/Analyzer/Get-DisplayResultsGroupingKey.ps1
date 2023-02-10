# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-DisplayResultsGroupingKey {
    param(
        [string]$Name,
        [bool]$DisplayGroupName = $true,
        [int]$DisplayOrder,
        [int]$DefaultTabNumber = 1
    )
    return [PSCustomObject]@{
        Name             = $Name
        DisplayGroupName = $DisplayGroupName
        DisplayOrder     = $DisplayOrder
        DefaultTabNumber = $DefaultTabNumber
    }
}
