# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Used for common pester testing actions

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
$Script:parentPath = (Split-Path -Parent $PSScriptRoot)
. $PSScriptRoot\..\Helpers\Class.ps1
. $PSScriptRoot\..\..\..\Shared\PesterLoadFunctions.NotPublished.ps1
$scriptContent = Get-PesterScriptContent -FilePath @(
    "$Script:parentPath\Analyzer\Invoke-AnalyzerEngine.ps1",
    "$Script:parentPath\DataCollection\ExchangeInformation\Get-HealthCheckerExchangeServer.ps1"
)

Invoke-Expression $scriptContent

Function SetActiveDisplayGrouping {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name
    )
    $key = $Script:results.DisplayResults.Keys | Where-Object { $_.Name -eq $Name }
    $Script:ActiveGrouping = $Script:results.DisplayResults[$key]
}

Function GetObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name
    )

    ($Script:ActiveGrouping | Where-Object { $_.TestingName -eq $Name }).TestingValue
}

Function GetWriteTypeObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name
    )

    ($Script:ActiveGrouping | Where-Object { $_.TestingName -eq $Name }).WriteType
}

Function TestObjectMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 2)]
        [object]$ResultValue,

        [Parameter(Position = 3)]
        [string]$WriteType = "Grey"
    )

    GetObject $Name |
        Should -Be $ResultValue
    GetWriteTypeObject $Name |
        Should -Be $WriteType
}
