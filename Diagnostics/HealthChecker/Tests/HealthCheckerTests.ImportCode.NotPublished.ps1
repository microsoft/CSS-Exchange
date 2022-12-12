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
    "$Script:parentPath\DataCollection\OrganizationInformation\Get-OrganizationInformation.ps1"
)

Invoke-Expression $scriptContent

function SetActiveDisplayGrouping {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name
    )
    $key = $Script:results.DisplayResults.Keys | Where-Object { $_.Name -eq $Name }
    $Script:ActiveGrouping = $Script:results.DisplayResults[$key]
}

function GetObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name
    )

    ($Script:ActiveGrouping | Where-Object { $_.TestingName -eq $Name }).TestingValue
}

function GetWriteTypeObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name
    )

    ($Script:ActiveGrouping | Where-Object { $_.TestingName -eq $Name }).WriteType
}

function TestObjectMatch {
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

function TestOutColumnObjectCompare {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$CompareObject,

        [Parameter(Mandatory = $true)]
        [object]$TestObject
    )
    $properties = ($CompareObject | Get-Member | Where-Object { $_.MemberType -eq "NoteProperty" }).Name
    foreach ($property in $properties) {
        if ($TestObject.$property.Value -ne $CompareObject.$property.Value) {
            Write-Host "Failed Property Value: $property"
        }
        $TestObject.$property.Value | Should -Be $CompareObject.$property.Value

        if ($TestObject.$property.DisplayColor -ne $CompareObject.$property.DisplayColor) {
            Write-Host "Failed Property Display Color: $property"
        }
        $TestObject.$property.DisplayColor | Should -Be $CompareObject.$property.DisplayColor
    }
}

function NewOutColumnCompareValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        [object]$Value,

        [Parameter(Position = 2)]
        [string]$DisplayColor = "Grey"
    )

    return [PSCustomObject]@{
        Value        = $Value
        DisplayColor = $DisplayColor
    }
}
