# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Used for common pester testing actions

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

$scriptContent = Get-ExpandedScriptContent -File "$Script:parentPath\Analyzer\Invoke-AnalyzerEngine.ps1"
$scriptContentString = [string]::Empty
$scriptContent | ForEach-Object { $scriptContentString += "$($_)`n" }
Invoke-Expression $scriptContentString

$internalFunctions = New-Object 'System.Collections.Generic.List[string]'
$scriptContent = Get-ExpandedScriptContent -File "$Script:parentPath\DataCollection\ExchangeInformation\Get-HealthCheckerExchangeServer.ps1"
$startIndex = $scriptContent.Trim().IndexOf($Script:PesterExtract)
for ($i = $startIndex + 1; $i -lt $scriptContent.Count; $i++) {
    if ($scriptContent[$i].Trim().Contains($Script:PesterExtract.Replace("Start", "End"))) {
        $endIndex = $i
        break
    }
    $internalFunctions.Add($scriptContent[$i])
}

$scriptContent.RemoveRange($startIndex, $endIndex - $startIndex)
$scriptContentString = [string]::Empty
$internalFunctionsString = [string]::Empty
$scriptContent | ForEach-Object { $scriptContentString += "$($_)`n" }
$internalFunctions | ForEach-Object { $internalFunctionsString += "$($_)`n" }
Invoke-Expression $scriptContentString
Invoke-Expression $internalFunctionsString

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
