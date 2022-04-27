# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\GetTagsFromFileContent.ps1

function GetSelectionTable($tags) {
    $selectionTable = @($tags | ForEach-Object {
            [PSCustomObject]@{
                name       = $_.name
                isSelected = $false
                tags       = @($_.tags | ForEach-Object {
                        [PSCustomObject]@{
                            name       = $_.name
                            isSelected = $false
                            scenarios  = @()
                        }
                    })
            }
        })

    return $selectionTable
}

$allTags = GetTagsFromFileContent (Get-Content $PSScriptRoot\tags.txt)
$selectionTable = GetSelectionTable $allTags
$scenarioFiles = Get-ChildItem $PSScriptRoot\Scenarios\*.txt
foreach ($scenarioFile in $scenarioFiles) {
    $scenarioName = $scenarioFile.BaseName
    $scenarioTags = GetTagsFromFileContent (Get-Content $scenarioFile)
    foreach ($category in $scenarioTags) {
        foreach ($tag in $category.tags) {
            $selectionTable | Where-Object name -EQ $category.name | Select-Object -ExpandProperty tags | Where-Object name -EQ $tag.name | ForEach-Object {
                $_.scenarios += $scenarioName
            }
        }
    }
}

$selectionTable | ConvertTo-Json -Depth 4 | Out-File $PSScriptRoot\SelectionTable.json -Encoding utf8
