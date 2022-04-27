# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetTagsFromFileContent($fileContent) {
    $tags = @($fileContent | ForEach-Object {
            if ($_ -match "(^TraceLevels|^InMemoryTracing|^FilteredTracing)" -or $_.Length -lt 1) {
                # Skip these lines
            } else {
                [PSCustomObject]@{
                    name = $_.Substring(0, $_.IndexOf(':'))
                    tags = @($_.Substring($_.IndexOf(':') + 1).Split(',') | Sort-Object | ForEach-Object {
                            [PSCustomObject]@{
                                name = $_
                            }
                        })
                }
            }
        })

    return $tags
}
