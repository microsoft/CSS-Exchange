# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Import-MyData {
    param(
        [Parameter(Mandatory = $true)][array]$FilePaths
    )
    [System.Collections.Generic.List[System.Object]]$myData = New-Object -TypeName System.Collections.Generic.List[System.Object]

    foreach ($filePath in $FilePaths) {
        $importData = Import-Clixml -Path $filePath
        $myData.Add($importData)
    }
    return $myData
}
