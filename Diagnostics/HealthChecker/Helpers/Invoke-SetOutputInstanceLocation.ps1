# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-SetOutputInstanceLocation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeServerName = $false
    )
    $endName = "-{0}.txt" -f $Script:dateTimeStringFormat

    if ($IncludeServerName) {
        $endName = "-{0}{1}" -f $Server, $endName
    }

    $Script:OutputFullPath = Join-Path -Path $Script:OutputFilePath -ChildPath ('{0}{1}' -f $FileName, $endName)
    $Script:OutXmlFullPath = [System.IO.Path]::ChangeExtension($Script:OutputFullPath, 'xml')
}
