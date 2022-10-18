# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-SetOutputInstanceLocation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeServerName = $false
    )
    $endName = "-{0}.txt" -f $Script:dateTimeStringFormat

    if ($IncludeServerName) {
        $endName = "-{0}{1}" -f $Server, $endName
    }

    $Script:OutputFullPath = "{0}\{1}{2}" -f $Script:OutputFilePath, $FileName, $endName
    $Script:OutXmlFullPath = $Script:OutputFullPath.Replace(".txt", ".xml")
}
