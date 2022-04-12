# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Logman\Get-LogmanData.ps1
Function  Save-LogmanExperfwizData {

    $PassedInfo.ExperfwizLogmanName |
        ForEach-Object {
            Get-LogmanData -LogmanName $_ -ServerName $env:COMPUTERNAME
        }
}
