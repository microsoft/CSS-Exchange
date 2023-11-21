# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-VSSWriter.ps1

function Get-VSSWritersAfter {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath
    )

    Write-Host "$(Get-Date) Checking VSS Writer Status: (after backup)"
    $writers = Get-VSSWriter
    $writers | Export-Csv $OutputPath\vssWritersAfter.csv -NoTypeInformation
    $writers | Sort-Object Name | Format-Table | Out-Host
}
