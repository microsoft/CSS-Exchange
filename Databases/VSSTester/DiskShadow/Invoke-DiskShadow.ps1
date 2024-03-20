# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Logging\Get-VSSWriter.ps1

function Invoke-DiskShadow {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath
    )

    Write-Host "$(Get-Date) Starting DiskShadow copy."
    Write-Host "  Running the following command:"
    Write-Host "  `"C:\Windows\System32\DiskShadow.exe /s $OutputPath\DiskShadow.dsh /l $OutputPath\DiskShadow.log`""

    #in case the $path and the script location is different we need to change location into the $path directory to get the results to work as expected.
    try {
        $here = (Get-Location).Path
        Set-Location $OutputPath
        DiskShadow.exe /s $OutputPath\DiskShadow.dsh /l $OutputPath\DiskShadow.log
    } finally {
        Set-Location $here
    }
}
