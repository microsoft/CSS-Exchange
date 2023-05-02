# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Write-ErrorInformation.ps1

# Compress the data that we typically would like to collect to a single file
# This makes it easier for data to be uploaded.
function Write-LogsToZip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )
    process {
        Write-Verbose "Compressing the following files:"
        $LiteralPath | Write-Verbose
        Write-Verbose "To the following location: $DestinationPath"
        $params = @{
            LiteralPath     = $LiteralPath
            DestinationPath = $DestinationPath
            ErrorAction     = "Stop"
        }
        try {
            Compress-Archive @params
            Write-Host "Successful compressed the data to $DestinationPath"
        } catch {
            Write-Host "Failed to compress the files."
            Write-HostErrorInformation
            Write-Host "The following files need to be collected manually:"
            $LiteralPath | Write-Host
        }
    }
}
