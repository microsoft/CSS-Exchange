# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-Result {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$WriteObject
    )
    process {
        if ($WriteObject.WriteType -eq "Warning") {
            $WriteObject.WriteData | Write-Warning
        } elseif ($WriteObject.WriteType -eq "Error") {
            $WriteObject.WriteData | Write-Error
        } elseif ($WriteObject.WriteType -eq "Host") {
            Write-Host $WriteObject.WriteData -ForegroundColor $WriteObject.ForegroundColor
        }
    }
}
