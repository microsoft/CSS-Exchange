# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-EnableVSSTracing {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath,

        [Parameter(Mandatory = $true)]
        [bool]
        $Circular
    )

    Write-Host "$(Get-Date) Enabling VSS Tracing..."
    if ($Circular) {
        logman start vss -o $OutputPath\vss.etl -ets -p "{9138500e-3648-4edb-aa4c-859e9f7b7c38}" 0xfff 255 -f bincirc -max 1024 -mode globalsequence
    } else {
        logman start vss -o $OutputPath\vss.etl -ets -p "{9138500e-3648-4edb-aa4c-859e9f7b7c38}" 0xfff 255
    }
}
