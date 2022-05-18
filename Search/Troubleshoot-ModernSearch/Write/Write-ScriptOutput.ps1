# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Write-LogInformation.ps1
function Write-ScriptOutput {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [switch]$Diagnostic
    )

    process {

        if (($Diagnostic -and
                $VerbosePreference) -or
            -not ($Diagnostic)) {
            $Object | Write-Output
        }

        Write-LogInformation $Object -VerboseEnabled $false
    }
}
