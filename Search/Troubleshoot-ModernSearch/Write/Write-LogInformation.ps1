# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-LogInformation {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [bool]$VerboseEnabled = $VerbosePreference
    )

    process {
        $Object | Out-File -FilePath $Script:ScriptLogging -Append
    }
}
