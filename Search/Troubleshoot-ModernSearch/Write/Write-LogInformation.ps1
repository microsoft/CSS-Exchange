# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Write-LogInformation {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [bool]$VerboseEnabled = $VerbosePreference
    )

    process {

        if ($VerboseEnabled) {
            $Object | Write-Verbose -Verbose
        }

        $Object | Out-File -FilePath $Script:ScriptLogging -Append
    }
}
