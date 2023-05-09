# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-LogInformation {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object]$Object
    )

    process {
        $Script:ScriptLogger = $Script:ScriptLogger | Write-LoggerInstance $Object
        $Object | Write-DebugLogInformation
    }
}

function Write-DebugLogInformation {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object]$Object
    )

    process {
        $Script:ScriptDebugLogger = $Script:ScriptDebugLogger | Write-LoggerInstance $Object
    }
}
