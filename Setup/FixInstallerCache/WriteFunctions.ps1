# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-DebugLog($message) {
    if (-not ([string]::IsNullOrEmpty($message))) {
        $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
    }
}

function Write-HostLog ($message) {
    Write-DebugLog $message
    $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
}
