# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Calls the $Script:Logger object to write the data to file only.
Function Write-DebugLog($message) {
    if ($null -ne $message -and
        ![string]::IsNullOrEmpty($message) -and
        $null -ne $Script:Logger) {
        $Script:Logger.WriteToFileOnly($message)
    }
}
