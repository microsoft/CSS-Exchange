# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-EventLogInformation {
    [CmdletBinding()]
    [OutputType("System.Collections.Hashtable")]
    param(
        [ScriptBlock]$CatchActionFunction
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $results = @{}
        foreach ($log in @("Application", "System")) {
            try {
                $lastLogEntry = Get-WinEvent -LogName $log -Oldest -MaxEvents 1
                $listLog = Get-WinEvent -ListLog $log
                $results.Add($log, ([PSCustomObject]@{
                            LastLogEntry = $lastLogEntry.TimeCreated
                            MaxSize      = $listLog.MaximumSizeInBytes
                            FileSize     = $listLog.FileSize
                            LogMode      = $listLog.LogMode.ToString()
                            IsEnabled    = $listLog.IsEnabled
                            LogFilePath  = $listLog.LogFilePath
                        }))
            } catch {
                Write-Verbose "Failed to get Event Log '$log'. Inner Exception: $_"
                Invoke-CatchActionError $CatchActionFunction
            }
        }

        return $results
    }
}
