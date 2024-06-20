# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
function Get-EventLogInformation {
    [CmdletBinding()]
    [OutputType("System.Collections.Hashtable")]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [ScriptBlock]$CatchActionFunction
    )
    process {
        function GetRemoteEventLogInformation {
            $results = @{}
            foreach ($log in @("Application", "System")) {
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
            }

            return $results
        }
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $params = @{
            ComputerName        = $Server
            ScriptBlock         = ${Function:GetRemoteEventLogInformation}
            CatchActionFunction = $CatchActionFunction
        }
        return (Invoke-ScriptBlockHandler @params)
    }
}
