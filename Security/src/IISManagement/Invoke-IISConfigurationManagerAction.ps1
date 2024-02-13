# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ParameterString.ps1
. $PSScriptRoot\Invoke-IISConfigurationRemoteAction.ps1
. $PSScriptRoot\..\..\..\Shared\Write-ErrorInformation.ps1

<#
.DESCRIPTION
    Use this function to execute all the configuration actions against all the servers that you would like for a particular configuration.
    It will execute the Invoke-IISConfigurationRemoteAction function that is designed to be executed locally on that server.
    It will return an object that will provide if everything was configured, backed up, or if any errors did occur.
    If an error did occur, we will log it out here.
#>
function Invoke-IISConfigurationManagerAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$InputObject,

        [string]$ConfigurationDescription = "Configure IIS"
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $serverManagement = New-Object System.Collections.Generic.List[object]
        $failedServers = New-Object System.Collections.Generic.List[object]
        $successfulServers = New-Object System.Collections.Generic.List[object]
        $managerActionProgressParams = @{
            Id              = 0
            Activity        = "Executing $ConfigurationDescription on Servers"
            Status          = [string]::Empty
            PercentComplete = 0
        }
    }
    process {
        $InputObject | ForEach-Object { $serverManagement.Add($_) }
    } end {

        $managerActionProgressCounter = 0
        $managerActionTotalActions = $serverManagement.Count

        foreach ($server in $serverManagement) {
            # Currently, this function is synchronous when executing on each server. Which makes it slow in large environments.
            # Would like to make this multi-threaded to improve performance.
            $managerActionProgressCounter++
            $managerActionProgressParams.Status = "Working on $($server.ServerName)"
            $managerActionProgressParams.PercentComplete = ($managerActionProgressCounter / $managerActionTotalActions * 100)
            Write-Progress @managerActionProgressParams
            $result = Invoke-ScriptBlockHandler -ComputerName $server.ServerName -ArgumentList $server -ScriptBlock ${Function:Invoke-IISConfigurationRemoteAction}

            if ($null -eq $result -or
                $result.ErrorContext.Count -gt 0 -or
                $result.SuccessfulExecution -eq $false) {
                $failedServers.Add($server.ServerName)
                Write-Warning "Failed to execute request on '$($server.ServerName)'. NULL Result: $($null -eq $result)"

                if ($result.ErrorContext.Count -gt 0) {
                    Write-Warning "Error context written out to debug log."
                    $result.ErrorContext | ForEach-Object { Write-VerboseErrorInformation -CurrentError $_ }
                } else {
                    Write-Verbose "No Error Context provided."
                }
            } else {

                if ($result.RestoreActions.Count -gt 0) {
                    Write-Verbose "[$($server.ServerName)] Restore Actions Determined:"

                    $result.RestoreActions |
                        ForEach-Object {
                            Write-Verbose "$($_.Cmdlet) $(Get-ParameterString $_.Parameters)"
                        }
                }
                $successfulServers.Add($server.ServerName)
            }
        }

        if ($failedServers.Count -gt 0) {
            Write-Warning "$ConfigurationDescription failed to complete for the following servers: $([string]::Join(", ", $failedServers))"
        }

        if ($successfulServers.Count -gt 0) {
            Write-Host "$ConfigurationDescription was successful on the following servers: $([string]::Join(", ", $successfulServers))"
        }
    }
}
