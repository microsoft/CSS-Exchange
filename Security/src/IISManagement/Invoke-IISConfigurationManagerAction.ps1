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
            # ${Function:Invoke-IISConfigurationRemoteAction} captures the function body as a script block
            # and passes it to Invoke-ScriptBlockHandler for execution. Locally this works in-process.
            # For remote servers, the script block is serialized via PowerShell remoting — nested functions
            # (like Write-VerboseAndLog) travel with it since they're defined inside the function body.
            # Any dot-sourced dependencies that Invoke-IISConfigurationRemoteAction relies on
            # at the top level would NOT be available in the remote session and would need to be
            # embedded or passed separately.
            $result = Invoke-ScriptBlockHandler -ComputerName $server.ServerName -ArgumentList $server -ScriptBlock ${Function:Invoke-IISConfigurationRemoteAction}

            if ($null -eq $result -or
                $result.ErrorContext.Count -gt 0 -or
                $result.SuccessfulExecution -eq $false) {
                $failedServers.Add($server.ServerName)
                Write-Warning "Failed to execute request on '$($server.ServerName)'. NULL Result: $($null -eq $result)"

                if ($null -ne $result) {
                    Write-Warning "SuccessfulExecution: $($result.SuccessfulExecution) | AllActionsPerformed: $($result.AllActionsPerformed) | GatheredAllRestoreActions: $($result.GatheredAllRestoreActions) | RestoreActionsSaved: $($result.RestoreActionsSaved) | ErrorCount: $($result.ErrorContext.Count)"

                    if ($result.ErrorContext.Count -gt 0) {
                        Write-Warning "Error details:"
                        $result.ErrorContext | ForEach-Object {
                            Write-Warning "  $_"
                            Write-VerboseErrorInformation -CurrentError $_
                        }
                    } else {
                        Write-Verbose "No Error Context provided."
                    }
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

        # EOMT: Return result so callers can check success/failure.
        # NOTE: The original IISManagement module does not return a value here.
        # ExchangeExtendedProtectionManagement relies on console output (Write-Warning/Write-Host)
        # for success/failure reporting. This return is additive and non-breaking — callers that
        # don't capture the return value are unaffected. When merging back to the shared module,
        # this return should be added to benefit EP management as well.
        return [PSCustomObject]@{
            FailedServers     = $failedServers
            SuccessfulServers = $successfulServers
            AllSucceeded      = ($failedServers.Count -eq 0 -and $successfulServers.Count -gt 0)
        }
    }
}
