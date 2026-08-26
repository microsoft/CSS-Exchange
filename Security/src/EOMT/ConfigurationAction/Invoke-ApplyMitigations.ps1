# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\IISManagement\New-IISConfigurationAction.ps1
. $PSScriptRoot\..\..\IISManagement\Invoke-IISConfigurationManagerAction.ps1

<#
.DESCRIPTION
    Applies mitigations using the IIS management pipeline. Takes a CVE mitigation definition
    object, invokes its GetActions script block to obtain raw actions, wraps each in
    New-IISConfigurationAction, then feeds them to Invoke-IISConfigurationManagerAction.
#>
function Invoke-ApplyMitigations {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$MitigationDefinition,

        [Parameter()]
        [string]$ServerName = $env:COMPUTERNAME
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        if ($PSCmdlet.ShouldProcess($ServerName, "Apply $($MitigationDefinition.Id) mitigation to $($MitigationDefinition.SiteName)")) {
            Write-Verbose "Invoking GetActions for $($MitigationDefinition.Id)"
            $rawActions = & $MitigationDefinition.GetActions
            Write-Verbose "GetActions returned $($rawActions.Count) action(s)"

            $wrappedActions = @()

            foreach ($action in $rawActions) {
                Write-Verbose "Wrapping action: $($action.Cmdlet) $(if($action.RuleName) {"RuleName=$($action.RuleName)"})"
                $wrappedActions += New-IISConfigurationAction -Action $action
            }

            Write-Verbose "Wrapped $($wrappedActions.Count) action(s). Sending to IIS configuration manager."

            $inputObject = [PSCustomObject]@{
                ServerName     = $ServerName
                Actions        = $wrappedActions
                BackupFileName = $MitigationDefinition.Id
            }

            # Capture the manager result to report actual success/failure.
            # Invoke-IISConfigurationManagerAction returns {FailedServers, SuccessfulServers, AllSucceeded}
            # (see addition in that file). The original shared module does not return a value.
            $managerResult = $inputObject | Invoke-IISConfigurationManagerAction -ConfigurationDescription "Apply $($MitigationDefinition.Id) Mitigation"

            return [PSCustomObject]@{
                CVE     = $MitigationDefinition.Id
                Success = $managerResult.AllSucceeded
                Result  = $managerResult
            }
        }
    }
}
