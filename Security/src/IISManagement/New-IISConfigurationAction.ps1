# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ParameterString.ps1

<#
.DESCRIPTION
    Creates the configuration action object and validates the parameters that is added to it.
#>
function New-IISConfigurationAction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state change.')]
    [CmdletBinding()]
    param(
        # A PSCustomObject that contains a property of [string]Cmdlet and [hashtable]Parameters that is required.
        # Cmdlet is the one that you are going to use and Parameters is what is passed to the cmdlet.
        # An optional property is a description of the action
        [Parameter(Mandatory = $true)]
        [object]$Action,

        [string]$OverrideErrorAction = "Stop",

        [bool]$OverrideWhatIf = $WhatIfPreference
    )
    begin {

        if (([string]::IsNullOrEmpty($Action.Cmdlet)) -or
            $null -eq $Action.Parameters -or
            $Action.Parameters.GetType().Name -ne "hashtable") {
            throw "Invalid Action parameter provided"
        }

        $Action.Parameters["ErrorAction"] = $OverrideErrorAction
        $Action.Parameters["WhatIf"] = $OverrideWhatIf
        $cmdParameters = $Action.Parameters
        Write-Verbose "Provided Action Cmdlet: '$($Action.Cmdlet)' Parameters: '$(Get-ParameterString $cmdParameters)'"
        $setWebConfigPropCmdlet = "Set-WebConfigurationProperty"
        $getCurrentValueAction = $null
        $restoreAction = $null
    }
    process {
        #TODO: Validate the Action.Parameters Pester Testing.
        # Validate the Action to make sure it passes prior to trying to execute.
        if ($Action.Cmdlet -eq $setWebConfigPropCmdlet) {
            # Set-WebConfigurationProperty requires Filter, Name, and Value.
            # We will also be requiring PSPath for this.
            # We currently are always using it and it should help clarify where we are making the change at.
            if (([string]::IsNullOrEmpty($cmdParameters["Filter"])) -or
                ([string]::IsNullOrEmpty($cmdParameters["Name"])) -or
                ([string]::IsNullOrEmpty($cmdParameters["Value"])) -or
                ([string]::IsNullOrEmpty($cmdParameters["PSPath"]))) {
                throw "Invalid cmdlet parameters provided for $setWebConfigPropCmdlet." +
                " Expected value for Filter, Name, Value, and PSPath. Provided: '$(Get-ParameterString $cmdParameters)'"
            }
            $currentValueActionParams = @{
                Filter      = $cmdParameters["Filter"]
                Name        = $cmdParameters["Name"]
                PSPath      = $cmdParameters["PSPath"]
                ErrorAction = "Stop"
            }

            if (-not([string]::IsNullOrEmpty($cmdParameters["Location"]))) {
                $currentValueActionParams.Add("Location", $cmdParameters["Location"])
            }
            $getCurrentValueAction = [PSCustomObject]@{
                Cmdlet             = "Get-WebConfigurationProperty"
                Parameters         = $currentValueActionParams
                ParametersToString = (Get-ParameterString $currentValueActionParams)
            }
            $restoreAction = [PSCustomObject]@{
                Cmdlet     = $setWebConfigPropCmdlet
                Parameters = $currentValueActionParams # Should be the same, then when executing on the server, add the value.
            }
        }

        return [PSCustomObject]@{
            Set     = [PSCustomObject]@{
                Cmdlet             = $Action.Cmdlet
                Parameters         = $cmdParameters
                ParametersToString = (Get-ParameterString $cmdParameters)
            }
            Get     = $getCurrentValueAction
            Restore = $restoreAction
        }
    }
}
