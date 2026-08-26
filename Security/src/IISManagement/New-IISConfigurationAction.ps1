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
        # EOMT: Added for URL Rewrite rule support - additional cmdlet constants
        $addWebConfigPropCmdlet = "Add-WebConfigurationProperty"
        $clearWebConfigCmdlet = "Clear-WebConfiguration"
        $getCurrentValueAction = $null
        $restoreAction = $null
    }
    process {
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
        # EOMT: Added for URL Rewrite rule support - Add-WebConfigurationProperty handling
        # When we add a new configuration entry (e.g., a URL Rewrite rule), the restore action
        # should remove it via Clear-WebConfiguration using the same Filter and PSPath.
        # The Get action checks if the entry already exists before adding.
        elseif ($Action.Cmdlet -eq $addWebConfigPropCmdlet) {
            if (([string]::IsNullOrEmpty($cmdParameters["Filter"])) -or
                ([string]::IsNullOrEmpty($cmdParameters["PSPath"]))) {
                throw "Invalid cmdlet parameters provided for $addWebConfigPropCmdlet." +
                " Expected value for Filter and PSPath. Provided: '$(Get-ParameterString $cmdParameters)'"
            }

            # EOMT: Build a filter that targets the specific element being added.
            # When RuleName is provided, we build a targeted Clear-WebConfiguration filter for rollback
            # (e.g., "system.webServer/rewrite/rules/rule[@name='RuleName']").
            # When RuleName is NOT provided (e.g., sub-collection items like preCondition conditions),
            # no individual rollback is created — the parent element's rollback handles cleanup.
            # ElementName defaults to "rule" but can be overridden for other collection types
            # (e.g., "preCondition" for outbound rule preConditions).
            if (-not ([string]::IsNullOrEmpty($Action.RuleName))) {
                $elementName = if ($Action.ElementName) { $Action.ElementName } else { "rule" }
                $clearFilter = "{0}/{1}[@name='{2}']" -f $cmdParameters["Filter"], $elementName, $Action.RuleName

                $clearParams = @{
                    Filter      = $clearFilter
                    PSPath      = $cmdParameters["PSPath"]
                    ErrorAction = "Stop"
                }

                if (-not([string]::IsNullOrEmpty($cmdParameters["Location"]))) {
                    $clearParams.Add("Location", $cmdParameters["Location"])
                }

                $getActionParams = @{
                    Filter      = $clearFilter
                    PSPath      = $cmdParameters["PSPath"]
                    ErrorAction = "SilentlyContinue"
                }

                if (-not([string]::IsNullOrEmpty($cmdParameters["Location"]))) {
                    $getActionParams.Add("Location", $cmdParameters["Location"])
                }

                $getCurrentValueAction = [PSCustomObject]@{
                    Cmdlet             = "Get-WebConfiguration"
                    Parameters         = $getActionParams
                    ParametersToString = (Get-ParameterString $getActionParams)
                }

                $restoreAction = [PSCustomObject]@{
                    Cmdlet     = $clearWebConfigCmdlet
                    Parameters = $clearParams
                }
            } else {
                Write-Verbose "Add-WebConfigurationProperty without RuleName — no individual rollback. Parent element rollback handles cleanup."
            }
        }
        # EOMT: Added for URL Rewrite rule support - Clear-WebConfiguration handling
        # When we clear/remove a configuration entry, the restore action should re-add it.
        # The Get action captures the current value before removal so it can be restored.
        elseif ($Action.Cmdlet -eq $clearWebConfigCmdlet) {
            if ([string]::IsNullOrEmpty($cmdParameters["Filter"])) {
                throw "Invalid cmdlet parameters provided for $clearWebConfigCmdlet." +
                " Expected value for Filter. Provided: '$(Get-ParameterString $cmdParameters)'"
            }

            $getParams = @{
                Filter      = $cmdParameters["Filter"]
                ErrorAction = "SilentlyContinue"
            }

            if (-not([string]::IsNullOrEmpty($cmdParameters["PSPath"]))) {
                $getParams.Add("PSPath", $cmdParameters["PSPath"])
            }

            if (-not([string]::IsNullOrEmpty($cmdParameters["Location"]))) {
                $getParams.Add("Location", $cmdParameters["Location"])
            }

            $getCurrentValueAction = [PSCustomObject]@{
                Cmdlet             = "Get-WebConfiguration"
                Parameters         = $getParams
                ParametersToString = (Get-ParameterString $getParams)
            }

            # EOMT: For Clear, the restore is an Add that re-creates the removed entry.
            # The actual value to re-add is captured at execution time by Invoke-IISConfigurationRemoteAction
            # and stored in the restore JSON file.
            $restoreParams = @{
                Filter      = $getParams["Filter"]
                Name        = "."
                ErrorAction = "SilentlyContinue"
            }

            if (-not([string]::IsNullOrEmpty($getParams["PSPath"]))) {
                $restoreParams.Add("PSPath", $getParams["PSPath"])
            }

            if (-not([string]::IsNullOrEmpty($getParams["Location"]))) {
                $restoreParams.Add("Location", $getParams["Location"])
            }

            $restoreAction = [PSCustomObject]@{
                Cmdlet     = $addWebConfigPropCmdlet
                Parameters = $restoreParams
            }
        }
        # EOMT: End of URL Rewrite rule support additions

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
