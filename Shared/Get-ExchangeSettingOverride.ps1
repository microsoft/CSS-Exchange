# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeDiagnosticInformation.ps1
. $PSScriptRoot\Invoke-CatchActionError.ps1

function Get-ExchangeSettingOverride {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $updatedTime = [DateTime]::MinValue
        $settingOverrides = $null
        $simpleSettingOverrides = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        try {
            $params = @{
                Process             = "Microsoft.Exchange.Directory.TopologyService"
                Component           = "VariantConfiguration"
                Argument            = "Overrides"
                Server              = $Server
                CatchActionFunction = $CatchActionFunction
            }
            $diagnosticInfo = Get-ExchangeDiagnosticInformation @params

            if ($null -ne $diagnosticInfo) {
                Write-Verbose "Successfully got the Exchange Diagnostic Information"
                $xml = [xml]$diagnosticInfo.Result
                $overrides = $xml.Diagnostics.Components.VariantConfiguration.Overrides
                $updatedTime = $overrides.Updated
                $settingOverrides = $overrides.SettingOverride

                foreach ($override in $settingOverrides) {
                    Write-Verbose "Working on $($override.Name)"
                    $simpleSettingOverrides.Add([PSCustomObject]@{
                            Name          = $override.Name
                            ModifiedBy    = $override.ModifiedBy
                            Reason        = $override.Reason
                            ComponentName = $override.ComponentName
                            SectionName   = $override.SectionName
                            Status        = $override.Status
                            Parameters    = $override.Parameters.Parameter
                        })
                }
            } else {
                Write-Verbose "Failed to get Exchange Diagnostic Information"
            }
        } catch {
            Write-Verbose "Failed to get the Exchange setting override. Inner Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        return [PSCustomObject]@{
            Server                 = $Server
            LastUpdated            = $updatedTime
            SettingOverrides       = $settingOverrides
            SimpleSettingOverrides = $simpleSettingOverrides
        }
    }
}
