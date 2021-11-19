# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1
Function Get-ExchangeAMSIConfigurationState {
    [CmdletBinding()]
    param ()

    begin {
        Function Get-AMSIStatusFlag {
            [CmdletBinding()]
            [OutputType([bool])]
            param (
                [Parameter(Mandatory = $true)]
                [object]$AMSIParameters
            )

            try {
                Switch ($AMSIParameters.Split("=")[1]) {
                    ("False") { return $false }
                    ("True") { return $true }
                    Default { return $null }
                }
            } catch {
                throw
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $amsiState = "Unknown"
        $amsiOrgWideSetting = $true
        $amsiConfigurationQuerySuccessful = $false
    } process {
        try {
            Write-Verbose "Trying to query AMSI configuration state"
            $amsiConfiguration = Get-SettingOverride -ErrorAction Stop | Where-Object { ($_.ComponentName -eq "Cafe") -and ($_.SectionName -eq "HttpRequestFiltering") }
            $amsiConfigurationQuerySuccessful = $true

            if (($null -ne $amsiConfiguration) -and
                ($amsiConfiguration.Count -eq 1)) {
                Write-Verbose "Setting override detected for AMSI configuration"
                $amsiState = Get-AMSIStatusFlag -AMSIParameters $amsiConfiguration.Parameters -ErrorAction Stop
                $amsiOrgWideSetting = ($null -eq $amsiConfiguration.Server)
            } elseif (($null -ne $amsiConfiguration) -and
                ($amsiConfiguration.Count -gt 1)) {
                Write-Verbose "$($amsiConfiguration.Count) overrides for the same component and section detected"
                $amsiMultiConfigObject = @()
                foreach ($amsiConfig in $amsiConfiguration) {
                    $amsiState = Get-AMSIStatusFlag -AMSIParameters $amsiConfig.Parameters -ErrorAction Stop
                    $amsiOrgWideSetting = ($null -eq $amsiConfig.Server)
                    $amsiConfigTempCustomObject = [PSCustomObject]@{
                        Id              = $amsiConfig.Id
                        Name            = $amsiConfig.Name
                        Reason          = $amsiConfig.Reason
                        Server          = $amsiConfig.Server
                        ModifiedBy      = $amsiConfig.ModifiedBy
                        Enabled         = $amsiState
                        OrgWideSetting  = $amsiOrgWideSetting
                        QuerySuccessful = $amsiConfigurationQuerySuccessful
                    }

                    $amsiMultiConfigObject += $amsiConfigTempCustomObject
                }
            } else {
                Write-Verbose "No setting override found that overrides AMSI configuration"
                $amsiState = $true
            }
        } catch {
            Write-Verbose "Unable to query AMSI configuration state"
            Invoke-CatchActions
        }
    } end {
        if ($amsiMultiConfigObject) {
            return $amsiMultiConfigObject
        }

        return [PSCustomObject]@{
            Id              = $amsiConfiguration.Id
            Name            = $amsiConfiguration.Name
            Reason          = $amsiConfiguration.Reason
            Server          = $amsiConfiguration.Server
            ModifiedBy      = $amsiConfiguration.ModifiedBy
            Enabled         = $amsiState
            OrgWideSetting  = $amsiOrgWideSetting
            QuerySuccessful = $amsiConfigurationQuerySuccessful
        }
    }
}
