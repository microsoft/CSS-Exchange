# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1
Function Get-ExchangeAMSIConfigurationState {
    [CmdletBinding()]
    param ()

    begin {
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
                Switch ($amsiConfiguration.Parameters.Split("=")[1]) {
                    ("False") { $amsiState = $false }
                    ("True") { $amsiState = $true }
                }

                $amsiOrgWideSetting = ($null -eq $amsiConfiguration.Server)
            } elseif (($null -ne $amsiConfiguration) -and
                ($amsiConfiguration.Count -gt 1)) {
                Write-Verbose "Multiple overrides for the same component and section detected"
                $amsiState = "Multiple overrides detected"
            } else {
                Write-Verbose "No setting override found that overrides AMSI configuration"
                $amsiState = $true
            }
        } catch {
            Write-Verbose "Unable to query AMSI configuration state"
            Invoke-CatchActions
        }
    } end {
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
