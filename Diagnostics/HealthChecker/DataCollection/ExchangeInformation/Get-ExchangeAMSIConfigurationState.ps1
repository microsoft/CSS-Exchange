# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ExchangeAMSIConfigurationState {
    [CmdletBinding()]
    param (
        [object]$GetSettingOverride
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $amsiSettingResults = New-Object "System.Collections.Generic.List[object]"
    } process {
        if ($null -ne $GetSettingOverride -and
            $GetSettingOverride -ne "Unknown") {
            Write-Verbose "Filtering for AMSI configuration state"
            $amsiConfiguration = $GetSettingOverride | Where-Object { ($_.ComponentName -eq "Cafe") -and ($_.SectionName -eq "HttpRequestFiltering") }

            if ($null -ne $amsiConfiguration) {
                Write-Verbose "$($amsiConfiguration.Count) override(s) detected for AMSI configuration"
                foreach ($amsiConfig in $amsiConfiguration) {
                    try {
                        # currently only 1 possible parameter here of Enabled
                        $value = $amsiConfig.Parameters.Substring("Enabled=".Length)
                        if ($value -eq "True") { $amsiState = $true }
                        elseif ($value -eq "False") { $amsiState = $false }
                        else { $amsiState = "Unknown" }
                    } catch {
                        Write-Verbose "Unable to process: $($amsiConfig.Parameters) to determine status flags"
                        $amsiState = "Unknown"
                        Invoke-CatchActions
                    }
                    $amsiSettingResults.Add([PSCustomObject]@{
                            Id             = $amsiConfig.Id
                            Name           = $amsiConfig.Name
                            Reason         = $amsiConfig.Reason
                            Server         = $amsiConfig.Server
                            ModifiedBy     = $amsiConfig.ModifiedBy
                            Enabled        = $amsiState
                            OrgWideSetting = ($null -eq $amsiConfig.Server)
                        })
                }
            } else {
                Write-Verbose "No setting override found that overrides AMSI configuration"
            }
        } elseif ($GetSettingOverride -eq "Unknown") {
            $amsiSettingResults.Add([PSCustomObject]@{
                    FailedQuery = $true
                })
        }
    } end {
        if ($amsiSettingResults.Count -eq 0) {
            $amsiSettingResults.Add([PSCustomObject]@{
                    Enabled = $true
                })
        }

        return $amsiSettingResults
    }
}
