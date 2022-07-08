# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ExchangeAMSIConfigurationState {
    [CmdletBinding()]
    param ()

    begin {
        function Get-AMSIStatusFlag {
            [CmdletBinding()]
            [OutputType([bool])]
            param (
                [Parameter(Mandatory = $true)]
                [object]$AMSIParameters
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            try {
                switch ($AMSIParameters.Split("=")[1]) {
                    ("False") { return $false }
                    ("True") { return $true }
                    default { return $null }
                }
            } catch {
                Write-Verbose "Ran into an issue when calling Split method. Parameters passed: $AMSIParameters"
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

            if ($null -ne $amsiConfiguration) {
                Write-Verbose "$($amsiConfiguration.Count) override(s) detected for AMSI configuration"
                $amsiMultiConfigObject = @()
                foreach ($amsiConfig in $amsiConfiguration) {
                    try {
                        $amsiState = Get-AMSIStatusFlag -AMSIParameters $amsiConfig.Parameters -ErrorAction Stop
                    } catch {
                        Write-Verbose "Unable to process: $($amsiConfig.Parameters) to determine status flags"
                        $amsiState = "Unknown"
                        Invoke-CatchActions
                    }
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
            Enabled         = $amsiState
            QuerySuccessful = $amsiConfigurationQuerySuccessful
        }
    }
}
