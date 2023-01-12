# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExchangeSerializedDataSigningState {
    [CmdletBinding()]
    param (
        [object]$GetSettingOverride
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $serializedDataSigningSettingResults = New-Object "System.Collections.Generic.List[object]"
    } process {
        if ($null -ne $GetSettingOverride -and
            $GetSettingOverride -ne "Unknown") {
            Write-Verbose "Filtering for EnableSerializationDataSigning configuration state"
            $signingConfiguration = $GetSettingOverride | Where-Object {
                (($_.ComponentName -eq "Data") -and
                ($_.SectionName -eq "EnableSerializationDataSigning"))
            }

            if ($null -ne $signingConfiguration) {
                Write-Verbose "$($signingConfiguration.Count) override(s) detected for SerializationDataSigning configuration"
                foreach ($signingConfig in $signingConfiguration) {
                    try {
                        # currently only 1 possible parameter here of Enabled
                        $value = $signingConfig.Parameters.Substring("Enabled=".Length)
                        if ($value -eq "True") { $signingState = $true }
                        elseif ($value -eq "False") { $signingState = $false }
                        else { $signingState = "Unknown" }
                    } catch {
                        Write-Verbose "Unable to process: $($signingConfig.Parameters) to determine status flags"
                        $signingState = "Unknown"
                        Invoke-CatchActions
                    }
                    $serializedDataSigningSettingResults.Add([PSCustomObject]@{
                            Id             = $signingConfig.Id
                            Name           = $signingConfig.Name
                            Reason         = $signingConfig.Reason
                            Server         = $signingConfig.Server
                            ModifiedBy     = $signingConfig.ModifiedBy
                            Enabled        = $signingState
                            OrgWideSetting = ($null -eq $signingConfig.Server)
                        })
                }
            }
        } elseif ($GetSettingOverride -eq "Unknown") {
            $serializedDataSigningSettingResults.Add([PSCustomObject]@{
                    FailedQuery = $true
                })
        }
    } end {
        if ($serializedDataSigningSettingResults.Count -eq 0) {
            Write-Verbose "No setting override found that enables the SerializationDataSigning feature"
            $serializedDataSigningSettingResults.Add([PSCustomObject]@{
                    Enabled        = $false
                    OrgWideSetting = $true
                })
        }

        return $serializedDataSigningSettingResults
    }
}
