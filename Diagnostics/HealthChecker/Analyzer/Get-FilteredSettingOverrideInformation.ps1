# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
 This function is to create a simple return value for the Setting Override you are looking for
 It will also determine if this setting override should be applied on the server or not
 You should pass in the results from Get-ExchangeSettingOverride (the true settings on the Exchange Server)
 And the Get-SettingOverride (what is stored in AD) as a fallback
 WARNING: Get-SettingOverride should really not be used as the status is only accurate for the session we are connected to for EMS.
    Caller should determine if the override is applied to the server by the Status and FromAdSettings properties.
    If FromAdSettings is set to true, the data was determined from Get-SettingOverride and to be not accurate.
#>
function Get-FilteredSettingOverrideInformation {
    [CmdletBinding()]
    param(
        [object[]]$GetSettingOverride,
        [object[]]$ExchangeSettingOverride,

        [Parameter(Mandatory = $true)]
        [string]$FilterServer,

        [Parameter(Mandatory = $true)]
        [System.Version]$FilterServerVersion,

        [Parameter(Mandatory = $true)]
        [string]$FilterComponentName,

        [Parameter(Mandatory = $true)]
        [string]$FilterSectionName,

        [Parameter(Mandatory = $true)]
        [string[]]$FilterParameterName
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Trying to filter down results for ComponentName: $FilterComponentName SectionName: $FilterSectionName ParameterName: $([string]::Join(", ", $FilterParameterName))"
        $results = New-Object "System.Collections.Generic.List[object]"
        $findFromOverride = $null
        $usedAdSettings = $false
        $adjustedFilterServer = $FilterServer.Split(".")[0].ToLower()
    } process {
        # Use ExchangeSettingOverride first
        if ($null -ne $ExchangeSettingOverride -and
            $ExchangeSettingOverride.SimpleSettingOverrides.Count -gt 0) {
            $findFromOverride = $ExchangeSettingOverride.SimpleSettingOverrides
        } elseif ($null -ne $GetSettingOverride -and
            $GetSettingOverride -ne "Unknown") {
            $findFromOverride = $GetSettingOverride
            $usedAdSettings = $true
        } elseif ($GetSettingOverride -eq "Unknown") {
            $results.Add("Unknown")
            return
        } else {
            Write-Verbose "No data to filter"
            return
        }

        $filteredResults = $findFromOverride | Where-Object { $_.ComponentName -eq $FilterComponentName -and $_.SectionName -eq $FilterSectionName }

        if ($null -ne $filteredResults) {
            Write-Verbose "Found $($filteredResults.Count) override(s)"
            foreach ($entry in $filteredResults) {
                Write-Verbose "Working on entry: $($entry.Name)"
                foreach ($p in [array]($entry.Parameters)) {
                    Write-Verbose "Working on parameter: $p"
                    foreach ($currentFilterParameterName in $FilterParameterName) {
                        if ($p.Contains($currentFilterParameterName)) {
                            $value = $p.Substring($currentFilterParameterName.Length + 1) # Add plus 1 for '='
                            # everything matched, however, only add it to the list for the following reasons
                            # - Status is Accepted and not from AD and a unique value in the list
                            # - Or From AD and current logic determines it applies

                            if ($usedAdSettings) {
                                # can have it apply by build and server parameter
                                if (($null -eq $entry.MinVersion -or
                                        $FilterServerVersion -ge $entry.MinVersion) -and
                                (($null -eq $entry.MaxVersion -or
                                        $FilterServerVersion -le $entry.MaxVersion)) -and
                                (($null -eq $entry.Server -or
                                        $entry.Server -contains $adjustedFilterServer))) {
                                    $status = $entry.Status.ToString()
                                } else {
                                    $status = "DoesNotApply"
                                }
                            } else {
                                $status = $entry.Status.ToString()
                            }

                            # Add to the list if the status is Accepted, and we do not have that ParameterName yet in the list.
                            if ($status -eq "Accepted" -and
                            ($results.Count -lt 1 -or
                                -not ($results.ParameterName -contains $currentFilterParameterName))) {
                                $results.Add([PSCustomObject]@{
                                        Name           = $entry.Name
                                        Reason         = $entry.Reason
                                        ModifiedBy     = $entry.ModifiedBy
                                        ComponentName  = $entry.ComponentName
                                        SectionName    = $entry.SectionName
                                        ParameterName  = $currentFilterParameterName
                                        ParameterValue = $value
                                        Status         = $entry.Status
                                        TrueStatus     = $status
                                        FromAdSettings = $usedAdSettings
                                    })
                            } elseif ($status -eq "Accepted") {
                                Write-Verbose "Already have 1 Accepted value added to list no need to add another one. Skip adding $($entry.Name)"
                            } else {
                                Write-Verbose "Already have parameter value added to the list. Skip adding $($entry.Name)"
                            }
                        }
                    }
                }
            }
        }
    } end {
        # If no filter data is found, return null.
        # Up to the caller for how to determine this information.
        if ($results.Count -eq 0) {
            return $null
        }
        return $results
    }
}
