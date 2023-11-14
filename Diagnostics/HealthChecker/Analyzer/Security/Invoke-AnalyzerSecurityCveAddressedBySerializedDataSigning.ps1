# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-SerializedDataSigningState.ps1
. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
function Invoke-AnalyzerSecurityCveAddressedBySerializedDataSigning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$SecurityObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    <#
        Description: Check for vulnerabilities that are addressed by turning serialized data signing for PowerShell payload on
        Affected Exchange versions: 2016, 2019
        Fix: Enable Serialized Data Signing for PowerShell payload if disabled or install Exchange update if running an unsupported build
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        function NewCveFixedBySDSObject {
            param()

            begin {
                Write-Verbose "Calling: $($MyInvocation.MyCommand)"
                $cveList = New-Object 'System.Collections.Generic.List[object]'

                # Add all CVE that are addressed by turning Serialized Data Signing for PowerShell payload on
                # Add true or false as an indicator as some fixes needs to be done via code fix + SDS on
                $cveFixedBySDS = @(
                    "CVE-2023-36050, $true",
                    "CVE-2023-36039, $true",
                    "CVE-2023-36035, $true",
                    "CVE-2023-36439, $true")
            } process {
                foreach ($cve in $cveFixedBySDS) {
                    $entry = $($cve.Split(",")[0]).Trim()
                    $fixIndicator = $($cve.Split(",")[1]).Trim()
                    $cveList.Add([PSCustomObject]@{
                            CVE             = $entry
                            CodeFixRequired = $fixIndicator
                        })
                }
            } end {
                return $cveList
            }
        }

        function FindCveEntryInAnalyzeResults {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Value is used')]
            param (
                [Parameter(Mandatory = $true)]
                [ref]$AnalyzeResults,

                [Parameter(Mandatory = $true)]
                [string]$CVE,

                [Parameter(Mandatory = $false)]
                [switch]$RemoveWhenFound
            )

            begin {
                Write-Verbose "Calling: $($MyInvocation.MyCommand)"

                $key = $null
                $cveFound = $false
            } process {
                ($AnalyzeResults.Value.DisplayResults.Values | Where-Object {
                    # Find the 'Security Vulnerability' section
                    ($_.Name -eq "Security Vulnerability")
                }) | ForEach-Object {
                    if ($_.CustomValue -match $CVE) {
                        # Loop through each entry and check if the value is equal the CVE that we're looking for
                        Write-Verbose ("$CVE was found in the CVE list!")
                        $key = $_
                    }
                }

                $cveFound = ($null -ne $key)

                if ($RemoveWhenFound -and
                    $cveFound) {
                    # Remove the entry if found and if RemovedWhenFound parameter was used
                    Write-Verbose ("Removing $CVE from the list")
                    $AnalyzeResults.Value.DisplayResults.Values.Remove($key)
                }
            } end {
                Write-Verbose ("Was $CVE found in the list? $cveFound")
                return $cveFound
            }
        }

        $params = @{
            AnalyzedInformation = $AnalyzeResults
            DisplayGroupingKey  = $DisplayGroupingKey
            Name                = "Security Vulnerability"
            DisplayWriteType    = "Red"
        }

        $detailsString = "{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/security-guidance/advisory/{0} for more information."

        $getSerializedDataSigningState = Get-SerializedDataSigningState -SecurityObject $SecurityObject
        $cveFixedBySerializedDataSigning = NewCveFixedBySDSObject
    }
    process {
        if ($getSerializedDataSigningState.SupportedRole -ne $false) {
            if ($cveFixedBySerializedDataSigning.Count -ge 1) {
                Write-Verbose ("Testing CVEs: {0}" -f [string]::Join(", ", $cveFixedBySerializedDataSigning.CVE))

                if (($getSerializedDataSigningState.SupportedVersion) -and
                    ($getSerializedDataSigningState.Enabled)) {
                    Write-Verbose ("Serialized Data Signing is supported and enabled - removing any CVE that is mitigated by this feature")

                    foreach ($entry in $cveFixedBySerializedDataSigning) {
                        $buildIsVulnerable = $null
                        # If we find it on the AnalyzedResults list, it means that the build is outdated and as a result vulnerable
                        $buildIsVulnerable = FindCveEntryInAnalyzeResults -AnalyzeResults $AnalyzeResults -CVE $($entry.CVE)
                        if ($entry.CodeFixRequired -and
                            $buildIsVulnerable) {
                            # SDS is configured but there is a code change required that comes as part of a newer Exchange build.
                            # We consider this version as vulnerable since it's running an outdated build.
                            Write-Verbose ("To be fully protected against this vulnerability, a fixed Exchange build is required")
                        } elseif (($entry.CodeFixRequired -eq $false) -and
                            ($buildIsVulnerable)) {
                            # SDS is configured as expected and there is no code change required.
                            # We consider this combination as secure since the Exchange build was vulnerable but SDS mitigates.
                            Write-Verbose ("CVE was on this list but was removed since SDS mitigates the vulnerability")
                            FindCveEntryInAnalyzeResults -AnalyzeResults $AnalyzeResults -CVE $($entry.CVE) -RemoveWhenFound
                        } else {
                            # We end up here if build is not vulnerable
                            Write-Verbose ("CVE wasn't on the list - system seems not to be vulnerable")
                        }
                    }
                } elseif (($getSerializedDataSigningState.SupportedVersion -eq $false) -or
                    ($getSerializedDataSigningState.Enabled -eq $false)) {

                    foreach ($entry in $cveFixedBySerializedDataSigning) {
                        Write-Verbose ("System is vulnerable to: $($entry.CVE)")

                        if ((FindCveEntryInAnalyzeResults -AnalyzeResults $AnalyzeResults -CVE $($entry.CVE)) -eq $false) {
                            Write-Verbose ("CVE wasn't found in the results list and will be added now as it requires SDS to be mitigated")
                            $params.Details = $detailsString -f $($entry.CVE)
                            $params.DisplayTestingValue = $($entry.CVE)
                            Add-AnalyzedResultInformation @params
                        } else {
                            # We end up here in case the CVE is already on the list
                            Write-Verbose ("CVE is already on the results list")
                        }
                    }
                }
            } else {
                Write-Verbose "There are no vulnerabilities that have been addressed by enabling serialized data signing"
            }
        } else {
            Write-Verbose "Exchange server role is not affected by these vulnerabilities"
        }
    }
}
