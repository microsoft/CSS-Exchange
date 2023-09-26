# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-AnalyzerSecurityExtendedProtectionConfigState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$SecurityObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $extendedProtection = $SecurityObject.ExchangeInformation.ExtendedProtectionConfig

    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    # Supported server roles are: Mailbox and ClientAccess
    if ($SecurityObject.IsEdgeServer -eq $false) {

        if ($null -ne $extendedProtection) {
            Write-Verbose "Exchange extended protection information found - performing vulnerability testing"

            # Description: Check for CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134 vulnerability
            # Affected Exchange versions: 2013, 2016, 2019
            # Fix: Install Aug 2022 SU & enable extended protection
            # Extended protection is available with IIS 7.5 or higher
            Write-Verbose "Testing CVE: CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
            if (($extendedProtection.ExtendedProtectionConfiguration.ProperlySecuredConfiguration.Contains($false)) -or
                ($extendedProtection.SupportedVersionForExtendedProtection -eq $false)) {
                Write-Verbose "At least one vDir is not configured properly and so, the system may be at risk"
                if (($extendedProtection.ExtendedProtectionConfiguration.SupportedExtendedProtection.Contains($false)) -and
                    ($extendedProtection.SupportedVersionForExtendedProtection -eq $false)) {
                    # This combination means that EP is configured for at least one vDir, but the Exchange build doesn't support it.
                    # Such a combination can break several things like mailbox access, EMS... .
                    # Recommended action: Disable EP, upgrade to a supported build (Aug 2022 SU+) and enable afterwards.
                    $epDetails = "Extended Protection is configured, but not supported on this Exchange Server build"
                } elseif ((-not($extendedProtection.ExtendedProtectionConfiguration.SupportedExtendedProtection.Contains($false))) -and
                    ($extendedProtection.SupportedVersionForExtendedProtection -eq $false)) {
                    # This combination means that EP is not configured and the Exchange build doesn't support it.
                    # Recommended action: Upgrade to a supported build (Aug 2022 SU+) and enable EP afterwards.
                    $epDetails = "Your Exchange server is at risk. Install the latest SU and enable Extended Protection"
                } else {
                    # This means that EP is supported but not configured for at least one vDir.
                    # Recommended action: Enable EP for each vDir on the system by using the script provided by us.
                    $epDetails += "Extended Protection isn't configured as expected"
                }

                $epCveParams = $baseParams + @{
                    Name                = "Security Vulnerability"
                    Details             = "CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
                    DisplayWriteType    = "Red"
                    TestingName         = "Extended Protection Vulnerable"
                    CustomName          = "CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
                    DisplayTestingValue = $true
                }
                $epBasicParams = $baseParams + @{
                    DisplayWriteType       = "Red"
                    DisplayCustomTabNumber = 2
                    Details                = "$epDetails"
                    TestingName            = "Extended Protection Vulnerable Details"
                    DisplayTestingValue    = $epDetails
                }
                Add-AnalyzedResultInformation @epCveParams
                Add-AnalyzedResultInformation @epBasicParams

                $epFrontEndOutputObjectDisplayValue = New-Object 'System.Collections.Generic.List[object]'
                $epBackEndOutputObjectDisplayValue = New-Object 'System.Collections.Generic.List[object]'
                $mitigationOutputObjectDisplayValue = New-Object 'System.Collections.Generic.List[object]'

                foreach ($entry in $extendedProtection.ExtendedProtectionConfiguration) {
                    $vDirArray = $entry.VirtualDirectoryName.Split("/", 2)
                    $ssl = $entry.Configuration.SslSettings

                    $listToAdd = $epFrontEndOutputObjectDisplayValue
                    if ($vDirArray[0] -eq "Exchange Back End") {
                        $listToAdd = $epBackEndOutputObjectDisplayValue
                    }

                    $listToAdd.Add(([PSCustomObject]@{
                                $vDirArray[0]     = $vDirArray[1]
                                Value             = $entry.ExtendedProtection
                                SupportedValue    = if ($entry.MitigationSupported -and $entry.MitigationEnabled) { "None" } else { $entry.ExpectedExtendedConfiguration }
                                ConfigSupported   = $entry.SupportedExtendedProtection
                                ConfigSecure      = $entry.ProperlySecuredConfiguration
                                RequireSSL        = "$($ssl.RequireSSL) $(if($ssl.Ssl128Bit) { "(128-bit)" })".Trim()
                                ClientCertificate = $ssl.ClientCertificate
                                IPFilterEnabled   = $entry.MitigationEnabled
                            })
                    )

                    if ($entry.MitigationEnabled) {
                        $mitigationOutputObjectDisplayValue.Add([PSCustomObject]@{
                                VirtualDirectory = $entry.VirtualDirectoryName
                                Details          = $entry.Configuration.MitigationSettings.Restrictions
                            })
                    }
                }

                $epConfig = {
                    param ($o, $p)
                    if ($p -eq "ConfigSupported") {
                        if ($o.$p -ne $true) {
                            "Red"
                        }
                    } elseif ($p -eq "IPFilterEnabled") {
                        if ($o.$p -eq $true) {
                            "Green"
                        }
                    } elseif ($p -eq "ConfigSecure") {
                        if ($o.$p -ne $true) {
                            "Red"
                        } else {
                            "Green"
                        }
                    }
                }

                $epFrontEndParams = $baseParams + @{
                    Name                = "Security Vulnerability"
                    OutColumns          = ([PSCustomObject]@{
                            DisplayObject      = $epFrontEndOutputObjectDisplayValue
                            ColorizerFunctions = @($epConfig)
                            IndentSpaces       = 8
                        })
                    DisplayTestingValue = "CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
                }

                $epBackEndParams = $baseParams + @{
                    Name                = "Security Vulnerability"
                    OutColumns          = ([PSCustomObject]@{
                            DisplayObject      = $epBackEndOutputObjectDisplayValue
                            ColorizerFunctions = @($epConfig)
                            IndentSpaces       = 8
                        })
                    DisplayTestingValue = "CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
                }

                Add-AnalyzedResultInformation @epFrontEndParams
                Add-AnalyzedResultInformation @epBackEndParams
                if ($mitigationOutputObjectDisplayValue.Count -ge 1) {
                    foreach ($mitigation in $mitigationOutputObjectDisplayValue) {
                        $epMitigationVDir = $baseParams + @{
                            Details          = "$($mitigation.Details.Count) IPs in filter list on vDir: '$($mitigation.VirtualDirectory)'"
                            DisplayWriteType = "Yellow"
                        }
                        Add-AnalyzedResultInformation @epMitigationVDir
                        $mitigationOutputObjectDisplayValue.Details.GetEnumerator() | ForEach-Object {
                            Write-Verbose "IP Address: $($_.key) is allowed to connect? $($_.value)"
                        }
                    }
                }

                $moreInformationParams = $baseParams + @{
                    DisplayWriteType = "Red"
                    Details          = "For more information about Extended Protection and how to configure, please read this article:`n`thttps://aka.ms/HC-ExchangeEPDoc"
                }
                Add-AnalyzedResultInformation @moreInformationParams
            } else {
                Write-Verbose "System NOT vulnerable to CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
            }
        } else {
            Write-Verbose "No Extended Protection configuration found - check will be skipped"
        }
    }
}
