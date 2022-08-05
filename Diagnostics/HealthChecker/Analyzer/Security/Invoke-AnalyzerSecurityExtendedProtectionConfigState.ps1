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
    if (($SecurityObject.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013) -and
            ($SecurityObject.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge)) {

        if ($null -ne $extendedProtection) {
            Write-Verbose "Exchange extended protection information found - performing vulnerability testing"

            # Description: Check for CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134 vulnerability
            # Affected Exchange versions: 2013, 2016, 2019
            # Fix: Install Aug 2022 SU & enable extended protection
            # Extended protection is available with IIS 7.5 or higher
            Write-Verbose "Testing CVE: CVE-2022-24516, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
            if (($extendedProtection.ExtendedProtectionConfiguration.SupportedExtendedProtection.Contains($false)) -or
                ($extendedProtection.SupportedVersionForExtendedProtection -eq $false)) {
                Write-Verbose "At least one vDir is not configured properly and so, the system may be at risk"
                if (($extendedProtection.ExtendedProtectionConfiguration.SupportedExtendedProtection.Contains($false)) -and
                    ($extendedProtection.SupportedVersionForExtendedProtection -eq $false)) {
                    # This combination means that EP is configured for at least one vDir, but the Exchange build doesn't support it.
                    # Such a combination can break several things like mailbox access, EMS... .
                    # Recommended action: Disable EP, upgrade to a supported build (Aug 2022 SU+) and enable afterwards.
                    $epDetails = "Extended Protection is configured, but not supported on this Exchange Server build."
                } elseif ((-not($extendedProtection.ExtendedProtectionConfiguration.SupportedExtendedProtection.Contains($false))) -and
                    ($extendedProtection.SupportedVersionForExtendedProtection -eq $false)) {
                    # This combination means that EP is not configured and the Exchange build doesn't support it.
                    # Recommended action: Upgrade to a supported build (Aug 2022 SU+) and enable EP afterwards.
                    $epDetails = "Your Exchange server is at risk. Install the latest SU and enable Extended Protection."
                } else {
                    # This means that EP is supported but not configured for at least one vDir.
                    # Recommended action: Enable EP for each vDir on the system by using the script provided by us.
                    $epDetails = "Extended Protection should be configured."
                }
                $epCveParams = $baseParams + @{
                    Name             = "Security Vulnerability"
                    Details          = "CVE-2022-24516, CVE-2022-21979, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
                    DisplayWriteType = "Red"
                }
                $epBasicParams = $baseParams + @{
                    DisplayWriteType       = "Red"
                    DisplayCustomTabNumber = 2
                    Details                = "$epDetails Current config:"
                }
                Add-AnalyzedResultInformation @epCveParams
                Add-AnalyzedResultInformation @epBasicParams

                $epOutputObjectDisplayValue = New-Object 'System.Collections.Generic.List[object]'
                foreach ($entry in $extendedProtection.ExtendedProtectionConfiguration) {
                    $ssl = $entry.Configuration.SslSettings

                    $epOutputObjectDisplayValue.Add(([PSCustomObject]@{
                                VirtualDirectory  = $entry.VirtualDirectoryName
                                Value             = $entry.ExtendedProtection
                                SupportedValue    = $entry.ExpectedExtendedConfiguration
                                ConfigSupported   = $entry.SupportedExtendedProtection
                                RequireSSL        = "$($ssl.RequireSSL) $(if($ssl.Ssl128Bit) { "(128-bit)" })".Trim()
                                ClientCertificate = $ssl.ClientCertificate
                            })
                    )
                }

                $epConfig = {
                    param ($o, $p)
                    if ($p -eq "ConfigSupported") {
                        if ($o.$p -ne $true) {
                            "Red"
                        } else {
                            "Green"
                        }
                    }
                }

                $epParams = $baseParams + @{
                    Name                = "Security Vulnerability"
                    OutColumns          = ([PSCustomObject]@{
                            DisplayObject      = $epOutputObjectDisplayValue
                            ColorizerFunctions = @($epConfig)
                            IndentSpaces       = 8
                        })
                    DisplayTestingValue = "CVE-2022-24516, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
                }
                Add-AnalyzedResultInformation @epParams

                $moreInformationParams = $baseParams + @{
                    DisplayWriteType = "Red"
                    Details          = "For more information about Extended Protection and how to configure, please read this article: https://aka.ms/HC-ExchangeEPDoc"
                }
                Add-AnalyzedResultInformation @moreInformationParams
            } else {
                Write-Verbose "System NOT vulnerable to CVE-2022-24516, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
            }
        } else {
            Write-Verbose "No Extended Protection configuration found - check will be skipped"
        }
    }
}
