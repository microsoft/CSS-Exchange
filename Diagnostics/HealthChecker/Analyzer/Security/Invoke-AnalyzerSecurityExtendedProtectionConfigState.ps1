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
    $isExtendedProtectionSupported = $SecurityObject.ExchangeInformation.BuildInformation.IsEPSupportedBuild
    $showAdditionalContent = $false

    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    # Supported server roles are: Mailbox and ClientAccess
    if (($SecurityObject.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2013) -and
            ($SecurityObject.ServerRole -ne [HealthChecker.ExchangeServerRole]::Edge)) {

        if ($null -ne $extendedProtection) {
            Write-Verbose "Exchange extended protection information found - performing vulnerability testing"

            # Description: Check for CVE-2022-24516, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134 vulnerability
            # Affected Exchange versions: 2013, 2016, 2019
            # Fix: Install July 2022 SU & enable extended protection
            # Extended protection is available with IIS 7.5 or higher
            Write-Verbose "Testing CVE: CVE-2022-24516, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
            if (($extendedProtection.ExtendedProtectionConfig.CheckPass.Contains($false)) -or
                ($isExtendedProtectionSupported -eq $false)) {
                $showAdditionalContent = $true
                $showEPConfigDetail = ("Configure Extended Protection by running: 'ConfigureExtendedProtection.ps1 -ExchangeServerNames {0}'" -f $Script:Server)
                Write-Verbose "At least one vDir is not configured properly and so, the system may be at risk"
                if (($extendedProtection.ExtendedProtectionConfig.CheckPass.Contains($false)) -and
                    ($isExtendedProtectionSupported -eq $false)) {
                    # This combination means that EP is configured for at least one vDir, but the Exchange build doesn't support it.
                    # Such a combination can break several things like mailbox access, EMS... .
                    # Recommended action: Disable EP, upgrade to a supported build (July 2022 SU+) and enable afterwards.
                    $epDetails = "Extended Protection is configured, but not supported on this Exchange Server build."
                    $showEPConfigDetail = ("Run: 'ConfigExtendedProtection.ps1 -Rollback -ExchangeServerNames {0}' to disable Extended Protection." -f $Script:Server)
                    $showEPConfigDetail += "`r`n`tInstall the latest Exchange Server build and enable Extended Protection afterwards."
                } elseif ((-not($extendedProtection.ExtendedProtectionConfig.CheckPass.Contains($true))) -and
                    ($isExtendedProtectionSupported -eq $false)) {
                    # This combination means that EP is not configured and the Exchange build doesn't support it.
                    # Recommended action: Upgrade to a supported build (July 2022 SU+) and enable EP afterwards.
                    $epDetails = "Your Exchange server is at risk. Install the latest SU and enable Extended Protection."
                    $showEPConfigDetail = "Install the latest Exchange Server build and enable Extended Protection by running:"
                    $showEPConfigDetail += ("`r`n`t'ConfigureExtendedProtection.ps1 -ExchangeServerNames {0}'" -f $Script:Server)
                } else {
                    # This means that EP is supported but not configured for at least one vDir.
                    # Recommended action: Enable EP for each vDir on the system by using the script provided by us.
                    $epDetails = "Extended Protection should be configured."
                }
                $epCveParams = $baseParams + @{
                    Name             = "Security Vulnerability"
                    Details          = "CVE-2022-24516, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
                    DisplayWriteType = "Red"
                }
                $epBasicParams = $baseParams + @{
                    DisplayWriteType       = "Red"
                    DisplayCustomTabNumber = 2
                    Details                = "$epDetails Current config:"
                }
                Add-AnalyzedResultInformation @epCveParams
                Add-AnalyzedResultInformation @epBasicParams

                $epOutputObjectDisplayValue = New-Object System.Collections.Generic.List[object]
                foreach ($entry in $extendedProtection.ExtendedProtectionConfig) {
                    $ssl = $entry.SSLConfiguration
                    $sslRequired = $ssl.RequireSSL

                    if ($ssl.SSL128Bit) {
                        $sslRequired = [System.String]::Join(" ", $ssl.RequireSSL, "(128-bit)")
                    }

                    $epOutputObjectDisplayValue.Add(([PSCustomObject]@{
                                vDir              = $entry.vDir
                                Site              = $entry.Type
                                Value             = $entry.ExtendedProtection
                                SupportedValue    = $entry.MaxSupportedValue
                                ConfigSupported   = $entry.ConfigSupported
                                RequireSSL        = $sslRequired
                                ClientCertificate = $ssl.ClientCertificates
                                IsConfigSecure    = $entry.CheckPass
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
                    } elseif ($p -eq "IsConfigSecure") {
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

                $epConfigParams = $baseParams + @{
                    DisplayWriteType = "Red"
                    Details          = $showEPConfigDetail
                }
                Add-AnalyzedResultInformation @epConfigParams
            } else {
                Write-Verbose "System NOT vulnerable to CVE-2022-24516, CVE-2022-21980, CVE-2022-24477, CVE-2022-30134"
            }
        } else {
            Write-Verbose "No Extended Protection configuration found - check will be skipped"
        }

        if ($showAdditionalContent) {
            $moreInformationParams = $baseParams + @{
                DisplayWriteType = "Red"
                Details          = "For more information, please read the following blog post: https://aka.ms/HC-July22SU"
            }
            Add-AnalyzedResultInformation @moreInformationParams
        }
    }
}
