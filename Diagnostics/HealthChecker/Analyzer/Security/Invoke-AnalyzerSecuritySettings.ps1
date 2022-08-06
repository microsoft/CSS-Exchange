# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityExchangeCertificates.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityAMSIConfigState.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityMitigationService.ps1
function Invoke-AnalyzerSecuritySettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [int]$Order
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $osInformation = $HealthServerObject.OSInformation
    $keySecuritySettings = (Get-DisplayResultsGroupingKey -Name "Security Settings"  -DisplayOrder $Order)
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $keySecuritySettings
    }

    ##############
    # TLS Settings
    ##############
    Write-Verbose "Working on TLS Settings"

    $tlsVersions = @("1.0", "1.1", "1.2")
    $currentNetVersion = $osInformation.TLSSettings.Registry.NET["NETv4"]

    $tlsSettings = $osInformation.TLSSettings.Registry.TLS
    $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]
    $misconfiguredClientServerSettings = ($tlsSettings.Values | Where-Object { $_.TLSMisconfigured -eq $true }).Count -ne 0
    $displayLinkToDocsPage = ($tlsSettings.Values | Where-Object { $_.TLSConfiguration -ne "Enabled" -and $_.TLSConfiguration -ne "Disabled" }).Count -ne 0
    $lowerTlsVersionDisabled = ($tlsSettings.Values | Where-Object { $_.TLSVersionDisabled -eq $true -and $_.TLSVersion -ne "1.2" }).Count -ne 0

    foreach ($tlsKey in $tlsVersions) {
        $currentTlsVersion = $osInformation.TLSSettings.Registry.TLS[$tlsKey]
        $outputObjectDisplayValue.Add(([PSCustomObject]@{
                    TLSVersion    = $tlsKey
                    ServerEnabled = $currentTlsVersion.ServerEnabled
                    ServerDbD     = $currentTlsVersion.ServerDisabledByDefault
                    ClientEnabled = $currentTlsVersion.ClientEnabled
                    ClientDbD     = $currentTlsVersion.ClientDisabledByDefault
                    Configuration = $currentTlsVersion.TLSConfiguration
                })
        )
    }

    $sbConfiguration = {
        param ($o, $p)
        if ($p -eq "Configuration") {
            if ($o.$p -eq "Misconfigured" -or $o.$p -eq "Half Disabled") {
                "Red"
            } elseif ($o.$p -eq "Disabled") {
                if ($o.TLSVersion -eq "1.2") {
                    "Red"
                } else {
                    "Green"
                }
            } else {
                "Green"
            }
        }
    }

    $params = $baseParams + @{
        OutColumns           = ([PSCustomObject]@{
                DisplayObject      = $outputObjectDisplayValue
                ColorizerFunctions = @($sbConfiguration)
                IndentSpaces       = 8
            })
        OutColumnsColorTests = @($sbConfiguration)
        HtmlName             = "TLS Settings"
        TestingName          = "TLS Settings Group"
    }
    Add-AnalyzedResultInformation @params

    $testValues = @("ServerEnabledValue", "ClientEnabledValue", "ServerDisabledByDefaultValue", "ClientDisabledByDefaultValue")

    foreach ($testValue in $testValues) {
        # If value not set to a 0 or a 1.
        $results = $tlsSettings.Values | Where-Object { $null -ne $_."$testValue" -and $_."$testValue" -ne 0 -and $_."$testValue" -ne 1 }

        if ($null -ne $results) {
            $displayLinkToDocsPage = $true
            foreach ($result in $results) {
                $params = $baseParams + @{
                    Name             = "$($result.TLSVersion) $testValue"
                    Details          = "$($result."$testValue") --- Error: Must be a value of 1 or 0."
                    DisplayWriteType = "Red"
                }
                Add-AnalyzedResultInformation @params
            }
        }

        # if value not defined, we should call that out.
        $results = $tlsSettings.Values | Where-Object { $null -eq $_."$testValue" }

        if ($null -ne $results) {
            $displayLinkToDocsPage = $true
            foreach ($result in $results) {
                $params = $baseParams + @{
                    Name             = "$($result.TLSVersion) $testValue"
                    Details          = "NULL --- Error: Value should be defined in registry for consistent results."
                    DisplayWriteType = "Red"
                }
                Add-AnalyzedResultInformation @params
            }
        }
    }

    if ($lowerTlsVersionDisabled -and
        ($currentNetVersion.SystemDefaultTlsVersions -eq $false -or
        $currentNetVersion.WowSystemDefaultTlsVersions -eq $false)) {
        $params = $baseParams + @{
            Details                = "Error: SystemDefaultTlsVersions is not set to the recommended value. Please visit on how to properly enable TLS 1.2 https://aka.ms/HC-TLSPart2"
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    if ($misconfiguredClientServerSettings) {
        $params = $baseParams + @{
            Details                = "Error: Mismatch in TLS version for client and server. Exchange can be both client and a server. This can cause issues within Exchange for communication."
            DisplayWriteType       = "Red"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params

        $displayValues = @("Exchange Server TLS guidance Part 1: Getting Ready for TLS 1.2: https://aka.ms/HC-TLSPart1",
            "Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It: https://aka.ms/HC-TLSPart2",
            "Exchange Server TLS guidance Part 3: Turning Off TLS 1.0/1.1: https://aka.ms/HC-TLSPart3")

        $params = $baseParams + @{
            Details                = "For More Information on how to properly set TLS follow these blog posts:"
            DisplayWriteType       = "Yellow"
            DisplayTestingValue    = $true
            DisplayCustomTabNumber = 2
            TestingName            = "Detected TLS Mismatch Display More Info"
        }
        Add-AnalyzedResultInformation @params

        foreach ($displayValue in $displayValues) {
            $params = $baseParams + @{
                Details                = $displayValue
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 3
            }
            Add-AnalyzedResultInformation @params
        }
    }

    if ($displayLinkToDocsPage) {
        $params = $baseParams + @{
            Details                = "More Information: https://aka.ms/HC-TLSConfigDocs"
            DisplayWriteType       = "Yellow"
            DisplayTestingValue    = $true
            DisplayCustomTabNumber = 2
            TestingName            = "Display Link to Docs Page"
        }
        Add-AnalyzedResultInformation @params
    }

    $netVersions = @("NETv4", "NETv2")
    $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]

    foreach ($netVersion in $netVersions) {
        $currentNetVersion = $osInformation.TLSSettings.Registry.NET[$netVersion]
        $outputObjectDisplayValue.Add(([PSCustomObject]@{
                    FrameworkVersion                    = $netVersion
                    SystemDefaultTlsVersions            = $currentNetVersion.SystemDefaultTlsVersions
                    Wow6432NodeSystemDefaultTlsVersions = $currentNetVersion.WowSystemDefaultTlsVersions
                    SchUseStrongCrypto                  = $currentNetVersion.SchUseStrongCrypto
                    Wow6432NodeSchUseStrongCrypto       = $currentNetVersion.WowSchUseStrongCrypto
                })
        )
    }

    $params = $baseParams + @{
        OutColumns  = ([PSCustomObject]@{
                DisplayObject = $outputObjectDisplayValue
                IndentSpaces  = 8
            })
        HtmlName    = "TLS NET Settings"
        TestingName = "NET TLS Settings Group"
    }
    Add-AnalyzedResultInformation @params

    # Check for NULL values on NETv4 registry settings
    $testValues = @("SystemDefaultTlsVersionsValue", "SchUseStrongCryptoValue", "WowSystemDefaultTlsVersionsValue", "WowSchUseStrongCryptoValue")
    $displayLinkToDocsPage = $false

    foreach ($testValue in $testValues) {
        $results = $osInformation.TLSSettings.Registry.NET["NETv4"] | Where-Object { $null -eq $_."$testValue" }

        if ($null -ne $results) {
            $displayLinkToDocsPage = $true
            foreach ($result in $results) {
                $params = $baseParams + @{
                    Name             = "$($result.NetVersion) $testValue"
                    Details          = "NULL --- Error: Value should be defined in registry for consistent results."
                    DisplayWriteType = "Red"
                }
                Add-AnalyzedResultInformation @params
            }
        }
    }

    if ($displayLinkToDocsPage) {
        $params = $baseParams + @{
            Details                = "More Information: https://aka.ms/HC-TLSConfigDocs"
            DisplayWriteType       = "Yellow"
            DisplayTestingValue    = $true
            DisplayCustomTabNumber = 2
            TestingName            = "Display Link to Docs Page"
        }
        Add-AnalyzedResultInformation @params
    }

    $params = $baseParams + @{
        Name    = "SecurityProtocol"
        Details = $osInformation.TLSSettings.SecurityProtocol
    }
    Add-AnalyzedResultInformation @params

    if ($null -ne $osInformation.TLSSettings.TlsCipherSuite) {
        $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]

        foreach ($tlsCipher in $osInformation.TLSSettings.TlsCipherSuite) {
            $outputObjectDisplayValue.Add(([PSCustomObject]@{
                        TlsCipherSuiteName = $tlsCipher.Name
                        CipherSuite        = $tlsCipher.CipherSuite
                        Cipher             = $tlsCipher.Cipher
                        Certificate        = $tlsCipher.Certificate
                    })
            )
        }

        $params = $baseParams + @{
            OutColumns  = ([PSCustomObject]@{
                    DisplayObject = $outputObjectDisplayValue
                    IndentSpaces  = 8
                })
            HtmlName    = "TLS Cipher Suite"
            TestingName = "TLS Cipher Suite Group"
        }
        Add-AnalyzedResultInformation @params
    }

    $params = $baseParams + @{
        Name    = "LmCompatibilityLevel Settings"
        Details = $osInformation.LmCompatibility.RegistryValue
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name                   = "Description"
        Details                = $osInformation.LmCompatibility.Description
        DisplayCustomTabNumber = 2
        AddHtmlDetailRow       = $false
    }
    Add-AnalyzedResultInformation @params

    $additionalDisplayValue = [string]::Empty
    $smb1Settings = $osInformation.Smb1ServerSettings

    if ($osInformation.BuildInformation.MajorVersion -gt [HealthChecker.OSServerVersion]::Windows2012) {
        $displayValue = "False"
        $writeType = "Green"

        if (-not ($smb1Settings.SuccessfulGetInstall)) {
            $displayValue = "Failed to get install status"
            $writeType = "Yellow"
        } elseif ($smb1Settings.Installed) {
            $displayValue = "True"
            $writeType = "Red"
            $additionalDisplayValue = "SMB1 should be uninstalled"
        }

        $params = $baseParams + @{
            Name             = "SMB1 Installed"
            Details          = $displayValue
            DisplayWriteType = $writeType
        }
        Add-AnalyzedResultInformation @params
    }

    $writeType = "Green"
    $displayValue = "True"

    if (-not ($smb1Settings.SuccessfulGetBlocked)) {
        $displayValue = "Failed to get block status"
        $writeType = "Yellow"
    } elseif (-not($smb1Settings.IsBlocked)) {
        $displayValue = "False"
        $writeType = "Red"
        $additionalDisplayValue += " SMB1 should be blocked"
    }

    $params = $baseParams + @{
        Name             = "SMB1 Blocked"
        Details          = $displayValue
        DisplayWriteType = $writeType
    }
    Add-AnalyzedResultInformation @params

    if ($additionalDisplayValue -ne [string]::Empty) {
        $additionalDisplayValue += "`r`n`t`tMore Information: https://aka.ms/HC-SMB1"

        $params = $baseParams + @{
            Details                = $additionalDisplayValue.Trim()
            DisplayWriteType       = "Yellow"
            DisplayCustomTabNumber = 2
            AddHtmlDetailRow       = $false
        }
        Add-AnalyzedResultInformation @params
    }

    Invoke-AnalyzerSecurityExchangeCertificates -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings
    Invoke-AnalyzerSecurityAMSIConfigState -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings
    Invoke-AnalyzerSecurityMitigationService -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings

    if ($null -ne $HealthServerObject.ExchangeInformation.BuildInformation.FIPFSUpdateIssue) {
        $fipfsInfoObject = $HealthServerObject.ExchangeInformation.BuildInformation.FIPFSUpdateIssue
        $highestVersion = $fipfsInfoObject.HighesVersionNumberDetected
        $fipfsIssueBaseParams = @{
            Name             = "FIP-FS Update Issue Detected"
            Details          = $true
            DisplayWriteType = "Red"
        }
        $moreInformation = "More Information: https://aka.ms/HC-FIPFSUpdateIssue"

        if ($fipfsInfoObject.ServerRoleAffected -eq $false) {
            # Server role is not affected by the FIP-FS issue so we don't need to check for the other conditions.
            Write-Verbose "The Exchange server runs a role which is not affected by the FIP-FS issue"
        } elseif (($fipfsInfoObject.FIPFSFixedBuild -eq $false) -and
            ($fipfsInfoObject.BadVersionNumberDirDetected)) {
            # Exchange doesn't run a build which is resitent against the problematic pattern
            # and a folder with the problematic version number was detected on the computer.
            $params = $baseParams + $fipfsIssueBaseParams
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = $moreInformation
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        } elseif (($fipfsInfoObject.FIPFSFixedBuild) -and
            ($fipfsInfoObject.BadVersionNumberDirDetected)) {
            # Exchange runs a build that can handle the problematic pattern. However, we found
            # a high-version folder which should be removed (recommendation).
            $fipfsIssueBaseParams.DisplayWriteType = "Yellow"
            $params = $baseParams + $fipfsIssueBaseParams
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = "Detected problematic FIP-FS version $highestVersion directory`r`n`t`tAlthough it should not cause any problems, we recommend performing a FIP-FS reset`r`n`t`t$moreInformation"
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        } elseif ($null -eq $fipfsInfoObject.HighesVersionNumberDetected) {
            # No scan engine was found on the Exchange server. This will cause multiple issues on transport.
            $fipfsIssueBaseParams.Details = "Error: Failed to find the scan engines on server, this can cause issues with transport rules as well as the malware agent."
            $params = $baseParams + $fipfsIssueBaseParams
            Add-AnalyzedResultInformation @params
        } else {
            Write-Verbose "Server runs a FIP-FS fixed build: $($fipfsInfoObject.FIPFSFixedBuild) - Highest version number: $highestVersion"
        }
    } else {
        $fipfsIssueBaseParams.Details = "Warning: Unable to check if the system is vulnerable to the FIP-FS bad pattern issue. Please re-run. $moreInformation"
        $fipfsIssueBaseParams.DisplayWriteType = "Yellow"
        $params = $baseParams + $fipfsIssueBaseParams
        Add-AnalyzedResultInformation @params
    }
}
