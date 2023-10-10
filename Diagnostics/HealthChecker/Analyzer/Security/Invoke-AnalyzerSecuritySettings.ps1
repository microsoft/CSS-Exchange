# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityExchangeCertificates.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityAMSIConfigState.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityOverrides.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityMitigationService.ps1
. $PSScriptRoot\Invoke-AnalyzerSecuritySerializedDataSigningState.ps1
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
    $aes256CbcInformation = $HealthServerObject.ExchangeInformation.AES256CBCInformation
    $keySecuritySettings = (Get-DisplayResultsGroupingKey -Name "Security Settings"  -DisplayOrder $Order)
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $keySecuritySettings
    }

    ##############
    # TLS Settings
    ##############
    Write-Verbose "Working on TLS Settings"

    function NewDisplayObject {
        param (
            [string]$RegistryKey,
            [string]$Location,
            [object]$Value
        )
        return [PSCustomObject]@{
            RegistryKey = $RegistryKey
            Location    = $Location
            Value       = if ($null -eq $Value) { "NULL" } else { $Value }
        }
    }

    $tlsVersions = @("1.0", "1.1", "1.2", "1.3")
    $currentNetVersion = $osInformation.TLSSettings.Registry.NET["NETv4"]

    $tlsSettings = $osInformation.TLSSettings.Registry.TLS
    $misconfiguredClientServerSettings = ($tlsSettings.Values | Where-Object { $_.TLSMisconfigured -eq $true }).Count -ne 0
    $displayLinkToDocsPage = ($tlsSettings.Values | Where-Object { $_.TLSConfiguration -ne "Enabled" -and $_.TLSConfiguration -ne "Disabled" }).Count -ne 0
    $lowerTlsVersionDisabled = ($tlsSettings.Values | Where-Object { $_.TLSVersionDisabled -eq $true -and ($_.TLSVersion -ne "1.2" -and $_.TLSVersion -ne "1.3") }).Count -ne 0
    $tls13NotDisabled = ($tlsSettings.Values | Where-Object { $_.TLSConfiguration -ne "Disabled" -and $_.TLSVersion -eq "1.3" }).Count -gt 0

    $sbValue = {
        param ($o, $p)
        if ($p -eq "Value") {
            if ($o.$p -eq "NULL" -and -not $o.Location.Contains("1.3")) {
                "Red"
            } elseif ($o.$p -ne "NULL" -and
                $o.$p -ne 1 -and
                $o.$p -ne 0) {
                "Red"
            }
        }
    }

    foreach ($tlsKey in $tlsVersions) {
        $currentTlsVersion = $osInformation.TLSSettings.Registry.TLS[$tlsKey]
        $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]
        $outputObjectDisplayValue.Add((NewDisplayObject "Enabled" -Location $currentTlsVersion.ServerRegistryPath -Value $currentTlsVersion.ServerEnabledValue))
        $outputObjectDisplayValue.Add((NewDisplayObject "DisabledByDefault" -Location $currentTlsVersion.ServerRegistryPath -Value $currentTlsVersion.ServerDisabledByDefaultValue))
        $outputObjectDisplayValue.Add((NewDisplayObject "Enabled" -Location $currentTlsVersion.ClientRegistryPath -Value $currentTlsVersion.ClientEnabledValue))
        $outputObjectDisplayValue.Add((NewDisplayObject "DisabledByDefault" -Location $currentTlsVersion.ClientRegistryPath -Value $currentTlsVersion.ClientDisabledByDefaultValue))
        $displayWriteType = "Green"

        # Any TLS version is Misconfigured or Half Disabled is Red
        # Only TLS 1.2 being Disabled is Red
        # Currently TLS 1.3 being Enabled is Red
        # TLS 1.0 or 1.1 being Enabled is Yellow as we recommend to disable this weak protocol versions
        if (($currentTlsVersion.TLSConfiguration -eq "Misconfigured" -or
                $currentTlsVersion.TLSConfiguration -eq "Half Disabled") -or
                ($tlsKey -eq "1.2" -and $currentTlsVersion.TLSConfiguration -eq "Disabled") -or
                ($tlsKey -eq "1.3" -and $currentTlsVersion.TLSConfiguration -eq "Enabled")) {
            $displayWriteType = "Red"
        } elseif ($currentTlsVersion.TLSConfiguration -eq "Enabled" -and
            ($tlsKey -eq "1.1" -or $tlsKey -eq "1.0")) {
            $displayWriteType = "Yellow"
        }

        $params = $baseParams + @{
            Name             = "TLS $tlsKey"
            Details          = $currentTlsVersion.TLSConfiguration
            DisplayWriteType = $displayWriteType
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            OutColumns           = ([PSCustomObject]@{
                    DisplayObject      = $outputObjectDisplayValue
                    ColorizerFunctions = @($sbValue)
                    IndentSpaces       = 8
                })
            OutColumnsColorTests = @($sbValue)
            HtmlName             = "TLS Settings $tlsKey"
            TestingName          = "TLS Settings Group $tlsKey"
        }
        Add-AnalyzedResultInformation @params
    }

    $netVersions = @("NETv4", "NETv2")
    $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]

    $sbValue = {
        param ($o, $p)
        if ($p -eq "Value") {
            if ($o.$p -eq "NULL" -and $o.Location -like "*v4.0.30319") {
                "Red"
            }
        }
    }

    foreach ($netVersion in $netVersions) {
        $currentNetVersion = $osInformation.TLSSettings.Registry.NET[$netVersion]
        $outputObjectDisplayValue.Add((NewDisplayObject "SystemDefaultTlsVersions" -Location $currentNetVersion.MicrosoftRegistryLocation -Value $currentNetVersion.SystemDefaultTlsVersionsValue))
        $outputObjectDisplayValue.Add((NewDisplayObject "SchUseStrongCrypto" -Location $currentNetVersion.MicrosoftRegistryLocation -Value $currentNetVersion.SchUseStrongCryptoValue))
        $outputObjectDisplayValue.Add((NewDisplayObject "SystemDefaultTlsVersions" -Location $currentNetVersion.WowRegistryLocation -Value $currentNetVersion.WowSystemDefaultTlsVersionsValue))
        $outputObjectDisplayValue.Add((NewDisplayObject "SchUseStrongCrypto" -Location $currentNetVersion.WowRegistryLocation -Value $currentNetVersion.WowSchUseStrongCryptoValue))
    }

    $params = $baseParams + @{
        OutColumns  = ([PSCustomObject]@{
                DisplayObject      = $outputObjectDisplayValue
                ColorizerFunctions = @($sbValue)
                IndentSpaces       = 8
            })
        HtmlName    = "TLS NET Settings"
        TestingName = "NET TLS Settings Group"
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
        $results = $tlsSettings.Values | Where-Object { $null -eq $_."$testValue" -and $_.TLSVersion -ne "1.3" }

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

    # Check for NULL values on NETv4 registry settings
    $testValues = @("SystemDefaultTlsVersionsValue", "SchUseStrongCryptoValue", "WowSystemDefaultTlsVersionsValue", "WowSchUseStrongCryptoValue")

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

    if ($lowerTlsVersionDisabled -and
        ($osInformation.TLSSettings.Registry.NET["NETv4"].SystemDefaultTlsVersions -eq $false -or
        $osInformation.TLSSettings.Registry.NET["NETv4"].WowSystemDefaultTlsVersions -eq $false -or
        $osInformation.TLSSettings.Registry.NET["NETv4"].SchUseStrongCrypto -eq $false -or
        $osInformation.TLSSettings.Registry.NET["NETv4"].WowSchUseStrongCrypto -eq $false)) {
        $params = $baseParams + @{
            Details                = "Error: SystemDefaultTlsVersions or SchUseStrongCrypto is not set to the recommended value. Please visit on how to properly enable TLS 1.2 https://aka.ms/HC-TLSGuide"
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

        $params = $baseParams + @{
            Details                = "For More Information on how to properly set TLS follow this guide: https://aka.ms/HC-TLSGuide"
            DisplayWriteType       = "Yellow"
            DisplayTestingValue    = $true
            DisplayCustomTabNumber = 2
            TestingName            = "Detected TLS Mismatch Display More Info"
        }
        Add-AnalyzedResultInformation @params
    }

    if ($tls13NotDisabled) {
        $displayLinkToDocsPage = $true
        $params = $baseParams + @{
            Details                = "Error: TLS 1.3 is not disabled and not supported currently on Exchange and is known to cause issues within the cluster."
            DisplayWriteType       = "Red"
            DisplayTestingValue    = $true
            DisplayCustomTabNumber = 2
            TestingName            = "TLS 1.3 not disabled"
        }
        Add-AnalyzedResultInformation @params
    }

    if ($lowerTlsVersionDisabled -eq $false) {
        $displayLinkToDocsPage = $true
        $params = $baseParams + @{
            Name = "TLS hardening recommendations"
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Details                = "Microsoft recommends customers proactively address weak TLS usage by removing TLS 1.0/1.1 dependencies in their environments and disabling TLS 1.0/1.1 at the operating system level where possible."
            DisplayWriteType       = "Yellow"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
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
        $outputObjectDisplayValue = New-Object 'System.Collections.Generic.List[object]'

        foreach ($tlsCipher in $osInformation.TLSSettings.TlsCipherSuite) {
            $outputObjectDisplayValue.Add(([PSCustomObject]@{
                        TlsCipherSuiteName = $tlsCipher.Name
                        CipherSuite        = $tlsCipher.CipherSuite
                        Cipher             = $tlsCipher.Cipher
                        Certificate        = $tlsCipher.Certificate
                        Protocols          = $tlsCipher.Protocols
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
        Name    = "AllowInsecureRenegoClients Value"
        Details = $osInformation.RegistryValues.AllowInsecureRenegoClients
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name    = "AllowInsecureRenegoServers Value"
        Details = $osInformation.RegistryValues.AllowInsecureRenegoServers
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name    = "LmCompatibilityLevel Settings"
        Details = $osInformation.RegistryValues.LmCompatibilityLevel
    }
    Add-AnalyzedResultInformation @params

    $description = [string]::Empty
    switch ($osInformation.RegistryValues.LmCompatibilityLevel) {
        0 { $description = "Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        1 { $description = "Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        2 { $description = "Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication." }
        3 { $description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        4 { $description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2." }
        5 { $description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2." }
    }

    $params = $baseParams + @{
        Name                   = "Description"
        Details                = $description
        DisplayCustomTabNumber = 2
        AddHtmlDetailRow       = $false
    }
    Add-AnalyzedResultInformation @params

    # AES256-CBC encryption support check
    $sp = "Supported Build"
    $vc = "Valid Configuration"
    $params = $baseParams + @{
        Name                = "AES256-CBC Protected Content Support"
        Details             = $true
        DisplayWriteType    = "Green"
        DisplayTestingValue = "$sp and $vc"
    }

    $irmConfig = $HealthServerObject.OrganizationInformation.GetIrmConfiguration

    if (($aes256CbcInformation.AES256CBCSupportedBuild) -and
        ($aes256CbcInformation.ValidAESConfiguration -eq $false) -and
        ($irmConfig.InternalLicensingEnabled -eq $true -or
        $irmConfig.ExternalLicensingEnabled -eq $true)) {
        $params.DisplayTestingValue = "$sp and not $vc"
        $params.Details = ("True" +
            "`r`n`t`tThis build supports AES256-CBC protected content, but the configuration is not complete. Exchange Server is not able to decrypt" +
            "`r`n`t`tprotected messages which could impact eDiscovery and Journaling tasks. If you use Rights Management Service (RMS) on-premises," +
            "`r`n`t`tplease follow the instructions as outlined in the documentation: https://aka.ms/ExchangeCBCKB")

        if ($irmConfig.InternalLicensingEnabled -eq $true) {
            $params.DisplayWriteType = "Red"
        } else {
            $params.DisplayWriteType = "Yellow"
        }
    } elseif ($aes256CbcInformation.AES256CBCSupportedBuild -eq $false) {
        $params.DisplayTestingValue = "Not $sp"
        $params.Details = ("False" +
            "`r`n`t`tThis could lead to scenarios where Exchange Server is no longer able to decrypt protected messages," +
            "`r`n`t`tfor example, when sending rights management protected messages using AES256-CBC encryption algorithm," +
            "`r`n`t`tor when performing eDiscovery and Journaling tasks." +
            "`r`n`t`tMore Information: https://aka.ms/Purview/CBCDetails")
        $params.DisplayWriteType = "Red"
    }
    Add-AnalyzedResultInformation @params

    $additionalDisplayValue = [string]::Empty
    $smb1Settings = $osInformation.Smb1ServerSettings

    if ($osInformation.BuildInformation.BuildVersion -ge "10.0.0.0" -or
        $osInformation.BuildInformation.MajorVersion -eq "Windows2012R2") {
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
    Invoke-AnalyzerSecuritySerializedDataSigningState -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings
    Invoke-AnalyzerSecurityOverrides -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings
    Invoke-AnalyzerSecurityMitigationService -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings

    if ($null -ne $HealthServerObject.ExchangeInformation.FIPFSUpdateIssue) {
        $fipFsInfoObject = $HealthServerObject.ExchangeInformation.FIPFSUpdateIssue
        $highestVersion = $fipFsInfoObject.HighestVersionNumberDetected
        $fipFsIssueBaseParams = @{
            Name             = "FIP-FS Update Issue Detected"
            Details          = $true
            DisplayWriteType = "Red"
        }
        $moreInformation = "More Information: https://aka.ms/HC-FIPFSUpdateIssue"

        if ($fipFsInfoObject.ServerRoleAffected -eq $false) {
            # Server role is not affected by the FIP-FS issue so we don't need to check for the other conditions.
            Write-Verbose "The Exchange server runs a role which is not affected by the FIP-FS issue"
        } elseif (($fipFsInfoObject.FIPFSFixedBuild -eq $false) -and
            ($fipFsInfoObject.BadVersionNumberDirDetected)) {
            # Exchange doesn't run a build which is resistent against the problematic pattern
            # and a folder with the problematic version number was detected on the computer.
            $params = $baseParams + $fipFsIssueBaseParams
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = $moreInformation
                DisplayWriteType       = "Red"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        } elseif (($fipFsInfoObject.FIPFSFixedBuild) -and
            ($fipFsInfoObject.BadVersionNumberDirDetected)) {
            # Exchange runs a build that can handle the problematic pattern. However, we found
            # a high-version folder which should be removed (recommendation).
            $fipFsIssueBaseParams.DisplayWriteType = "Yellow"
            $params = $baseParams + $fipFsIssueBaseParams
            Add-AnalyzedResultInformation @params

            $params = $baseParams + @{
                Details                = "Detected problematic FIP-FS version $highestVersion directory`r`n`t`tAlthough it should not cause any problems, we recommend performing a FIP-FS reset`r`n`t`t$moreInformation"
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        } elseif ($null -eq $fipFsInfoObject.HighestVersionNumberDetected) {
            # No scan engine was found on the Exchange server. This will cause multiple issues on transport.
            $fipFsIssueBaseParams.Details = "Error: Failed to find the scan engines on server, this can cause issues with transport rules as well as the malware agent."
            $params = $baseParams + $fipFsIssueBaseParams
            Add-AnalyzedResultInformation @params
        } else {
            Write-Verbose "Server runs a FIP-FS fixed build: $($fipFsInfoObject.FIPFSFixedBuild) - Highest version number: $highestVersion"
        }
    } else {
        $fipFsIssueBaseParams = $baseParams + @{
            Name             = "FIP-FS Update Issue Detected"
            Details          = "Warning: Unable to check if the system is vulnerable to the FIP-FS bad pattern issue. Please re-run. $moreInformation"
            DisplayWriteType = "Yellow"
        }
        Add-AnalyzedResultInformation @params
    }
}
