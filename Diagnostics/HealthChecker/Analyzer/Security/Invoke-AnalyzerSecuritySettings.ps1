# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityExchangeCertificates.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityAMSIConfigState.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityMitigationService.ps1
Function Invoke-AnalyzerSecuritySettings {
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
    $keySecuritySettings = Get-DisplayResultsGroupingKey -Name "Security Settings"  -DisplayOrder $Order
    $osInformation = $HealthServerObject.OSInformation

    ##############
    # TLS Settings
    ##############
    Write-Verbose "Working on TLS Settings"

    $tlsVersions = @("1.0", "1.1", "1.2")
    $currentNetVersion = $osInformation.TLSSettings.Registry.NET["NETv4"]

    $tlsSettings = $osInformation.TLSSettings.Registry.TLS
    $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]
    $misconfiguredClientServerSettings = ($tlsSettings.Values | Where-Object { $_.TLSMisconfigured -eq $true }).Count -ne 0
    $lowerTlsVersionDisabled = ($tlsSettings.Values | Where-Object { $_.TLSVersionDisabled -eq $true -and $_.TLSVersion -ne "1.2" }).Count -ne 0

    foreach ($tlsKey in $tlsVersions) {
        $currentTlsVersion = $osInformation.TLSSettings.Registry.TLS[$tlsKey]
        $outputObjectDisplayValue.Add(([PSCustomObject]@{
                    TLSVersion    = $tlsKey
                    ServerEnabled = $currentTlsVersion.ServerEnabled
                    ServerDbD     = $currentTlsVersion.ServerDisabledByDefault
                    ClientEnabled = $currentTlsVersion.ClientEnabled
                    ClientDbD     = $currentTlsVersion.ClientDisabledByDefault
                    Disabled      = $currentTlsVersion.TLSVersionDisabled
                    Misconfigured = $currentTlsVersion.TLSMisconfigured
                })
        )
    }

    $sbMisconfigured = { param ($o, $p) if ($p -eq "Misconfigured") { if ($o."$p" -eq $true) { "Red" } else { "Green" } } }
    $sbDisabled = { param ($o, $p) if ($p -eq "Disabled") { if ($o."$p" -eq $true) { if ($o.TLSVersion -eq "1.2" ) { "Red" } else { "Green" } } } }
    $AnalyzeResults | Add-AnalyzedResultInformation -OutColumns ([PSCustomObject]@{
            DisplayObject      = $outputObjectDisplayValue
            ColorizerFunctions = @($sbMisconfigured, $sbDisabled)
            IndentSpaces       = 6
        }) `
        -DisplayGroupingKey $keySecuritySettings

    Function GetBadTlsValueSetting {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            $TlsSetting,
            $PropertyName
        )
        process {
            return $TlsSetting | Where-Object { $null -ne $_."$PropertyName" -and $_."$PropertyName" -ne 0 -and $_."$PropertyName" -ne 1 }
        }
    }
    $testValues = @("ServerEnabledValue", "ClientEnabledValue", "ServerDisabledByDefaultValue", "ClientDisabledByDefaultValue")

    foreach ($testValue in $testValues) {
        $results = $tlsSettings.Values | GetBadTlsValueSetting -PropertyName $testValue

        if ($null -ne $results) {
            foreach ($result in $results) {
                $AnalyzeResults | Add-AnalyzedResultInformation -Name "$($result.TLSVersion) $testValue" -Details ("$($result."$testValue") --- Error: Must be a value of 1 or 0.") `
                    -DisplayGroupingKey $keySecuritySettings `
                    -DisplayWriteType "Red"
            }
        }
    }

    if ($lowerTlsVersionDisabled -and
        ($currentNetVersion.SystemDefaultTlsVersions -eq $false -or
        $currentNetVersion.WowSystemDefaultTlsVersions -eq $false)) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details "Error: SystemDefaultTlsVersions is not set to the recommended value. Please visit on how to properly enable TLS 1.2 https://aka.ms/HC-TLSPart2" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Red"
    }

    if ($misconfiguredClientServerSettings) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details "Error: Mismatch in TLS version for client and server. Exchange can be both client and a server. This can cause issues within Exchange for communication." `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -DisplayWriteType "Red"

        $displayValues = @("Exchange Server TLS guidance Part 1: Getting Ready for TLS 1.2: https://aka.ms/HC-TLSPart1",
            "Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It: https://aka.ms/HC-TLSPart2",
            "Exchange Server TLS guidance Part 3: Turning Off TLS 1.0/1.1: https://aka.ms/HC-TLSPart3")

        $AnalyzeResults | Add-AnalyzedResultInformation -Details "For More Information on how to properly set TLS follow these blog posts:" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2 `
            -TestingName "Detected TLS Mismatch Display More Info" `
            -DisplayTestingValue $true `
            -DisplayWriteType "Yellow"

        foreach ($displayValue in $displayValues) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details $displayValue `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 3
        }
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

    $AnalyzeResults | Add-AnalyzedResultInformation -OutColumns ([PSCustomObject]@{
            DisplayObject = $outputObjectDisplayValue
            IndentSpaces  = 6
        }) `
        -DisplayGroupingKey $keySecuritySettings

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "SecurityProtocol" -Details ($osInformation.TLSSettings.SecurityProtocol) `
        -DisplayGroupingKey $keySecuritySettings

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "LmCompatibilityLevel Settings" -Details ($osInformation.LmCompatibility.RegistryValue) `
        -DisplayGroupingKey $keySecuritySettings

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Description" -Details ($osInformation.LmCompatibility.Description) `
        -DisplayGroupingKey $keySecuritySettings `
        -DisplayCustomTabNumber 2 `
        -AddHtmlDetailRow $false

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

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "SMB1 Installed" -Details $displayValue `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType $writeType
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

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "SMB1 Blocked" -Details $displayValue `
        -DisplayGroupingKey $keySecuritySettings `
        -DisplayWriteType $writeType

    if ($additionalDisplayValue -ne [string]::Empty) {
        $additionalDisplayValue += "`r`n`t`tMore Information: https://aka.ms/HC-SMB1"

        $AnalyzeResults | Add-AnalyzedResultInformation -Details $additionalDisplayValue.Trim() `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Yellow" `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false
    }

    Invoke-AnalyzerSecurityExchangeCertificates -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings
    Invoke-AnalyzerSecurityAMSIConfigState -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings
    Invoke-AnalyzerSecurityMitigationService -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings

    if ($HealthServerObject.ExchangeInformation.BuildInformation.AffectedByFIPFSUpdateIssue) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "FIP-FS Update Issue Detected" -Details $true `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Red"

        $AnalyzeResults | Add-AnalyzedResultInformation -Details "More Information: https://aka.ms/HC-FIPFSUpdateIssue" `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Red" `
            -DisplayCustomTabNumber 2
    } elseif ($null -eq $HealthServerObject.ExchangeInformation.BuildInformation.AffectedByFIPFSUpdateIssue) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "FIP-FS Update Issue Detected" -Details "Error: Failed to find the scan engines on server, this can cause issues with transport rules as well as the malware agent." `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayWriteType "Red"
    }
}
