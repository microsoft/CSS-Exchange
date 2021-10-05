# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\Invoke-AnalyzerSecurityExchangeCertificates.ps1
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

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "LmCompatibilityLevel Settings" -Details ($osInformation.LmCompatibility.RegistryValue) `
        -DisplayGroupingKey $keySecuritySettings

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Description" -Details ($osInformation.LmCompatibility.Description) `
        -DisplayGroupingKey $keySecuritySettings `
        -DisplayCustomTabNumber 2 `
        -AddHtmlDetailRow $false

    ##############
    # TLS Settings
    ##############
    Write-Verbose "Working on TLS Settings"

    $tlsVersions = @("1.0", "1.1", "1.2")
    $currentNetVersion = $osInformation.TLSSettings["NETv4"]

    function TestTlsValue {
        param(
            [string]$Name,
            [int]$Value,
            [string]$Key
        )
        if ($Value -ne 0 -and
            $Value -ne 1) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Name $Name -Details "$Value --- Error: Must be a value of 1 or 0." `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Red" `
                -TestingName "TLS $key - $Name" `
                -DisplayTestingValue $Value
        }
    }

    foreach ($tlsKey in $tlsVersions) {
        $currentTlsVersion = $osInformation.TLSSettings[$tlsKey]

        $AnalyzeResults | Add-AnalyzedResultInformation -Details ("TLS {0}" -f $tlsKey) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 1

        $AnalyzeResults | Add-AnalyzedResultInformation -Name ("Server Enabled") -Details ($currentTlsVersion.ServerEnabled) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2

        TestTlsValue -Name "Server Enabled Value" -Value $currentTlsVersion.ServerEnabledValue -Key $tlsKey

        $AnalyzeResults | Add-AnalyzedResultInformation -Name ("Server Disabled By Default") -Details ($currentTlsVersion.ServerDisabledByDefault) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2

        TestTlsValue -Name "Server Disabled By Default Value" -Value $currentTlsVersion.ServerDisabledByDefaultValue -Key $tlsKey

        $AnalyzeResults | Add-AnalyzedResultInformation -Name ("Client Enabled") -Details ($currentTlsVersion.ClientEnabled) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2

        TestTlsValue -Name "Client Enabled Value" -Value $currentTlsVersion.ClientEnabledValue -Key $tlsKey

        $AnalyzeResults | Add-AnalyzedResultInformation -Name ("Client Disabled By Default") -Details ($currentTlsVersion.ClientDisabledByDefault) `
            -DisplayGroupingKey $keySecuritySettings `
            -DisplayCustomTabNumber 2

        TestTlsValue -Name "Client Disabled By Default Value" -Value $currentTlsVersion.ClientDisabledByDefaultValue -Key $tlsKey

        if ($currentTlsVersion.ServerEnabled -ne $currentTlsVersion.ClientEnabled) {
            $detectedTlsMismatch = $true
            $AnalyzeResults | Add-AnalyzedResultInformation -Details ("Error: Mismatch in TLS version for client and server. Exchange can be both client and a server. This can cause issues within Exchange for communication.") `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 3 `
                -TestingName "TLS $tlsKey - Mismatch" `
                -DisplayTestingValue $true `
                -DisplayWriteType "Red"
        }

        if (($tlsKey -eq "1.0" -or
                $tlsKey -eq "1.1") -and (
                $currentTlsVersion.ServerEnabled -eq $false -or
                $currentTlsVersion.ClientEnabled -eq $false -or
                $currentTlsVersion.ServerDisabledByDefault -or
                $currentTlsVersion.ClientDisabledByDefault) -and
            ($currentNetVersion.SystemDefaultTlsVersions -eq $false -or
            $currentNetVersion.WowSystemDefaultTlsVersions -eq $false)) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details ("Error: SystemDefaultTlsVersions is not set to the recommended value. Please visit on how to properly enable TLS 1.2 https://aka.ms/HC-TLSPart2") `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 3 `
                -TestingName "TLS $tlsKey - SystemDefaultTlsVersions Error" `
                -DisplayTestingValue $true `
                -DisplayWriteType "Red"
        }
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "SystemDefaultTlsVersions" -Details ($currentNetVersion.SystemDefaultTlsVersions) `
        -DisplayGroupingKey $keySecuritySettings

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "SystemDefaultTlsVersions - Wow6432Node" -Details ($currentNetVersion.WowSystemDefaultTlsVersions) `
        -DisplayGroupingKey $keySecuritySettings

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "SchUseStrongCrypto" -Details ($currentNetVersion.SchUseStrongCrypto) `
        -DisplayGroupingKey $keySecuritySettings

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "SchUseStrongCrypto - Wow6432Node" -Details ($currentNetVersion.WowSchUseStrongCrypto) `
        -DisplayGroupingKey $keySecuritySettings

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "SecurityProtocol" -Details ($currentNetVersion.SecurityProtocol) `
        -DisplayGroupingKey $keySecuritySettings

    <#
    [array]$securityProtocols = $currentNetVersion.SecurityProtocol.Split(",").Trim().ToUpper()
    $lowerTLSVersions = @("1.0", "1.1")

    foreach ($tlsKey in $lowerTLSVersions) {
        $currentTlsVersion = $osInformation.TLSSettings[$tlsKey]
        $securityProtocolCheck = "TLS"
        if ($tlsKey -eq "1.1") {
            $securityProtocolCheck = "TLS11"
        }

        if (($currentTlsVersion.ServerEnabled -eq $false -or
                $currentTlsVersion.ClientEnabled -eq $false) -and
            $securityProtocols.Contains($securityProtocolCheck)) {

            $AnalyzeResults = Add-AnalyzedResultInformation -Details ("Security Protocol is able to use TLS when we have TLS {0} disabled in the registry. This can cause issues with connectivity. It is recommended to follow the proper TLS settings. In some cases, it may require to also set SchUseStrongCrypto in the registry." -f $tlsKey) `
                -DisplayGroupingKey $keySecuritySettings `
                -DisplayCustomTabNumber 2 `
                -DisplayWriteType "Yellow" `
                -AnalyzedInformation $AnalyzeResults
        }
    }
#>

    if ($detectedTlsMismatch) {
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
    Invoke-AnalyzerSecurityMitigationService -AnalyzeResults $AnalyzeResults -HealthServerObject $HealthServerObject -DisplayGroupingKey $keySecuritySettings
}
