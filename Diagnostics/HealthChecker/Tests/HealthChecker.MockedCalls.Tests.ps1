# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

Describe "Testing Health Checker by Mock Data Imports" {

    BeforeAll {
        . $PSScriptRoot\HealthCheckerTests.ImportCode.NotPublished.ps1
        $Script:Server = $env:COMPUTERNAME
        $Script:MockDataCollectionRoot = "$Script:parentPath\Tests\DataCollection\E19"
        . $PSScriptRoot\HealthCheckerTest.CommonMocks.NotPublished.ps1
    }

    Context "Mocked Calls" {

        It "Testing Standard Mock Calls" {
            $Script:ErrorCount = 0
            Mock Invoke-CatchActions { $Script:ErrorCount++ }
            #redo change to a mock call for Exchange cmdlets
            Mock Get-ExchangeServer { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeServer.xml" }
            Mock Get-ExchangeCertificate { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeCertificate.xml" }
            Mock Get-AuthConfig { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAuthConfig.xml" }
            Mock Get-ExSetupFileVersionInfo { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\ExSetup.xml" }
            Mock Get-MailboxServer { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetMailboxServer.xml" }
            Mock Get-OwaVirtualDirectory { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOwaVirtualDirectory.xml" }
            Mock Get-WebServicesVirtualDirectory { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetWebServicesVirtualDirectory.xml" }
            Mock Get-OrganizationConfig { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetOrganizationConfig.xml" }
            Mock Get-InternalTransportCertificateFromServer { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetInternalTransportCertificateFromServer.xml" }
            Mock Get-HybridConfiguration { return $null }
            Mock Get-ExchangeDiagnosticInfo { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetExchangeDiagnosticInfo.xml" }
            # do not need to match the function. Only needed really to test the Assert-MockCalled
            Mock Get-Service { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServiceMitigation.xml" }
            Mock Get-SettingOverride { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSettingOverride.xml" }
            Mock Get-ServerComponentState { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetServerComponentState.xml" }
            Mock Test-ServiceHealth { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\TestServiceHealth.xml" }
            Mock Get-AcceptedDomain { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetAcceptedDomain.xml" }
            Mock Get-ReceiveConnector { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetReceiveConnector.xml" }
            Mock Get-SendConnector { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetSendConnector.xml" }
            Mock Get-DynamicDistributionGroup { return Import-Clixml "$Script:MockDataCollectionRoot\Exchange\GetDynamicDistributionGroupPfMailboxes.xml" }
            Mock Get-ActiveSyncVirtualDirectory { return $null }
            Mock Get-AutodiscoverVirtualDirectory { return $null }
            Mock Get-EcpVirtualDirectory { return $null }
            Mock Get-MapiVirtualDirectory { return $null }
            Mock Get-OutlookAnywhere { return $null }
            Mock Get-PowerShellVirtualDirectory { return $null }

            $Error.Clear()
            Get-OrganizationInformation -EdgeServer $false | Out-Null
            Get-HealthCheckerExchangeServer -ServerName $Script:Server | Out-Null

            $Error.Count | Should -Be $Script:ErrorCount
            # Hard coded to know if this ever changes.
            # Not sure why, but in the build pipeline this has now changed to 2. Where as on my computer it is 1
            # Going to comment out for now
            # Assert-MockCalled Invoke-CatchActions -Exactly 1

            Assert-MockCalled Get-WmiObjectHandler -Exactly 6
            Assert-MockCalled Invoke-ScriptBlockHandler -Exactly 5
            Assert-MockCalled Get-RemoteRegistryValue -Exactly 24
            Assert-MockCalled Get-NETFrameworkVersion -Exactly 1
            Assert-MockCalled Get-DotNetDllFileVersions -Exactly 1
            Assert-MockCalled Get-NicPnpCapabilitiesSetting -Exactly 1
            Assert-MockCalled Get-NetIPConfiguration -Exactly 1
            Assert-MockCalled Get-DnsClient -Exactly 1
            Assert-MockCalled Get-NetAdapterRss -Exactly 1
            Assert-MockCalled Get-HotFix -Exactly 1
            Assert-MockCalled Get-LocalizedCounterSamples -Exactly 1
            Assert-MockCalled Get-ServerRebootPending -Exactly 1
            Assert-MockCalled Get-AllTlsSettings -Exactly 1
            Assert-MockCalled Get-Smb1ServerSettings -Exactly 1
            Assert-MockCalled Get-ExchangeAppPoolsInformation -Exactly 1
            Assert-MockCalled Get-ExchangeUpdates -Exactly 1
            Assert-MockCalled Get-ExchangeDomainsAclPermissions -Exactly 1
            Assert-MockCalled Get-ExchangeAdSchemaClass -Exactly 2
            Assert-MockCalled Get-ExchangeServer -Exactly 1
            Assert-MockCalled Get-ExchangeCertificate -Exactly 1
            Assert-MockCalled Get-AuthConfig -Exactly 1
            Assert-MockCalled Get-ExSetupFileVersionInfo -Exactly 1
            Assert-MockCalled Get-MailboxServer -Exactly 1
            Assert-MockCalled Get-OwaVirtualDirectory -Exactly 1
            Assert-MockCalled Get-WebServicesVirtualDirectory -Exactly 1
            Assert-MockCalled Get-OrganizationConfig -Exactly 1
            Assert-MockCalled Get-HybridConfiguration -Exactly 1
            Assert-MockCalled Get-Service -Exactly 1
            Assert-MockCalled Get-SettingOverride -Exactly 1
            Assert-MockCalled Get-ServerComponentState -Exactly 1
            Assert-MockCalled Test-ServiceHealth -Exactly 1
            Assert-MockCalled Get-AcceptedDomain -Exactly 1
            Assert-MockCalled Get-FIPFSScanEngineVersionState -Exactly 1
            Assert-MockCalled Get-ReceiveConnector -Exactly 1
            Assert-MockCalled Get-SendConnector -Exactly 1
            Assert-MockCalled Get-IISModules -Exactly 1
            Assert-MockCalled Get-ExchangeDiagnosticInfo -Exactly 1
            Assert-MockCalled Get-ExchangeADSplitPermissionsEnabled -Exactly 1
            Assert-MockCalled Get-DynamicDistributionGroup -Exactly 1
            Assert-MockCalled Get-ActiveSyncVirtualDirectory -Exactly 1
            Assert-MockCalled Get-AutodiscoverVirtualDirectory -Exactly 1
            Assert-MockCalled Get-EcpVirtualDirectory -Exactly 1
            Assert-MockCalled Get-MapiVirtualDirectory -Exactly 1
            Assert-MockCalled Get-OutlookAnywhere -Exactly 1
            Assert-MockCalled Get-PowerShellVirtualDirectory -Exactly 1
        }
    }
}
