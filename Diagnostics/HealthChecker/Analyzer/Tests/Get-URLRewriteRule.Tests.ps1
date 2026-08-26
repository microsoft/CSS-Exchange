# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    . $PSScriptRoot\..\..\..\..\Shared\PesterLoadFunctions.NotPublished.ps1
    $scriptContent = Get-PesterScriptContent -FilePath "$PSScriptRoot\..\Get-URLRewriteRule.ps1"
    Invoke-Expression $scriptContent
    function Invoke-CatchActions { throw "Called Invoke-CatchActions" }

    $Script:mockDataRoot = "$PSScriptRoot\..\..\Tests\DataCollection\ExchangeSE\Exchange\IIS"
    [xml]$Script:appHost = Get-Content "$Script:mockDataRoot\applicationHost.config" -Raw -Encoding UTF8

    $Script:webConfigContent = @{
        "Default Web Site"      = (Get-Content "$Script:mockDataRoot\DefaultWebSite_web.config" -Raw -Encoding UTF8)
        "Default Web Site/owa"  = (Get-Content "$Script:mockDataRoot\DefaultWebSite-OWA_web.config" -Raw -Encoding UTF8)
        "Default Web Site/mapi" = (Get-Content "$Script:mockDataRoot\DefaultWebSite-MAPI_web.config" -Raw -Encoding UTF8)
        "Default Web Site/EWS"  = (Get-Content "$Script:mockDataRoot\DefaultWebSite-EWS_web.config" -Raw -Encoding UTF8)
    }

    $Script:result = Get-URLRewriteRule -ApplicationHostConfig $Script:appHost -WebConfigContent $Script:webConfigContent
}

Describe "Get-URLRewriteRule" {

    Context "Rule extraction from web.config" {

        It "Should find inbound rule from Default Web Site web.config" {
            $siteRules = $Script:result.Inbound["Default Web Site"]
            $allRuleNames = @($siteRules.rule.name | Where-Object { $null -ne $_ })
            $allRuleNames | Should -Contain "CVE-2022-41040 Mitigation"
        }

        It "Should collect remove entry from MAPI web.config" {
            $mapiRules = $Script:result.Inbound["Default Web Site/mapi"]
            # First entry is from web.config which contains the <remove> element
            $removeNames = @($mapiRules[0].remove.name)
            $removeNames | Should -Contain "Global Block Bad User Agents"
        }
    }

    Context "Rule extraction from applicationHost.config per-location" {

        It "Should find disabled inbound rule from appHost Default Web Site location" {
            $siteRules = $Script:result.Inbound["Default Web Site"]
            $allRuleNames = @($siteRules.rule.name | Where-Object { $null -ne $_ })
            $allRuleNames | Should -Contain "Disable HTTP - Redirect to HTTPS"
        }

        It "Should preserve disabled attribute on appHost rule" {
            $siteRules = $Script:result.Inbound["Default Web Site"]
            $disabledRule = $siteRules | ForEach-Object { $_.rule } |
                Where-Object { $_.name -eq "Disable HTTP - Redirect to HTTPS" }
            $disabledRule.enabled | Should -Be "false"
        }
    }

    Context "Rule extraction from applicationHost.config global section" {

        It "Should find global inbound rule" {
            $siteRules = $Script:result.Inbound["Default Web Site"]
            $allRuleNames = @($siteRules.rule.name | Where-Object { $null -ne $_ })
            $allRuleNames | Should -Contain "Global Block Bad User Agents"
        }
    }

    Context "Inheritance walk-up" {

        It "Should collect rules from all 3 levels for Default Web Site" {
            # web.config (CVE-2022-41040) + appHost location (disabled HTTPS redirect) + global (Block Bad User Agents)
            $Script:result.Inbound["Default Web Site"].Count | Should -Be 3
        }

        It "Should inherit parent and global rules for Default Web Site/owa" {
            # OWA web.config has no inbound rules (only outbound)
            # OWA appHost location has no inbound rules (only outbound)
            # Walks up to Default Web Site: web.config has CVE-2022-41040, appHost has disabled HTTPS redirect
            # Then global has Block Bad User Agents
            $owaRules = $Script:result.Inbound["Default Web Site/owa"]
            $allRuleNames = @($owaRules.rule.name | Where-Object { $null -ne $_ })
            $allRuleNames | Should -Contain "CVE-2022-41040 Mitigation"
            $allRuleNames | Should -Contain "Disable HTTP - Redirect to HTTPS"
            $allRuleNames | Should -Contain "Global Block Bad User Agents"
        }

        It "Should inherit rules for vDir with no rewrite config" {
            # EWS web.config has no rewrite section at all
            # Should inherit from parent Default Web Site and global
            $ewsRules = $Script:result.Inbound["Default Web Site/EWS"]
            $allRuleNames = @($ewsRules.rule.name | Where-Object { $null -ne $_ })
            $allRuleNames | Should -Contain "CVE-2022-41040 Mitigation"
            $allRuleNames | Should -Contain "Global Block Bad User Agents"
        }
    }

    Context "AppHost-only locations (no web.config entry)" {

        It "Should process Proxy location that only exists in appHost" {
            # EAS/Proxy exists in applicationHost.config but is not returned by Get-WebApplication
            # so it has no entry in $webConfigContent. The fix adds it from appHost locations.
            $Script:result.Inbound.ContainsKey("Default Web Site/Microsoft-Server-ActiveSync/Proxy") | Should -Be $true
            $Script:result.Outbound.ContainsKey("Default Web Site/Microsoft-Server-ActiveSync/Proxy") | Should -Be $true
        }

        It "Should inherit parent rules for appHost-only Proxy location" {
            # Proxy has no rules at its own appHost level. Walk-up should reach DWS web.config
            # (CVE-2022-41040) and DWS appHost (disabled HTTPS redirect, AppHost Only Rule) and global.
            $proxyRules = $Script:result.Inbound["Default Web Site/Microsoft-Server-ActiveSync/Proxy"]
            $proxyRuleNames = @($proxyRules.rule.name | Where-Object { $null -ne $_ })
            $proxyRuleNames | Should -Contain "CVE-2022-41040 Mitigation"
            $proxyRuleNames | Should -Contain "Global Block Bad User Agents"
        }

        It "Should not duplicate keys that exist in both WebConfigContent and appHost" {
            # "Default Web Site" exists in both $webConfigContent and appHost locations.
            # It should appear exactly once in the result, not duplicated.
            $dwsCount = @($Script:result.Inbound.Keys | Where-Object { $_ -eq "Default Web Site" }).Count
            $dwsCount | Should -Be 1
        }
    }

    Context "Clear stops inheritance" {

        It "Should stop at clear in appHost location for Default Web Site/mapi" {
            # MAPI web.config has <remove> (collected but no clear)
            # MAPI appHost location has <clear/> which stops inheritance
            # Should NOT contain parent Default Web Site rules or global rules
            $mapiRules = $Script:result.Inbound["Default Web Site/mapi"]
            $mapiRules.Count | Should -Be 2
            $allRuleNames = @($mapiRules.rule.name | Where-Object { $null -ne $_ })
            $allRuleNames | Should -Not -Contain "CVE-2022-41040 Mitigation"
            $allRuleNames | Should -Not -Contain "Global Block Bad User Agents"
        }

        It "Should stop at clear in web.config and not check appHost or parent" {
            # Edge case: clear in web.config is a different code path (line 52) than clear in appHost (line 75)
            # Our mock data only has clear in appHost, so use inline XML for this specific path
            $clearWebConfig = '<configuration><system.webServer><rewrite><rules><clear /></rules></rewrite></system.webServer></configuration>'
            $emptyWebConfig = '<configuration><system.webServer><modules /></system.webServer></configuration>'
            $webConfigs = @{
                "Default Web Site/owa" = $clearWebConfig
                "Default Web Site"     = $emptyWebConfig
            }

            $result = Get-URLRewriteRule -ApplicationHostConfig $Script:appHost -WebConfigContent $webConfigs

            # Should only have 1 entry (the clear node from web.config) - nothing from appHost or parent
            $result.Inbound["Default Web Site/owa"].Count | Should -Be 1
            $null -ne $result.Inbound["Default Web Site/owa"][0].clear | Should -Be $true
        }
    }

    Context "Outbound rule extraction from web.config" {

        It "Should find outbound rule from OWA web.config" {
            $owaOutbound = $Script:result.Outbound["Default Web Site/owa"]
            $allRuleNames = @($owaOutbound.rule.name | Where-Object { $null -ne $_ })
            $allRuleNames | Should -Contain "EOMT OWA CSP - outbound"
        }
    }

    Context "Outbound rule extraction from applicationHost.config per-location" {

        It "Should find outbound rule from appHost OWA location" {
            $owaOutbound = $Script:result.Outbound["Default Web Site/owa"]
            $allRuleNames = @($owaOutbound.rule.name | Where-Object { $null -ne $_ })
            $allRuleNames | Should -Contain "AppHost OWA Outbound Test"
        }
    }

    Context "Outbound rule structure" {

        It "Should preserve preCondition attribute on outbound rule" {
            $owaOutbound = $Script:result.Outbound["Default Web Site/owa"]
            $outboundRule = $owaOutbound | ForEach-Object { $_.rule } |
                Where-Object { $_.name -eq "EOMT OWA CSP - outbound" }
            $outboundRule.preCondition | Should -Be "EOMT OWA SPA HTML shell - precondition"
        }

        It "Should have serverVariable on outbound match" {
            $owaOutbound = $Script:result.Outbound["Default Web Site/owa"]
            $outboundRule = $owaOutbound | ForEach-Object { $_.rule } |
                Where-Object { $_.name -eq "EOMT OWA CSP - outbound" }
            $outboundRule.match.serverVariable | Should -Be "RESPONSE_Content_Security_Policy"
        }
    }

    Context "Outbound inheritance and independent clear tracking" {

        It "Should have empty outbound for vDir with no outbound rules at any level" {
            $ewsOutbound = $Script:result.Outbound["Default Web Site/EWS"]
            $ewsOutbound.Count | Should -Be 0
        }

        It "Should continue outbound walk-up when only inbound has clear" {
            # Inbound clear at child level should not block outbound from inheriting parent rules
            $childConfig = '<configuration><system.webServer><rewrite><rules><clear /></rules></rewrite></system.webServer></configuration>'
            $parentConfig = @"
<configuration><system.webServer><rewrite><outboundRules>
    <rule name="Parent Outbound Rule">
        <match serverVariable="RESPONSE_X_Test" pattern="(.*)" />
        <action type="Rewrite" value="test" />
    </rule>
</outboundRules></rewrite></system.webServer></configuration>
"@
            [xml]$testAppHost = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer />
    <location path="Default Web Site/test">
        <system.webServer />
    </location>
    <location path="Default Web Site">
        <system.webServer />
    </location>
</configuration>
"@
            $webConfigs = @{
                "Default Web Site/test" = $childConfig
                "Default Web Site"      = $parentConfig
            }

            $result = Get-URLRewriteRule -ApplicationHostConfig $testAppHost -WebConfigContent $webConfigs

            # Inbound: should have 1 entry (the clear node) - walk-up stopped
            $result.Inbound["Default Web Site/test"].Count | Should -Be 1
            # Outbound: should have inherited from parent - walk-up NOT blocked by inbound clear
            $outboundNames = @($result.Outbound["Default Web Site/test"].rule.name | Where-Object { $null -ne $_ })
            $outboundNames | Should -Contain "Parent Outbound Rule"
        }
    }

    Context "Empty rewrite sections" {

        It "Should return empty lists when no rewrite rules exist at any level" {
            $emptyWebConfig = '<configuration><system.webServer><modules /></system.webServer></configuration>'
            [xml]$emptyAppHost = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer />
    <location path="Default Web Site/test">
        <system.webServer />
    </location>
</configuration>
"@
            $webConfigs = @{
                "Default Web Site/test" = $emptyWebConfig
            }

            $result = Get-URLRewriteRule -ApplicationHostConfig $emptyAppHost -WebConfigContent $webConfigs

            $result.Inbound.ContainsKey("Default Web Site/test") | Should -Be $true
            $result.Inbound["Default Web Site/test"].Count | Should -Be 0
            $result.Outbound.ContainsKey("Default Web Site/test") | Should -Be $true
            $result.Outbound["Default Web Site/test"].Count | Should -Be 0
        }
    }
}
