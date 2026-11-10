# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

BeforeAll {
    $componentPath = Split-Path -Parent $PSScriptRoot
    . (Join-Path $componentPath "Functions/htmlContent.ps1")
}

Describe "FreeBusyChecker HTML report" {
    BeforeEach {
        $Script:htmlFile = Join-Path $TestDrive "FreeBusyChecker.html"
        $Script:LogFile = "C:\Reports & Logs\FreeBusyChecker.txt"
        $Script:Server = "EXCH01"
        $Script:ExchangeOnPremDomain = "contoso.example"
        $Script:ExchangeOnlineDomain = "contoso.mail.onmicrosoft.com"
        $Script:ExchangeOnPremLocalDomain = "contoso.local"
        $Script:ExchangeOnPremEWS = "https://mail.contoso.example/EWS/Exchange.asmx"
        $Script:UserOnPrem = "alex@contoso.example"
        $Script:UserOnline = "sam@contoso.mail.onmicrosoft.com"
        $Script:Auth = "All"
        $Script:settingsList = @(
            [PSCustomObject]@{ Name = "Enabled"; Value = "FreeBusyAccessEnabled is set to True"; Color = "green" }
            [PSCustomObject]@{ Name = "Scope"; Value = "Review the configured scope"; Color = "red" }
        )
    }

    It "writes a complete, accessible HTML document before any checks run" {
        showParametersHtml
        $report = Get-Content $Script:htmlFile -Raw

        [regex]::Matches($report, "<!DOCTYPE html>").Count | Should -Be 1
        $report | Should -Match "<html lang='en'>"
        $report | Should -Match "<meta charset='utf-8'>"
        $report | Should -Match "name='viewport'"
        $report | Should -Match "aria-label='Report sections'"
        $report | Should -Match "</main>\s*</body>\s*</html>\s*$"
        $report | Should -Not -Match "</table>"
    }

    It "preserves and HTML-encodes the environment values" {
        $Script:Server = "EXCH01 <primary>"
        showParametersHtml
        $report = Get-Content $Script:htmlFile -Raw

        foreach ($value in @(
                "EXCH01 &lt;primary&gt;"
                "C:\Reports &amp; Logs\FreeBusyChecker.txt"
                $Script:ExchangeOnPremDomain
                $Script:ExchangeOnlineDomain
                $Script:ExchangeOnPremLocalDomain
                $Script:ExchangeOnPremEWS
                $Script:UserOnPrem
                $Script:UserOnline
            )) {
            $report | Should -Match ([regex]::Escape($value))
        }
    }

    It "keeps all section navigation targets and troubleshooting references" {
        showParametersHtml
        $report = Get-Content $Script:htmlFile -Raw

        foreach ($target in @("overview", "environment", "diagnostics", "resources")) {
            $report | Should -Match "href='#$target'"
            $report | Should -Match "id='$target'"
        }
        [regex]::Matches($report, "<a href='https://").Count | Should -Be 7
        $report | Should -Match "TLS 1.2"
        $report | Should -Match "Nonstandard values may be intentional"
    }

    It "works offline without external styles, fonts, or scripts" {
        showParametersHtml
        $report = Get-Content $Script:htmlFile -Raw

        $report | Should -Not -Match "<(?:script|link|img)\b"
        $report | Should -Not -Match "@import|url\(\s*['""]?https?://"
    }

    It "includes mobile, print, and reduced-motion styles" {
        showParametersHtml
        $report = Get-Content $Script:htmlFile -Raw

        $report | Should -Match "@media \(max-width: 760px\)"
        $report | Should -Match "@media print"
        $report | Should -Match "prefers-reduced-motion"
        $report | Should -Match "overflow-wrap: anywhere"
    }

    It "keeps muted text and diagnostic colors above a 4.5 to 1 contrast ratio" {
        showParametersHtml
        $report = Get-Content $Script:htmlFile -Raw
        $palette = @{}
        foreach ($match in [regex]::Matches($report, "--(?<name>page|surface|muted|good|bad|warn):\s*#(?<hex>[0-9a-f]{6});")) {
            $palette[$match.Groups["name"].Value] = $match.Groups["hex"].Value
        }
        $luminance = {
            param([string]$hex)
            $channels = foreach ($offset in @(0, 2, 4)) {
                $channel = [Convert]::ToInt32($hex.Substring($offset, 2), 16) / 255
                if ($channel -le 0.04045) {
                    $channel / 12.92
                } else {
                    [Math]::Pow(($channel + 0.055) / 1.055, 2.4)
                }
            }
            $channels[0] * 0.2126 + $channels[1] * 0.7152 + $channels[2] * 0.0722
        }
        foreach ($pair in @(
                @{ Foreground = "muted"; Background = "page" }
                @{ Foreground = "good"; Background = "surface" }
                @{ Foreground = "bad"; Background = "surface" }
                @{ Foreground = "warn"; Background = "surface" }
            )) {
            $foreground = & $luminance $palette[$pair.Foreground]
            $background = & $luminance $palette[$pair.Background]
            $ratio = ([Math]::Max($foreground, $background) + 0.05) / ([Math]::Min($foreground, $background) + 0.05)
            $ratio | Should -BeGreaterOrEqual 4.5 -Because "$($pair.Foreground) text must remain readable"
        }
    }

    It "keeps diagnostic messages and their original status colors" {
        showParametersHtml
        orgRelHtml
        $report = Get-Content $Script:htmlFile -Raw

        $report | Should -Match "FreeBusyAccessEnabled is set to True"
        $report | Should -Match "Review the configured scope"
        $report | Should -Match "color: green"
        $report | Should -Match "color: red"
        $report | Should -Match "Get-OrganizationRelationship"
    }

    It "keeps tables separate for <Scenario>" -ForEach @(
        @{ Scenario = "on-premises DAuth"; DAuth = $true; OAuth = $false; Online = $false; TableCount = 1 }
        @{ Scenario = "on-premises OAuth"; DAuth = $false; OAuth = $true; Online = $false; TableCount = 1 }
        @{ Scenario = "Exchange Online only"; DAuth = $false; OAuth = $false; Online = $true; TableCount = 1 }
        @{ Scenario = "all hybrid checks"; DAuth = $true; OAuth = $true; Online = $true; TableCount = 3 }
    ) {
        showParametersHtml
        if ($DAuth) {
            orgRelHtml
            TestOrgRelHtmlOK
        }
        if ($OAuth) {
            IntraOrgConCheckHtml
            AuthServerCheckHtml
        }
        if ($Online) {
            exoHeaderHtml
            EXOIntraOrgConCheckHtml
        }
        $report = Get-Content $Script:htmlFile -Raw

        [regex]::Matches($report, "<table\b").Count | Should -Be $TableCount
        [regex]::Matches($report, "</table>").Count | Should -Be $TableCount
        [regex]::Matches($report, "class='command-column'").Count | Should -Be $TableCount
        [regex]::Matches($report, "class='result-column'").Count | Should -Be $TableCount
        $report | Should -Match "</table>\s*<footer"
    }

    It "persists the final organization relationship result: <Renderer>" -ForEach @(
        @{ Renderer = "TestOrgRelHtmlOK"; Message = "No Significant Issues to Report" }
        @{ Renderer = "TestOrgRelHtmlNotOK"; Message = "Test Organization Relationship Completed with errors" }
        @{ Renderer = "TestOrgRelHtmlNoUri"; Message = "Test-OrganizationRelationship can't be run" }
    ) {
        showParametersHtml
        orgRelHtml
        & $Renderer
        $report = Get-Content $Script:htmlFile -Raw

        $report | Should -Match ([regex]::Escape($Message))
        $report | Should -Match "</div>\s*</td>\s*</tr>\s*</table>"
    }

    It "does not accumulate footers or close the in-memory table between checks" {
        showParametersHtml
        orgRelHtml
        FedInfoHtml
        fedTrustHtml
        $report = Get-Content $Script:htmlFile -Raw

        [regex]::Matches($report, "<footer\b").Count | Should -Be 1
        [regex]::Matches($report, "</html>").Count | Should -Be 1
        $Script:html | Should -Not -Match "<footer\b|</html>|</table>"
    }

    It "retains multiple web services virtual directories in the same result cell" {
        showParametersHtml
        orgRelHtml
        EWSVirtualDHeaderHtml
        $Script:EwsVDIdentity = "EXCH01\EWS (Default Web Site)"
        EwsVDHtmlOK
        $Script:EwsVDIdentity = "EXCH02\EWS (Default Web Site)"
        EwsVDHtmlNotOK
        $report = Get-Content $Script:htmlFile -Raw

        $report | Should -Match ([regex]::Escape("EXCH01\EWS"))
        $report | Should -Match ([regex]::Escape("EXCH02\EWS"))
        $report | Should -Match "Get-WebServicesVirtualDirectory"
        $report | Should -Not -Match "</tr>\s*<div><b>Identity"
    }

    It "writes diagnostic text as UTF-8" {
        showParametersHtml
        IntraOrgConCheckHtml
        $Script:OAuthConnectivityResultType = "Connectivity result: " + [char]0x00E9
        OAuthConnectivityCheckHtml
        $report = [System.IO.File]::ReadAllText($Script:htmlFile, [System.Text.Encoding]::UTF8)

        $report | Should -Match ([regex]::Escape($Script:OAuthConnectivityResultType))
    }
}
