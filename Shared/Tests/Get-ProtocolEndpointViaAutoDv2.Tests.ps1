# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Get-ProtocolEndpointViaAutoDv2.ps1

    function Get-AutoDiscoverResponse {
        return [PSCustomObject]@{
            StatusCode = 200
            Headers    = @{ Date = "Mon, 01 Jan 2024 00:00:00 GMT" }
            Content    = '{"Protocol":"EWS","Url":"https://ews.contoso.example/EWS/Exchange.asmx","ServerLocation":"Exchange Online"}'
        }
    }
}

Describe "Get-ProtocolEndpointViaAutoDv2" {

    BeforeEach {
        Mock Invoke-WebRequestWithProxyDetection { return Get-AutoDiscoverResponse }
    }

    Context "Selecting the AutoDiscover host" {

        It "uses the worldwide host when no override is supplied" {
            Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS"

            Should -Invoke Invoke-WebRequestWithProxyDetection -Exactly 1 -ParameterFilter {
                $Uri -like "https://outlook.office365.com/autodiscover/autodiscover.json/*"
            }
        }

        It "uses the supplied host when CustomAutoDiscoverUrl is provided" {
            Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -CustomAutoDiscoverUrl "autodiscover.contoso.example"

            Should -Invoke Invoke-WebRequestWithProxyDetection -Exactly 1 -ParameterFilter {
                $Uri -like "https://autodiscover.contoso.example/autodiscover/autodiscover.json/*"
            }
        }

        It "does not fall back to the worldwide host when an override is supplied" {
            Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -CustomAutoDiscoverUrl "autodiscover.contoso.example"

            Should -Invoke Invoke-WebRequestWithProxyDetection -Exactly 0 -ParameterFilter {
                $Uri -like "*outlook.office365.com*"
            }
        }

        It "still honors the on-premises host, which shares the SmtpAddress and Protocol parameters" {
            Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -Url "mail.contoso.example"

            Should -Invoke Invoke-WebRequestWithProxyDetection -Exactly 1 -ParameterFilter {
                $Uri -like "https://mail.contoso.example/autodiscover/autodiscover.json/*"
            }
        }

        It "preserves the query string that the server requires" {
            Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -CustomAutoDiscoverUrl "autodiscover.contoso.example"

            Should -Invoke Invoke-WebRequestWithProxyDetection -Exactly 1 -ParameterFilter {
                $Uri -like "*/v1.0/user@contoso.com?Protocol=EWS&ServerLocation=true"
            }
        }
    }

    Context "Rejecting invalid input" {

        It "rejects an override that is combined with the on-premises Url" {
            { Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -Url "mail.contoso.example" -CustomAutoDiscoverUrl "autodiscover.contoso.example" } |
                Should -Throw -ExpectedMessage "*Parameter set cannot be resolved*"
        }

        It "rejects an override that includes a scheme" {
            { Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -CustomAutoDiscoverUrl "https://autodiscover.contoso.example" } |
                Should -Throw
        }

        It "rejects an override with a trailing slash" {
            { Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -CustomAutoDiscoverUrl "autodiscover.contoso.example/" } |
                Should -Throw
        }
    }

    Context "Returning the result" {

        It "returns the protocol information reported by the server" {
            $result = Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -CustomAutoDiscoverUrl "autodiscover.contoso.example"

            $result.Protocol | Should -Be "EWS"
            $result.Url | Should -Be "https://ews.contoso.example/EWS/Exchange.asmx"
            $result.ServerLocation | Should -Be "Exchange Online"
        }

        It "returns no usable Url when the server does not answer with a success code" {
            Mock Invoke-WebRequestWithProxyDetection {
                return [PSCustomObject]@{ StatusCode = 500; Headers = @{}; Content = $null }
            }

            $result = Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "user@contoso.com" -Protocol "EWS" -CustomAutoDiscoverUrl "autodiscover.contoso.example"

            # The caller decides whether the lookup succeeded by testing Url, so that is the contract worth pinning.
            # The function returns an object with empty properties here rather than $null, because the early return
            # in the process block still leaves the end block to emit a result.
            $result.Url | Should -BeNullOrEmpty
            $result.ServerLocation | Should -BeNullOrEmpty
        }
    }
}
