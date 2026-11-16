# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Functions\CommonFunctions.ps1
    . $Script:parentPath\Functions\OnPremDAuthFunctions.ps1
    . $Script:parentPath\Functions\OnPremOAuthFunctions.ps1

    # The worldwide values the script compared against before endpoint overrides were introduced. These are
    # intentionally duplicated here so a change to a default has to be made deliberately in two places.
    $Script:worldwide = @{
        Ews                     = "https://outlook.office365.com/EWS/Exchange.asmx"
        AutoDiscover            = "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc"
        AutoDiscoverWsSecurity  = "https://AutoDiscover-s.outlook.com/AutoDiscover/AutoDiscover.svc/WSSecurity"
        HybridAgentAutoDiscover = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc/"
        OwaPrefix               = "http://outlook.com/owa/"
        OwaMail                 = "https://outlook.office.com/mail."
        AzureAD                 = "https://login.windows.net"
        TokenIssuingPattern     = "https://login.windows.net/common/oauth2/token*"
        AuthMetadataPattern     = "https://login.windows.net/*/federationmetadata/2007-06/federationmetadata.xml"
        AuthServerIssuer        = "https://sts.windows.net"
        FedTrustTokenIssuer     = "https://login.microsoftonline.com/extSTS.srf"
        FedTrustMetadata        = "https://nexus.microsoftonline-p.com/FederationMetadata/2006-12/FederationMetadata.xml"
        FedTargetApplicationUri = "Outlook.com"
        HybridAgentTargetAppUri = "http://outlook.office.com/"
    }

    # A fictitious sovereign cloud. The point is only that every value differs from the worldwide one.
    $Script:sovereign = @{
        Ews                     = "https://outlook.office365.example/EWS/Exchange.asmx"
        AutoDiscover            = "https://autodiscover-s.office365.example/autodiscover/autodiscover.svc"
        AzureAD                 = "https://login.example"
        AuthServerIssuer        = "https://sts.example"
        FedTrustTokenIssuer     = "https://login.microsoftonline.example/extSTS.srf"
        FedTrustMetadata        = "https://nexus.microsoftonline-p.example/FederationMetadata/2006-12/FederationMetadata.xml"
        FedTargetApplicationUri = "outlook.example"
        HybridAgentTargetAppUri = "http://outlook.office.example/"
    }

    function Script:GetParameterDefault {
        param(
            [string]$Path,
            [string]$FunctionName,
            [string]$ParameterName
        )

        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)

        if ([string]::IsNullOrWhiteSpace($FunctionName)) {
            $parameters = $ast.ParamBlock.Parameters
        } else {
            $function = $ast.Find({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $FunctionName
                }, $true)
            $parameters = $function.Body.ParamBlock.Parameters
        }

        $parameter = $parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $ParameterName }
        return [scriptblock]::Create($parameter.DefaultValue.Extent.Text).Invoke()
    }

    # Minimal stand-ins for the output helpers, so the check functions can run without an Exchange shell.
    function PrintDynamicWidthLine {}
    function orgRelHtml {}
    function AuthServerCheckHtml {}
    function Get-AuthServer {}
}

Describe "SetExpectedEndpointValues" {
    Context "When no overrides are supplied" {
        BeforeAll {
            SetExpectedEndpointValues
        }

        It "reproduces the worldwide Exchange Online EWS endpoint" {
            $Script:ExchangeOnlineEwsEndpointUri | Should -BeExactly $Script:worldwide.Ews
        }

        It "reproduces the worldwide Exchange Online AutoDiscover endpoint" {
            $Script:ExchangeOnlineAutoDiscoverEndpointUri | Should -BeExactly $Script:worldwide.AutoDiscover
        }

        It "reproduces the worldwide AutoDiscover WSSecurity endpoint" {
            $Script:ExchangeOnlineAutoDiscoverWsSecurityUri | Should -BeExactly $Script:worldwide.AutoDiscoverWsSecurity
        }

        It "reproduces a Hybrid Agent AutoDiscover endpoint that still matches the previous literal" {
            # The previous literal was lower case. -like is case insensitive, which is why the derived value,
            # which keeps the casing of the base endpoint, is still equivalent.
            $Script:HybridAgentAutoDiscoverEndpointUri | Should -BeLike $Script:worldwide.HybridAgentAutoDiscover
        }

        It "reproduces the worldwide TarGetOwAUrl standard values" {
            $Script:ExchangeOnlineOwaUri[0] | Should -BeExactly $Script:worldwide.OwaPrefix
            $Script:ExchangeOnlineOwaUri[1] | Should -BeExactly $Script:worldwide.OwaMail
        }

        It "reproduces the worldwide Microsoft Entra authority" {
            $Script:AzureADEndpointUri | Should -BeExactly $Script:worldwide.AzureAD
        }

        It "reproduces the worldwide TokenIssuingEndpoint pattern including its wildcard" {
            $Script:AzureADTokenIssuingEndpointPattern | Should -BeExactly $Script:worldwide.TokenIssuingPattern
        }

        It "reproduces the worldwide AuthMetadataUrl pattern including its wildcard" {
            $Script:AzureADAuthMetadataUrlPattern | Should -BeExactly $Script:worldwide.AuthMetadataPattern
        }

        It "reproduces the worldwide AuthServer issuer" {
            $Script:AuthServerIssuerUri | Should -BeExactly $Script:worldwide.AuthServerIssuer
        }

        It "reproduces the worldwide Federation Trust token issuer" {
            $Script:FederationTrustTokenIssuerUri | Should -BeExactly $Script:worldwide.FedTrustTokenIssuer
        }

        It "reproduces the worldwide Federation Trust metadata endpoint" {
            $Script:FederationTrustMetadataUri | Should -BeExactly $Script:worldwide.FedTrustMetadata
        }

        It "reproduces the worldwide Federation TarGetApplicationUri" {
            $Script:FederationTargetApplicationUri | Should -BeExactly $Script:worldwide.FedTargetApplicationUri
        }

        It "reproduces the worldwide Hybrid Agent TarGetApplicationUri" {
            $Script:HybridAgentTargetApplicationUri | Should -BeExactly $Script:worldwide.HybridAgentTargetAppUri
        }
    }

    Context "When overrides are supplied" {
        BeforeAll {
            SetExpectedEndpointValues -ExchangeOnlineAutoDiscoverEndpointUri $Script:sovereign.AutoDiscover `
                -AzureADEndpointUri $Script:sovereign.AzureAD
        }

        It "derives the WSSecurity endpoint from the override" {
            $Script:ExchangeOnlineAutoDiscoverWsSecurityUri | Should -BeExactly "$($Script:sovereign.AutoDiscover)/WSSecurity"
        }

        It "derives the Hybrid Agent AutoDiscover endpoint from the override" {
            $Script:HybridAgentAutoDiscoverEndpointUri | Should -BeExactly "$($Script:sovereign.AutoDiscover)/"
        }

        It "keeps the trailing wildcard on the TokenIssuingEndpoint pattern" {
            $Script:AzureADTokenIssuingEndpointPattern | Should -BeExactly "$($Script:sovereign.AzureAD)/common/oauth2/token*"
        }

        It "keeps the embedded wildcard on the AuthMetadataUrl pattern" {
            $Script:AzureADAuthMetadataUrlPattern | Should -BeExactly "$($Script:sovereign.AzureAD)/*/federationmetadata/2007-06/federationmetadata.xml"
        }
    }

    Context "When an override carries a trailing slash" {
        BeforeAll {
            SetExpectedEndpointValues -ExchangeOnlineAutoDiscoverEndpointUri "$($Script:sovereign.AutoDiscover)/" `
                -AzureADEndpointUri "$($Script:sovereign.AzureAD)/"
        }

        It "does not produce a doubled slash in the derived WSSecurity endpoint" {
            $Script:ExchangeOnlineAutoDiscoverWsSecurityUri | Should -BeExactly "$($Script:sovereign.AutoDiscover)/WSSecurity"
        }

        It "does not produce a doubled slash in the derived AuthMetadataUrl pattern" {
            $Script:AzureADAuthMetadataUrlPattern | Should -BeExactly "$($Script:sovereign.AzureAD)/*/federationmetadata/2007-06/federationmetadata.xml"
        }
    }
}

Describe "FreeBusyChecker endpoint parameter defaults" {
    BeforeAll {
        $Script:scriptPath = "$Script:parentPath\FreeBusyChecker.ps1"
        $Script:commonPath = "$Script:parentPath\Functions\CommonFunctions.ps1"
        $Script:endpointParameters = @(
            "ExchangeOnlineEwsEndpointUri"
            "ExchangeOnlineAutoDiscoverEndpointUri"
            "ExchangeOnlineOwaUri"
            "AzureADEndpointUri"
            "AuthServerIssuerUri"
            "FederationTrustTokenIssuerUri"
            "FederationTrustMetadataUri"
            "FederationTargetApplicationUri"
            "HybridAgentTargetApplicationUri"
        )
    }

    It "declares every endpoint parameter on the script" {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Script:scriptPath, [ref]$null, [ref]$null)
        $declared = $ast.ParamBlock.Parameters.Name.VariablePath.UserPath
        foreach ($name in $Script:endpointParameters) {
            $declared | Should -Contain $name
        }
    }

    It "keeps the script defaults and the SetExpectedEndpointValues defaults in agreement" {
        foreach ($name in $Script:endpointParameters) {
            $fromScript = GetParameterDefault -Path $Script:scriptPath -ParameterName $name
            $fromFunction = GetParameterDefault -Path $Script:commonPath -FunctionName "SetExpectedEndpointValues" -ParameterName $name
            $fromScript | Should -BeExactly $fromFunction -Because "$name must default to the same value in both places"
        }
    }
}

Describe "FreeBusyChecker parameter sets" {
    BeforeAll {
        # Bind against a copy of the real attribute and param block so the parameter sets are exercised without
        # starting the script, which would require an Exchange shell.
        $Script:scriptPath = "$Script:parentPath\FreeBusyChecker.ps1"
        $content = Get-Content $Script:scriptPath -Raw
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$null)
        $firstAttribute = $ast.ParamBlock.Attributes | Sort-Object { $_.Extent.StartOffset } | Select-Object -First 1
        $begin = $firstAttribute.Extent.StartOffset
        $paramBlock = $content.Substring($begin, ($ast.ParamBlock.Extent.EndOffset - $begin))

        $Script:bindingStub = Join-Path ([System.IO.Path]::GetTempPath()) "FreeBusyCheckerParameterSets.$PID.ps1"
        Set-Content -Path $Script:bindingStub -Value "$paramBlock`n`$PSCmdlet.ParameterSetName" -Encoding UTF8

        $Script:override = @{ ExchangeOnlineEwsEndpointUri = "https://outlook.office365.example/EWS/Exchange.asmx" }
    }

    AfterAll {
        Remove-Item $Script:bindingStub -Force -ErrorAction SilentlyContinue
    }

    It "does not place SkipVersionCheck in a parameter set of its own" {
        # Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1 documents that SkipVersionCheck carries no
        # ParameterSetName, so it stays usable alongside every other parameter.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Script:scriptPath, [ref]$null, [ref]$null)
        $parameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "SkipVersionCheck" }
        $parameter | Should -Not -BeNullOrEmpty

        $setNames = $parameter.Attributes |
            Where-Object { $_.TypeName.FullName -eq "Parameter" } |
            ForEach-Object { $_.NamedArguments } |
            Where-Object { $_.ArgumentName -eq "ParameterSetName" }
        $setNames | Should -BeNullOrEmpty -Because "SkipVersionCheck must belong to every parameter set"
    }

    It "binds -SkipVersionCheck together with an endpoint override" {
        # An air-gapped organization needs the overrides and has no route to the update check.
        $splat = $Script:override + @{ SkipVersionCheck = $true }
        { & $Script:bindingStub @splat } | Should -Not -Throw
    }

    It "binds -SkipVersionCheck together with -Auth" {
        { & $Script:bindingStub -Auth "OAuth" -SkipVersionCheck } | Should -Not -Throw
    }

    It "resolves the Test parameter set for an endpoint override" {
        $splat = $Script:override
        & $Script:bindingStub @splat | Should -BeExactly "Test"
    }

    It "still resolves the dedicated parameter sets" {
        & $Script:bindingStub -ScriptUpdateOnly | Should -BeExactly "ScriptUpdateOnly"
        & $Script:bindingStub -Help | Should -BeExactly "Help"
    }
}

Describe "OrgRelCheck TarGetSharingEpr" {
    BeforeAll {
        $Script:ExchangeOnlineDomain = "contoso.mail.onmicrosoft.com"

        function Script:NewOrgRel {
            param([string]$TarGetSharingEpr, [string]$TarGetAutoDiscoverEpr)
            return [PSCustomObject]@{
                DomainNames           = $Script:ExchangeOnlineDomain
                FreeBusyAccessEnabled = $true
                FreeBusyAccessLevel   = "AvailabilityOnly"
                FreeBusyAccessScope   = ""
                TarGetOwAUrl          = ""
                TarGetSharingEpr      = $TarGetSharingEpr
                TarGetAutoDiscoverEpr = $TarGetAutoDiscoverEpr
                Enabled               = $true
                ArchiveAccessEnabled  = $false
            }
        }
    }

    It "reports a sovereign TarGetSharingEpr as incorrect when no override is supplied" {
        SetExpectedEndpointValues
        $orgRel = NewOrgRel -TarGetSharingEpr $Script:sovereign.Ews -TarGetAutoDiscoverEpr $Script:worldwide.AutoDiscoverWsSecurity
        $output = (OrgRelCheck -OrgRelParameter $orgRel 6>&1) | Out-String

        $output | Should -Match "TarGetSharingEpr Should be blank"
        $output | Should -Match "Configurations may not be Correct"
    }

    It "accepts a sovereign TarGetSharingEpr when the matching override is supplied" {
        SetExpectedEndpointValues -ExchangeOnlineEwsEndpointUri $Script:sovereign.Ews `
            -ExchangeOnlineAutoDiscoverEndpointUri $Script:sovereign.AutoDiscover
        $orgRel = NewOrgRel -TarGetSharingEpr $Script:sovereign.Ews `
            -TarGetAutoDiscoverEpr "$($Script:sovereign.AutoDiscover)/WSSecurity"
        $output = (OrgRelCheck -OrgRelParameter $orgRel 6>&1) | Out-String

        $output | Should -Match "TarGetSharingEpr Is ideally blank"
        $output | Should -Match "TarGetAutoDiscoverEpr Is correct"
        $output | Should -Match "Configurations Seem Correct"
    }

    It "still accepts the worldwide TarGetSharingEpr when no override is supplied" {
        SetExpectedEndpointValues
        $orgRel = NewOrgRel -TarGetSharingEpr $Script:worldwide.Ews -TarGetAutoDiscoverEpr $Script:worldwide.AutoDiscoverWsSecurity
        $output = (OrgRelCheck -OrgRelParameter $orgRel 6>&1) | Out-String

        $output | Should -Match "TarGetSharingEpr Is ideally blank"
        $output | Should -Match "Configurations Seem Correct"
    }
}

Describe "AuthServerCheck" {
    BeforeAll {
        function Script:NewAuthServer {
            param([string]$Authority, [string]$Issuer)
            return [PSCustomObject]@{
                Name                 = "EvoSts - 00000000-0000-0000-0000-000000000000"
                Realm                = "00000000-0000-0000-0000-000000000000"
                IssuerIdentifier     = "$Issuer/00000000-0000-0000-0000-000000000000/"
                TokenIssuingEndpoint = "$Authority/common/oauth2/token"
                AuthMetadataUrl      = "$Authority/contoso.onmicrosoft.com/federationmetadata/2007-06/federationmetadata.xml"
                Enabled              = $true
            }
        }
    }

    It "reports a sovereign AuthServer as incorrect when no override is supplied" {
        Mock Get-AuthServer { NewAuthServer -Authority $Script:sovereign.AzureAD -Issuer $Script:sovereign.AuthServerIssuer }
        SetExpectedEndpointValues
        $output = (AuthServerCheck 6>&1) | Out-String

        $output | Should -Match "IssuerIdentifier appears not to be correct"
        $output | Should -Match "TokenIssuingEndpoint appears not to be correct"
        $output | Should -Match "AuthMetadataUrl appears not to be correct"
    }

    It "accepts a sovereign AuthServer when the matching overrides are supplied" {
        Mock Get-AuthServer { NewAuthServer -Authority $Script:sovereign.AzureAD -Issuer $Script:sovereign.AuthServerIssuer }
        SetExpectedEndpointValues -AzureADEndpointUri $Script:sovereign.AzureAD `
            -AuthServerIssuerUri $Script:sovereign.AuthServerIssuer
        $output = (AuthServerCheck 6>&1) | Out-String

        $output | Should -Not -Match "appears not to be correct"
        $Script:tDAuthServerIssuerIdentifierColor | Should -BeExactly "green"
        $Script:tDAuthServerTokenIssuingEndpointColor | Should -BeExactly "green"
        $Script:tDAuthServerAuthMetadataUrlColor | Should -BeExactly "green"
    }

    It "still accepts the worldwide AuthServer when no override is supplied" {
        Mock Get-AuthServer { NewAuthServer -Authority $Script:worldwide.AzureAD -Issuer $Script:worldwide.AuthServerIssuer }
        SetExpectedEndpointValues
        $output = (AuthServerCheck 6>&1) | Out-String

        $output | Should -Not -Match "appears not to be correct"
        $Script:tDAuthServerTokenIssuingEndpointColor | Should -BeExactly "green"
    }
}
