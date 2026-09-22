# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeDiscovery -ScriptBlock {
    $endpointCases = @(
        @{ Scenario = "module defaults"; Endpoints = @{} }
        @{ Scenario = "source connection only"; Endpoints = @{ SourceConnectionUri = "https://source.example.com/powershell" } }
        @{ Scenario = "source authorization only"; Endpoints = @{ SourceAzureADAuthorizationEndpointUri = "https://source.example.com/authorize" } }
        @{ Scenario = "source endpoint pair"; Endpoints = @{
                SourceConnectionUri                   = "https://source.example.com/powershell"
                SourceAzureADAuthorizationEndpointUri = "https://source.example.com/authorize"
            }
        }
        @{ Scenario = "target connection only"; Endpoints = @{ TargetConnectionUri = "https://target.example.com/powershell" } }
        @{ Scenario = "target authorization only"; Endpoints = @{ TargetAzureADAuthorizationEndpointUri = "https://target.example.com/authorize" } }
        @{ Scenario = "target endpoint pair"; Endpoints = @{
                TargetConnectionUri                   = "https://target.example.com/powershell"
                TargetAzureADAuthorizationEndpointUri = "https://target.example.com/authorize"
            }
        }
        @{ Scenario = "independent tenant endpoint pairs"; Endpoints = @{
                SourceConnectionUri                   = "https://source.example.com/powershell"
                SourceAzureADAuthorizationEndpointUri = "https://source.example.com/authorize"
                TargetConnectionUri                   = "https://target.example.com/powershell"
                TargetAzureADAuthorizationEndpointUri = "https://target.example.com/authorize"
            }
        }
        @{ Scenario = "source connection and target authorization"; Endpoints = @{
                SourceConnectionUri                   = "https://source.example.com/powershell"
                TargetAzureADAuthorizationEndpointUri = "https://target.example.com/authorize"
            }
        }
        @{ Scenario = "source authorization and target connection"; Endpoints = @{
                SourceAzureADAuthorizationEndpointUri = "https://source.example.com/authorize"
                TargetConnectionUri                   = "https://target.example.com/powershell"
            }
        }
    )
    $Script:connectionCases = foreach ($helper in @(
            @{ HelperName = "ConnectToEXOTenants"; ExpectedPrefixes = @("Source", "Target") }
            @{ HelperName = "ConnectToSourceEXOTenant"; ExpectedPrefixes = @("Source") }
            @{ HelperName = "ConnectToTargetEXOTenant"; ExpectedPrefixes = @("Target") }
        )) {
        foreach ($endpointCase in $endpointCases) {
            @{
                HelperName       = $helper.HelperName
                ExpectedPrefixes = $helper.ExpectedPrefixes
                Scenario         = $endpointCase.Scenario
                Endpoints        = $endpointCase.Endpoints
            }
        }
    }
    $Script:bindingCases = foreach ($mode in @(
            @{ ParameterSetName = "ObjectsValidation"; ModeParameters = @{ CheckObjects = $true; LogPath = "validation.log" } }
            @{ ParameterSetName = "OrgsValidation"; ModeParameters = @{ CheckOrgs = $true; LogPath = "validation.log" } }
            @{ ParameterSetName = "SDP"; ModeParameters = @{ SDP = $true; LogPath = "validation.log"; PathForCollectedData = "collected" } }
            @{ ParameterSetName = "CollectMode"; ModeParameters = @{ CollectSourceOnly = $true; LogPath = "validation.log"; PathForCollectedData = "collected" } }
            @{ ParameterSetName = "OfflineMode"; ModeParameters = @{ SourceIsOffline = $true; CheckObjects = $true; LogPath = "validation.log"; PathForCollectedData = "collected.zip" } }
            @{ ParameterSetName = "OfflineMode"; ModeParameters = @{ SourceIsOffline = $true; CheckOrgs = $true; LogPath = "validation.log"; PathForCollectedData = "collected.zip" } }
        )) {
        foreach ($endpointCase in $endpointCases) {
            @{
                ParameterSetName = $mode.ParameterSetName
                ModeParameters   = $mode.ModeParameters
                Scenario         = $endpointCase.Scenario
                Endpoints        = $endpointCase.Endpoints
            }
        }
    }
    $endpointNames = @(
        "SourceConnectionUri"
        "SourceAzureADAuthorizationEndpointUri"
        "TargetConnectionUri"
        "TargetAzureADAuthorizationEndpointUri"
    )
    $Script:invalidCases = foreach ($endpointName in $endpointNames) {
        @{ EndpointName = $endpointName; Value = $null; Description = "null" }
        @{ EndpointName = $endpointName; Value = ""; Description = "empty" }
    }
    $Script:updateCases = foreach ($endpointName in $endpointNames) {
        @{ EndpointName = $endpointName }
    }
}

BeforeAll -Scriptblock {
    $scriptPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "CrossTenantMailboxMigrationValidation.ps1"
    $Script:parseErrors = $null
    $Script:ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$Script:parseErrors)
    # Extract only connection helpers and parameter binding to avoid module loading, COM, and live script execution.
    $functions = $Script:ast.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $Node.Name -in @("ConnectToEXOTenants", "ConnectToSourceEXOTenant", "ConnectToTargetEXOTenant")
        }, $false)
    foreach ($function in $functions) {
        . ([ScriptBlock]::Create($function.Extent.Text))
    }
    $Script:parameterBinding = [ScriptBlock]::Create($Script:ast.ParamBlock.Extent.Text + @'

[PSCustomObject]@{
    ParameterSetName = $PSCmdlet.ParameterSetName
    BoundParameters = $PSBoundParameters
}
'@)

    function Connect-ExchangeOnline {
        [CmdletBinding()]
        param(
            [string]$Prefix,
            [bool]$ShowBanner,
            [string]$ConnectionUri,
            [string]$AzureADAuthorizationEndpointUri
        )
        throw "Exchange Online must be mocked."
    }
}

Describe -Name "Cross-tenant Exchange Online endpoint overrides" -Fixture {
    BeforeAll -Scriptblock {
        Mock -CommandName Connect-ExchangeOnline -MockWith {
            $Script:connectionCalls.Add(@{} + $PesterBoundParameters)
        }
    }

    BeforeEach -Scriptblock {
        $Script:SourceConnectionUri = $null
        $Script:SourceAzureADAuthorizationEndpointUri = $null
        $Script:TargetConnectionUri = $null
        $Script:TargetAzureADAuthorizationEndpointUri = $null
        $Script:connectionCalls = [System.Collections.Generic.List[object]]::new()
        $Script:wsh = [PSCustomObject]@{ Calls = [System.Collections.Generic.List[object]]::new() }
        $Script:wsh | Add-Member -MemberType ScriptMethod -Name Popup -Value {
            param($Message, $Timeout, $Title)
            $this.Calls.Add([PSCustomObject]@{ Message = $Message; Timeout = $Timeout; Title = $Title })
            return 0
        }
    }

    It -Name "<HelperName> preserves tenant isolation with <Scenario>" -TestCases $Script:connectionCases -Test {
        param($HelperName, $ExpectedPrefixes, $Endpoints)
        foreach ($endpoint in $Endpoints.GetEnumerator()) {
            Set-Variable -Name $endpoint.Key -Value $endpoint.Value -Scope Script
        }

        & $HelperName

        $Script:connectionCalls.Count | Should -Be $ExpectedPrefixes.Count
        $Script:wsh.Calls.Count | Should -Be $ExpectedPrefixes.Count
        for ($index = 0; $index -lt $ExpectedPrefixes.Count; $index++) {
            $prefix = $ExpectedPrefixes[$index]
            $call = $Script:connectionCalls[$index]
            $call.Prefix | Should -BeExactly $prefix
            $call.ShowBanner | Should -BeFalse
            $expectedCount = 2
            foreach ($parameter in @("ConnectionUri", "AzureADAuthorizationEndpointUri")) {
                $endpointName = $prefix + $parameter
                $call.ContainsKey($parameter) | Should -Be $Endpoints.ContainsKey($endpointName)
                if ($Endpoints.ContainsKey($endpointName)) {
                    $call[$parameter] | Should -BeExactly $Endpoints[$endpointName]
                    $expectedCount++
                }
            }
            $call.Count | Should -Be $expectedCount
            $Script:wsh.Calls[$index].Title | Should -BeExactly "$($prefix.ToUpper()) tenant"
            $Script:wsh.Calls[$index].Timeout | Should -Be 0
            $Script:wsh.Calls[$index].Message | Should -BeExactly "You're about to connect to $($prefix.ToLower()) tenant (EXO), please provide the $($prefix.ToUpper()) tenant admin credentials"
        }
    }

    It -Name "does not retain <Prefix> overrides between connections" -TestCases @(
        @{ Prefix = "Source"; HelperName = "ConnectToSourceEXOTenant" }
        @{ Prefix = "Target"; HelperName = "ConnectToTargetEXOTenant" }
    ) -Test {
        param($Prefix, $HelperName)
        Set-Variable -Name ($Prefix + "ConnectionUri") -Value "https://example.com/powershell" -Scope Script
        Set-Variable -Name ($Prefix + "AzureADAuthorizationEndpointUri") -Value "https://example.com/authorize" -Scope Script
        & $HelperName
        Set-Variable -Name ($Prefix + "ConnectionUri") -Value $null -Scope Script
        Set-Variable -Name ($Prefix + "AzureADAuthorizationEndpointUri") -Value $null -Scope Script
        & $HelperName

        $Script:connectionCalls.Count | Should -Be 2
        $Script:connectionCalls[0].Count | Should -Be 4
        $Script:connectionCalls[1].Count | Should -Be 2
        $Script:connectionCalls[1].ContainsKey("ConnectionUri") | Should -BeFalse
        $Script:connectionCalls[1].ContainsKey("AzureADAuthorizationEndpointUri") | Should -BeFalse
    }
}

Describe -Name "Cross-tenant script parameter binding" -Fixture {
    It -Name "has no parser errors" -Test {
        $Script:parseErrors | Should -BeNullOrEmpty
    }

    It -Name "keeps existing parameters before the appended endpoint overrides" -Test {
        $names = @($Script:ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $names[0..9] -join "," | Should -BeExactly "CheckObjects,CSV,LogPath,CheckOrgs,SDP,CollectSourceOnly,PathForCollectedData,SourceIsOffline,SkipVersionCheck,ScriptUpdateOnly"
    }

    It -Name "binds <Scenario> in <ParameterSetName>" -TestCases $Script:bindingCases -Test {
        param($ParameterSetName, $ModeParameters, $Endpoints)
        $parameters = @{} + $ModeParameters + $Endpoints
        $result = & $Script:parameterBinding @parameters

        $result.ParameterSetName | Should -BeExactly $ParameterSetName
        $result.BoundParameters.Count | Should -Be $parameters.Count
        foreach ($endpoint in $Endpoints.GetEnumerator()) {
            $result.BoundParameters[$endpoint.Key] | Should -BeExactly $endpoint.Value
        }
    }

    It -Name "rejects <Description> for <EndpointName>" -TestCases $Script:invalidCases -Test {
        param($EndpointName, $Value)
        $parameters = @{ CheckObjects = $true; LogPath = "validation.log"; $EndpointName = $Value }
        { & $Script:parameterBinding @parameters } | Should -Throw
    }

    It -Name "rejects <EndpointName> with ScriptUpdateOnly" -TestCases $Script:updateCases -Test {
        param($EndpointName)
        $parameters = @{ ScriptUpdateOnly = $true; $EndpointName = "https://example.com/endpoint" }
        { & $Script:parameterBinding @parameters } | Should -Throw
    }

    It -Name "preserves ScriptUpdateOnly without endpoint overrides" -Test {
        $result = & $Script:parameterBinding -ScriptUpdateOnly
        $result.ParameterSetName | Should -BeExactly "ScriptUpdateOnly"
        $result.BoundParameters.Count | Should -Be 1
    }
}
