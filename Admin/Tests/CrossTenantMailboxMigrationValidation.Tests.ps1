# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Stub definitions that exist only so Pester can mock the real cmdlets')]
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
        @{ Scenario = "graph endpoint pair"; Endpoints = @{
                GraphEndpointUri   = "https://graph.example.com"
                AzureADEndpointUri = "https://login.example.com"
            }
        }
        @{ Scenario = "AAD app redirect override"; Endpoints = @{ AADAppRedirectUri = "https://portal.example.com" } }
        @{ Scenario = "all graph overrides"; Endpoints = @{
                GraphEndpointUri   = "https://graph.example.com"
                AzureADEndpointUri = "https://login.example.com"
                AADAppRedirectUri  = "https://portal.example.com"
            }
        }
    )
    $Script:exoEndpointCases = $endpointCases | Where-Object {
        $_.Endpoints.Keys.Count -eq 0 -or -not ($_.Endpoints.Keys | Where-Object { $_ -notlike "Source*" -and $_ -notlike "Target*" })
    }
    $Script:connectionCases = foreach ($helper in @(
            @{ HelperName = "ConnectToEXOTenants"; ExpectedPrefixes = @("Source", "Target") }
            @{ HelperName = "ConnectToSourceEXOTenant"; ExpectedPrefixes = @("Source") }
            @{ HelperName = "ConnectToTargetEXOTenant"; ExpectedPrefixes = @("Target") }
        )) {
        foreach ($endpointCase in $Script:exoEndpointCases) {
            @{
                HelperName       = $helper.HelperName
                ExpectedPrefixes = $helper.ExpectedPrefixes
                Scenario         = $endpointCase.Scenario
                Endpoints        = $endpointCase.Endpoints
            }
        }
    }
    $Script:allEndpointNames = @(
        "SourceConnectionUri"
        "SourceAzureADAuthorizationEndpointUri"
        "TargetConnectionUri"
        "TargetAzureADAuthorizationEndpointUri"
        "GraphEndpointUri"
        "AzureADEndpointUri"
        "AADAppRedirectUri"
    )
    # Each execution path only connects to the tenants and services it actually uses, so the parameter
    # sets only accept the overrides that can take effect. Keep this in sync with the param block.
    $modes = @(
        @{
            ParameterSetName = "ObjectsValidation"
            ModeParameters   = @{ CheckObjects = $true; LogPath = "validation.log" }
            Allowed          = @("SourceConnectionUri", "SourceAzureADAuthorizationEndpointUri", "TargetConnectionUri", "TargetAzureADAuthorizationEndpointUri")
        }
        @{
            ParameterSetName = "OrgsValidation"
            ModeParameters   = @{ CheckOrgs = $true; LogPath = "validation.log" }
            Allowed          = $Script:allEndpointNames
        }
        @{
            ParameterSetName = "SDP"
            ModeParameters   = @{ SDP = $true; LogPath = "validation.log"; PathForCollectedData = "collected" }
            Allowed          = $Script:allEndpointNames
        }
        @{
            ParameterSetName = "CollectMode"
            ModeParameters   = @{ CollectSourceOnly = $true; LogPath = "validation.log"; PathForCollectedData = "collected" }
            Allowed          = @("SourceConnectionUri", "SourceAzureADAuthorizationEndpointUri", "GraphEndpointUri", "AzureADEndpointUri", "AADAppRedirectUri")
        }
        @{
            ParameterSetName = "OfflineMode"
            ModeParameters   = @{ SourceIsOffline = $true; CheckObjects = $true; LogPath = "validation.log"; PathForCollectedData = "collected.zip" }
            Allowed          = @("TargetConnectionUri", "TargetAzureADAuthorizationEndpointUri", "GraphEndpointUri", "AzureADEndpointUri", "AADAppRedirectUri")
        }
        @{
            ParameterSetName = "OfflineMode"
            ModeParameters   = @{ SourceIsOffline = $true; CheckOrgs = $true; LogPath = "validation.log"; PathForCollectedData = "collected.zip" }
            Allowed          = @("TargetConnectionUri", "TargetAzureADAuthorizationEndpointUri", "GraphEndpointUri", "AzureADEndpointUri", "AADAppRedirectUri")
        }
    )
    $Script:bindingCases = foreach ($mode in $modes) {
        foreach ($endpointCase in $endpointCases) {
            if ($endpointCase.Endpoints.Keys | Where-Object { $_ -notin $mode.Allowed }) { continue }
            @{
                ParameterSetName = $mode.ParameterSetName
                ModeParameters   = $mode.ModeParameters
                Scenario         = $endpointCase.Scenario
                Endpoints        = $endpointCase.Endpoints
            }
        }
    }
    $Script:rejectedSetCases = foreach ($mode in $modes) {
        foreach ($endpointName in ($Script:allEndpointNames | Where-Object { $_ -notin $mode.Allowed })) {
            @{
                ParameterSetName = $mode.ParameterSetName
                ModeParameters   = $mode.ModeParameters
                EndpointName     = $endpointName
                Scenario         = ($mode.ModeParameters.Keys | Sort-Object) -join "+"
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
    $Script:invalidGraphCases = foreach ($endpointName in @("GraphEndpointUri", "AzureADEndpointUri", "AADAppRedirectUri")) {
        @{ EndpointName = $endpointName; Value = $null; Description = "null" }
        @{ EndpointName = $endpointName; Value = ""; Description = "empty" }
    }
    $Script:updateCases = foreach ($endpointName in $Script:allEndpointNames) {
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
            $Node.Name -in @("ConnectToEXOTenants", "ConnectToSourceEXOTenant", "ConnectToTargetEXOTenant",
                "TestGraphEndpointParameters", "RemoveGraphEnvironment", "ConnectToTenantAAD", "KillSessions")
        }, $false)
    foreach ($function in $functions) {
        . ([ScriptBlock]::Create($function.Extent.Text))
    }
    # The migration endpoint check is the first statement of each org validation helper. Extracting just that
    # statement keeps the assertion on real script code without running the rest of the validation.
    $Script:migrationEndpointChecks = @{}
    foreach ($helperName in @("CheckOrgs", "CheckOrgsSourceOffline")) {
        $helper = $Script:ast.Find({
                param($Node)
                $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $helperName
            }, $false)
        $Script:migrationEndpointChecks[$helperName] = [ScriptBlock]::Create($helper.Body.EndBlock.Statements[0].Extent.Text)
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

    function Connect-MgGraph {
        [CmdletBinding()]
        param(
            [string[]]$Scopes,
            [string]$Environment
        )
        throw "Microsoft Graph must be mocked."
    }

    function Get-MgEnvironment {
        [CmdletBinding()]
        param([string]$Name)
        throw "Microsoft Graph must be mocked."
    }

    function Add-MgEnvironment {
        [CmdletBinding()]
        param([string]$Name, [string]$GraphEndpoint, [string]$AzureADEndpoint)
        throw "Microsoft Graph must be mocked."
    }

    function Set-MgEnvironment {
        [CmdletBinding()]
        param([string]$Name, [string]$GraphEndpoint, [string]$AzureADEndpoint)
        throw "Microsoft Graph must be mocked."
    }

    function Remove-MgEnvironment {
        [CmdletBinding()]
        param([string]$Name)
        throw "Microsoft Graph must be mocked."
    }

    function Get-TargetMigrationEndpoint {
        [CmdletBinding()]
        param()
        throw "Exchange Online must be mocked."
    }

    # Shadow the session cmdlets so the tests can pipe plain objects without binding to real PSSession types.
    function Get-PSSession {
        [CmdletBinding()]
        param()
        throw "Remote sessions must be mocked."
    }

    function Remove-PSSession {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            $Session
        )
        process { throw "Remote sessions must be mocked." }
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

Describe -Name "Cross-tenant Microsoft Graph endpoint overrides" -Fixture {
    BeforeEach -Scriptblock {
        $Script:GraphEndpointUri = $null
        $Script:AzureADEndpointUri = $null
        $Script:GraphEnvironmentName = "CrossTenantMailboxMigrationValidation"
        # Model the Microsoft Graph settings file so the tests see the same state the real cmdlets would leave behind.
        $Script:fakeEnvironments = @{}
        Mock -CommandName Get-MgEnvironment -MockWith {
            if ($Script:fakeEnvironments.ContainsKey($Name)) { $Script:fakeEnvironments[$Name] }
        }
        Mock -CommandName Add-MgEnvironment -MockWith {
            $Script:fakeEnvironments[$Name] = [PSCustomObject]@{ Name = $Name; GraphEndpoint = $GraphEndpoint; AzureADEndpoint = $AzureADEndpoint }
        }
        Mock -CommandName Set-MgEnvironment -MockWith {
            $Script:fakeEnvironments[$Name] = [PSCustomObject]@{ Name = $Name; GraphEndpoint = $GraphEndpoint; AzureADEndpoint = $AzureADEndpoint }
        }
        Mock -CommandName Remove-MgEnvironment -MockWith {
            $Script:fakeEnvironments.Remove($Name)
        }
        Mock -CommandName Connect-MgGraph -MockWith { }
    }

    It -Name "connects without an environment when no overrides are supplied" -Test {
        ConnectToTenantAAD

        Should -Invoke -CommandName Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            $Scopes -contains "Application.Read.All" -and -not $PSBoundParameters.ContainsKey("Environment")
        }
        Should -Invoke -CommandName Add-MgEnvironment -Times 0
        Should -Invoke -CommandName Set-MgEnvironment -Times 0
    }

    It -Name "registers the supplied endpoints and connects using them" -Test {
        $Script:GraphEndpointUri = "https://graph.example.com"
        $Script:AzureADEndpointUri = "https://login.example.com"

        ConnectToTenantAAD

        Should -Invoke -CommandName Add-MgEnvironment -Times 1 -Exactly -ParameterFilter {
            $Name -eq "CrossTenantMailboxMigrationValidation" -and
            $GraphEndpoint -eq "https://graph.example.com" -and
            $AzureADEndpoint -eq "https://login.example.com"
        }
        Should -Invoke -CommandName Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            $Scopes -contains "Application.Read.All" -and $Environment -eq "CrossTenantMailboxMigrationValidation"
        }
    }

    It -Name "does not leave the registered environment in the settings file" -Test {
        $Script:GraphEndpointUri = "https://graph.example.com"
        $Script:AzureADEndpointUri = "https://login.example.com"

        ConnectToTenantAAD

        $Script:fakeEnvironments.Count | Should -Be 0
        Should -Invoke -CommandName Remove-MgEnvironment -Times 1 -Exactly
    }

    It -Name "removes the registered environment when connecting fails" -Test {
        $Script:GraphEndpointUri = "https://graph.example.com"
        $Script:AzureADEndpointUri = "https://login.example.com"
        Mock -CommandName Connect-MgGraph -MockWith { throw "Authentication failed" }

        { ConnectToTenantAAD } | Should -Throw -ExpectedMessage "Authentication failed"

        $Script:fakeEnvironments.Count | Should -Be 0
        Should -Invoke -CommandName Remove-MgEnvironment -Times 1 -Exactly
    }

    It -Name "reuses an environment left behind by an earlier run" -Test {
        $Script:fakeEnvironments["CrossTenantMailboxMigrationValidation"] = [PSCustomObject]@{ Name = "CrossTenantMailboxMigrationValidation" }
        $Script:GraphEndpointUri = "https://graph.example.com"
        $Script:AzureADEndpointUri = "https://login.example.com"

        ConnectToTenantAAD

        Should -Invoke -CommandName Set-MgEnvironment -Times 1 -Exactly -ParameterFilter {
            $GraphEndpoint -eq "https://graph.example.com" -and $AzureADEndpoint -eq "https://login.example.com"
        }
        Should -Invoke -CommandName Add-MgEnvironment -Times 0
        $Script:fakeEnvironments.Count | Should -Be 0
    }

    It -Name "connects to Graph for both the source and the target tenant" -Test {
        $Script:GraphEndpointUri = "https://graph.example.com"
        $Script:AzureADEndpointUri = "https://login.example.com"

        ConnectToTenantAAD
        ConnectToTenantAAD

        Should -Invoke -CommandName Connect-MgGraph -Times 2 -Exactly -ParameterFilter {
            $Environment -eq "CrossTenantMailboxMigrationValidation"
        }
        $Script:fakeEnvironments.Count | Should -Be 0
    }

    It -Name "requires <EndpointName> to be paired with the other override" -TestCases @(
        @{ EndpointName = "GraphEndpointUri" }
        @{ EndpointName = "AzureADEndpointUri" }
    ) -Test {
        param($EndpointName)
        Set-Variable -Name $EndpointName -Value "https://only.example.com" -Scope Script

        { TestGraphEndpointParameters } | Should -Throw -ExpectedMessage "GraphEndpointUri and AzureADEndpointUri must be specified together"
        { ConnectToTenantAAD } | Should -Throw -ExpectedMessage "GraphEndpointUri and AzureADEndpointUri must be specified together"
        Should -Invoke -CommandName Add-MgEnvironment -Times 0
        Should -Invoke -CommandName Connect-MgGraph -Times 0
    }

    It -Name "reports whether the Graph overrides were supplied" -Test {
        TestGraphEndpointParameters | Should -BeFalse

        $Script:GraphEndpointUri = "https://graph.example.com"
        $Script:AzureADEndpointUri = "https://login.example.com"

        TestGraphEndpointParameters | Should -BeTrue
    }

    It -Name "does not remove an environment that is not registered" -Test {
        RemoveGraphEnvironment

        Should -Invoke -CommandName Remove-MgEnvironment -Times 0
    }
}

Describe -Name "Cross-tenant migration endpoint validation" -Fixture {
    BeforeEach -Scriptblock {
        $Script:TargetAADApp = [PSCustomObject]@{ AppId = "00000000-0000-0000-0000-000000000001" }
        Mock -CommandName Write-Host -MockWith { }
        Mock -CommandName Get-TargetMigrationEndpoint -MockWith { }
    }

    It -Name "<HelperName> accepts a RemoteServer outside the commercial cloud" -TestCases @(
        @{ HelperName = "CheckOrgs"; RemoteServer = "outlook.office365.us" }
        @{ HelperName = "CheckOrgsSourceOffline"; RemoteServer = "outlook.office365.us" }
        @{ HelperName = "CheckOrgs"; RemoteServer = "outlook.office.com" }
        @{ HelperName = "CheckOrgsSourceOffline"; RemoteServer = "outlook.office.com" }
    ) -Test {
        param($HelperName, $RemoteServer)
        Mock -CommandName Get-TargetMigrationEndpoint -MockWith {
            [PSCustomObject]@{
                EndpointType  = "ExchangeRemoteMove"
                ApplicationId = "00000000-0000-0000-0000-000000000001"
                RemoteServer  = $RemoteServer
            }
        }

        & $Script:migrationEndpointChecks[$HelperName]

        Should -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -eq "Migration endpoint found and correctly set, RemoteServer: $RemoteServer"
        }
    }

    It -Name "<HelperName> still reports a missing migration endpoint" -TestCases @(
        @{ HelperName = "CheckOrgs" }
        @{ HelperName = "CheckOrgsSourceOffline" }
    ) -Test {
        param($HelperName)
        Mock -CommandName Get-TargetMigrationEndpoint -MockWith {
            [PSCustomObject]@{
                EndpointType  = "ExchangeRemoteMove"
                ApplicationId = "00000000-0000-0000-0000-000000000002"
                RemoteServer  = "outlook.office365.us"
            }
        }

        & $Script:migrationEndpointChecks[$HelperName]

        Should -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -eq ">> Error: Expected Migration endpoint not found"
        }
    }
}

Describe -Name "Cross-tenant session cleanup" -Fixture {
    It -Name "removes Exchange Online sessions regardless of the cloud endpoint" -Test {
        $sessions = @(
            [PSCustomObject]@{ Name = "ExchangeOnlineInternalSession_1"; ComputerName = "outlook.office365.us" }
            [PSCustomObject]@{ Name = "ExchangeOnlineInternalSession_2"; ComputerName = "outlook.office365.com" }
            [PSCustomObject]@{ Name = "WinRM1"; ComputerName = "exchange.contoso.com" }
        )
        Mock -CommandName Get-PSSession -MockWith { $sessions }
        Mock -CommandName Remove-PSSession -MockWith { }

        KillSessions

        Should -Invoke -CommandName Remove-PSSession -Times 2 -Exactly
        Should -Invoke -CommandName Remove-PSSession -Times 0 -ParameterFilter { $Session.Name -eq "WinRM1" }
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

    It -Name "rejects <EndpointName> in <ParameterSetName> (<Scenario>)" -TestCases $Script:rejectedSetCases -Test {
        param($ModeParameters, $EndpointName)
        $parameters = @{} + $ModeParameters
        $parameters[$EndpointName] = "https://example.com/endpoint"
        { & $Script:parameterBinding @parameters } | Should -Throw
    }

    It -Name "defaults AADAppRedirectUri when it is not supplied" -Test {
        $result = & $Script:parameterBinding -CheckOrgs -LogPath "validation.log"
        $result.BoundParameters.ContainsKey("AADAppRedirectUri") | Should -BeFalse
    }

    It -Name "rejects <Description> for <EndpointName>" -TestCases $Script:invalidCases -Test {
        param($EndpointName, $Value)
        $parameters = @{ CheckObjects = $true; LogPath = "validation.log"; $EndpointName = $Value }
        { & $Script:parameterBinding @parameters } | Should -Throw
    }

    It -Name "rejects <Description> for <EndpointName>" -TestCases $Script:invalidGraphCases -Test {
        param($EndpointName, $Value)
        $parameters = @{ CheckOrgs = $true; LogPath = "validation.log"; $EndpointName = $Value }
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
