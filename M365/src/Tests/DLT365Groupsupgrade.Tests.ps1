# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore Groupsupgrade

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Module installation stub for Pester')]
[CmdletBinding()]
param()

BeforeAll {
    $scriptPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'DLT365Groupsupgrade.ps1'
    $parseErrors = $null
    $Script:ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw "The distribution group script has parsing errors: $parseErrors"
    }

    # Load functions without creating files, prompting, installing modules, or connecting to Exchange.
    $functions = $Script:ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $false)
    foreach ($definition in $functions) {
        . ([ScriptBlock]::Create($definition.Extent.Text))
    }
    $Script:parameterBinding = [ScriptBlock]::Create($Script:ast.ParamBlock.Extent.Text + "`n" + '$PSBoundParameters')

    $sessionAssignment = $Script:ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $_.Left.VariablePath.UserPath -eq 'SessionCheck'
    }
    $sessionCondition = $Script:ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.IfStatementAst] -and
        $null -ne $_.Find({
                $args[0] -is [System.Management.Automation.Language.CommandAst] -and
                $args[0].GetCommandName() -eq 'Connect2EXO'
            }, $true)
    }
    if ($null -eq $sessionAssignment -or $null -eq $sessionCondition) {
        throw 'Expected the session reuse check and connection call.'
    }
    $Script:sessionCode = [ScriptBlock]::Create($sessionAssignment.Extent.Text + "`n" + $sessionCondition.Extent.Text)

    function Connect-ExchangeOnline {
        [CmdletBinding()]
        param(
            [string]$ConnectionUri,
            [string]$AzureADAuthorizationEndpointUri
        )
        throw 'Exchange Online connections must be mocked.'
    }

    function Install-Module {
        [CmdletBinding()]
        param(
            [string]$Name,
            [switch]$Force,
            [string]$Scope
        )
        throw 'Module installation must be mocked.'
    }
}

Describe 'Distribution group endpoint parameters' {
    It 'keeps both overrides optional and unbound by default' {
        $result = & $Script:parameterBinding
        $result.ContainsKey('ConnectionUri') | Should -BeFalse
        $result.ContainsKey('AzureADAuthorizationEndpointUri') | Should -BeFalse
    }

    It 'binds either endpoint independently or both together' -TestCases @(
        @{ Overrides = @{ ConnectionUri = 'https://outlook.contoso.com/powershell' } }
        @{ Overrides = @{ AzureADAuthorizationEndpointUri = 'https://login.contoso.com/organizations' } }
        @{ Overrides = @{ ConnectionUri = 'https://outlook.contoso.com/powershell'; AzureADAuthorizationEndpointUri = 'https://login.contoso.com/organizations' } }
    ) {
        param($Overrides)
        $result = & $Script:parameterBinding @Overrides
        foreach ($key in $Overrides.Keys) {
            $result[$key] | Should -BeExactly $Overrides[$key]
        }
    }

    It 'rejects an explicitly empty or null endpoint for <Name>' -TestCases @(
        @{ Name = 'ConnectionUri'; Value = '' }
        @{ Name = 'ConnectionUri'; Value = $null }
        @{ Name = 'AzureADAuthorizationEndpointUri'; Value = '' }
        @{ Name = 'AzureADAuthorizationEndpointUri'; Value = $null }
    ) {
        param($Name, $Value)
        $overrides = @{ $Name = $Value }
        { & $Script:parameterBinding @overrides } | Should -Throw
    }
}

Describe 'Distribution group Exchange Online connections' {
    BeforeEach {
        $Script:ConnectionUri = $null
        $Script:AzureADAuthorizationEndpointUri = $null
        $Script:moduleLoaded = $false
        Mock -CommandName Get-Module -MockWith {
            if ($Script:moduleLoaded) {
                [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Count = 1 }
            }
        }
        Mock -CommandName Install-Module -MockWith {}
        Mock -CommandName Import-Module -MockWith {}
        Mock -CommandName Connect-ExchangeOnline -MockWith {}
        Mock -CommandName log -MockWith {}
        Mock -CommandName Write-Host -MockWith {}
        Mock -CommandName Write-Warning -MockWith {}
    }

    It 'preserves default connection arguments when module loaded is <Loaded>' -TestCases @(
        @{ Loaded = $true }
        @{ Loaded = $false }
    ) {
        param($Loaded)
        $Script:moduleLoaded = $Loaded

        Connect2EXO

        Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
            $ErrorAction -eq 'Stop' -and
            -not $PesterBoundParameters.ContainsKey('ConnectionUri') -and
            -not $PesterBoundParameters.ContainsKey('AzureADAuthorizationEndpointUri')
        }
        Should -Invoke -CommandName Import-Module -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'ExchangeOnlineManagement' -and $Force -and $ErrorAction -eq 'Stop'
        }
        $installCount = if ($Loaded) { 0 } else { 1 }
        Should -Invoke -CommandName Install-Module -Times $installCount -Exactly
    }

    It 'forwards supplied endpoints when module loaded is <Loaded> and selection is <Selection>' -TestCases @(
        @{ Loaded = $true; Selection = 'connection only'; Connection = 'https://outlook.contoso.com/powershell'; Authorization = $null }
        @{ Loaded = $false; Selection = 'connection only'; Connection = 'https://outlook.contoso.com/powershell'; Authorization = $null }
        @{ Loaded = $true; Selection = 'authorization only'; Connection = $null; Authorization = 'https://login.contoso.com/organizations' }
        @{ Loaded = $false; Selection = 'authorization only'; Connection = $null; Authorization = 'https://login.contoso.com/organizations' }
        @{ Loaded = $true; Selection = 'both'; Connection = 'https://outlook.contoso.com/powershell'; Authorization = 'https://login.contoso.com/organizations' }
        @{ Loaded = $false; Selection = 'both'; Connection = 'https://outlook.contoso.com/powershell'; Authorization = 'https://login.contoso.com/organizations' }
    ) {
        param($Loaded, $Selection, $Connection, $Authorization)
        $Script:moduleLoaded = $Loaded
        $Script:ConnectionUri = $Connection
        $Script:AzureADAuthorizationEndpointUri = $Authorization

        Connect2EXO

        Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
            $ErrorAction -eq 'Stop' -and
            $PesterBoundParameters.ContainsKey('ConnectionUri') -eq ($null -ne $Script:ConnectionUri) -and
            $PesterBoundParameters.ContainsKey('AzureADAuthorizationEndpointUri') -eq ($null -ne $Script:AzureADAuthorizationEndpointUri) -and
            ([string]$ConnectionUri) -ceq ([string]$Script:ConnectionUri) -and
            ([string]$AzureADAuthorizationEndpointUri) -ceq ([string]$Script:AzureADAuthorizationEndpointUri)
        }
    }

    It 'reuses an existing session even when overrides are provided' {
        $Script:ConnectionUri = 'https://outlook.contoso.com/powershell'
        $Script:AzureADAuthorizationEndpointUri = 'https://login.contoso.com/organizations'
        Mock -CommandName Get-PSSession -MockWith { [PSCustomObject]@{ Name = 'ExchangeOnlineExample'; State = 'Opened' } }
        Mock -CommandName Connect2EXO -MockWith {}

        & $Script:sessionCode

        Should -Invoke -CommandName Connect2EXO -Times 0 -Exactly
        Should -Invoke -CommandName Connect-ExchangeOnline -Times 0 -Exactly
    }

    It 'uses supplied overrides through the main connection path when there is no open session' {
        $Script:ConnectionUri = 'https://outlook.contoso.com/powershell'
        $Script:AzureADAuthorizationEndpointUri = 'https://login.contoso.com/organizations'
        Mock -CommandName Get-PSSession -MockWith {}

        & $Script:sessionCode

        Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
            $ConnectionUri -ceq $Script:ConnectionUri -and
            $AzureADAuthorizationEndpointUri -ceq $Script:AzureADAuthorizationEndpointUri
        }
    }
}
