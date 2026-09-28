# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeDiscovery {
    $Script:connectionCases = @(
        @{
            ScriptPath   = 'MailPublicFolderSync\Import-MailPublicFolders.ps1'
            FunctionName = 'CreateTenantSession'
            Arguments    = @{}
            IsMigration  = $false
            IsDumpster   = $false
        }
        @{
            ScriptPath   = 'MailPublicFolderSync\Import-PublicFolderMailboxes.ps1'
            FunctionName = 'CreateTenantSession'
            Arguments    = @{}
            IsMigration  = $false
            IsDumpster   = $false
        }
        @{
            ScriptPath   = 'MailPublicFolderSync\Sync-MailPublicFolders.ps1'
            FunctionName = 'InitializeExchangeOnlineRemoteSession'
            Arguments    = @{ CsvSummaryFile = 'summary.csv' }
            IsMigration  = $false
            IsDumpster   = $false
        }
        @{
            ScriptPath   = 'MailPublicFolderSync\Sync-MailPublicFoldersCloudToOnprem.ps1'
            FunctionName = 'InitializeExchangeOnlineRemoteSession'
            Arguments    = @{ CsvSummaryFile = 'summary.csv' }
            IsMigration  = $false
            IsDumpster   = $false
        }
        @{
            ScriptPath   = 'Migration\ToMicrosoft365Groups\AddMembersToGroups.ps1'
            FunctionName = 'InitializeExchangeOnlineRemoteSession'
            Arguments    = @{ MappingCsv = 'map.csv'; BackupDir = 'backup'; ArePublicFoldersOnPremises = $true }
            IsMigration  = $true
            IsDumpster   = $false
        }
        @{
            ScriptPath   = 'Migration\ToMicrosoft365Groups\LockAndSavePublicFolderProperties.ps1'
            FunctionName = 'InitializeExchangeOnlineRemoteSession'
            Arguments    = @{ MappingCsv = 'map.csv'; BackupDir = 'backup'; ArePublicFoldersOnPremises = $true }
            IsMigration  = $true
            IsDumpster   = $false
        }
        @{
            ScriptPath   = 'Migration\ToMicrosoft365Groups\UnlockAndRestorePublicFolderProperties.ps1'
            FunctionName = 'InitializeExchangeOnlineRemoteSession'
            Arguments    = @{ BackupDir = 'backup'; ArePublicFoldersOnPremises = $true }
            IsMigration  = $true
            IsDumpster   = $false
        }
        @{
            ScriptPath   = 'ValidateEXOPFDumpster.ps1'
            FunctionName = 'Connect2EXO'
            Arguments    = @{ PFolder = '\ExampleFolder' }
            IsMigration  = $false
            IsDumpster   = $true
        }
    )
}

BeforeAll {
    function Connect-ExchangeOnline {
        [CmdletBinding()]
        param(
            [string]$ConnectionUri,
            [string]$AzureADAuthorizationEndpointUri,
            [PSCredential]$Credential,
            [string]$Prefix,
            [bool]$ShowBanner
        )
        throw 'Exchange Online connections must be mocked.'
    }

    function WriteInfoMessage { param($Message) }
    function WriteLog { param($Path, $Message) }
    function LogError { param($CurrentStatus, $Function, $CurrentDescription) }

    function Assert-ConnectionParameters {
        param([hashtable]$Expected)

        Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -Scope It
        ($Script:lastConnectionParameters.Keys | Sort-Object) -join ',' |
            Should -BeExactly (($Expected.Keys | Sort-Object) -join ',')
        foreach ($key in $Expected.Keys) {
            $Script:lastConnectionParameters[$key] | Should -Be $Expected[$key]
        }
    }
}

Describe 'Exchange Online authorization endpoints: <ScriptPath>' -ForEach $Script:connectionCases {
    BeforeAll {
        $parentPath = Split-Path -Path $PSScriptRoot -Parent
        $path = Join-Path -Path $parentPath -ChildPath $ScriptPath
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) {
            throw "Script parsing failed: $parseErrors"
        }

        $definition = $ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $FunctionName
        }
        $invocations = @($ast.FindAll({
                    $args[0] -is [System.Management.Automation.Language.CommandAst] -and
                    $args[0].GetCommandName() -eq $FunctionName
                }, $false))
        if ($null -eq $definition -or $invocations.Count -ne 1) {
            throw "Expected one connection helper and one invocation in $ScriptPath."
        }

        # Execute only the connection definition and its real call site, never migration or diagnostic bodies.
        $connectionCode = $invocations[0].Extent.Text
        if ($IsMigration -or $IsDumpster) {
            $connectionStatement = $invocations[0]
            while ($connectionStatement -isnot [System.Management.Automation.Language.IfStatementAst]) {
                $connectionStatement = $connectionStatement.Parent
                if ($null -eq $connectionStatement) {
                    throw "Expected a conditional connection in $ScriptPath."
                }
            }
            $connectionCode = $connectionStatement.Extent.Text
        }
        if ($IsDumpster) {
            $sessionAssignment = $ast.EndBlock.Statements | Where-Object {
                $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $_.Left.VariablePath.UserPath -eq 'SessionCheck'
            }
            $connectionCode = $sessionAssignment.Extent.Text + [Environment]::NewLine + $connectionCode
        }
        $Script:connectionScript = [ScriptBlock]::Create(
            $ast.ParamBlock.Extent.Text + [Environment]::NewLine +
            $definition.Extent.Text + [Environment]::NewLine + $connectionCode)
        $Script:parameterBinding = [ScriptBlock]::Create($ast.ParamBlock.Extent.Text + @'

[PSCustomObject]@{
    BoundParameters = $PSBoundParameters
    ParameterSetName = $PSCmdlet.ParameterSetName
    ConnectionUri = $ConnectionUri
    AzureADAuthorizationEndpointUri = $AzureADAuthorizationEndpointUri
}
'@)
        $Script:LocalizedStrings = @{
            CreatingRemoteSession            = 'Creating remote session'
            RemoteSessionCreatedSuccessfully = 'Remote session created'
        }
        $Script:logPath = 'connection.log'
        $Script:defaultConnection = @{ ErrorAction = 'Stop' }
        if (-not $IsDumpster) {
            $Script:defaultConnection = @{
                ConnectionUri = 'https://outlook.office365.com/powerShell-liveID'
                Prefix        = 'Remote'
                ErrorAction   = 'SilentlyContinue'
            }
        }
    }

    BeforeEach {
        $Script:lastConnectionParameters = @{}
        Mock -CommandName Import-Module -MockWith {} -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock -CommandName Get-Module -MockWith {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement' }
        } -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock -CommandName Get-PSSession -MockWith { $null }
        Mock -CommandName Connect-ExchangeOnline -MockWith {
            $Script:lastConnectionParameters = @{}
            foreach ($key in $PesterBoundParameters.Keys) {
                $Script:lastConnectionParameters[$key] = $PesterBoundParameters[$key]
            }
        }
        Mock -CommandName Write-Host -MockWith {}
        Mock -CommandName WriteInfoMessage -MockWith {}
        Mock -CommandName WriteLog -MockWith {}
        Mock -CommandName LogError -MockWith {}
    }

    It 'keeps the original connection parameters exactly when overrides are omitted' {
        & $Script:connectionScript @Arguments

        Assert-ConnectionParameters -Expected $Script:defaultConnection
        $binding = & $Script:parameterBinding @Arguments
        $binding.AzureADAuthorizationEndpointUri | Should -BeNullOrEmpty
        $binding.BoundParameters.ContainsKey('AzureADAuthorizationEndpointUri') | Should -BeFalse
        if ($IsDumpster) {
            $binding.ConnectionUri | Should -BeNullOrEmpty
            $binding.BoundParameters.ContainsKey('ConnectionUri') | Should -BeFalse
        } else {
            $binding.ConnectionUri | Should -BeExactly $Script:defaultConnection.ConnectionUri
        }
    }

    It 'forwards both overrides through the real helper call while preserving all other options' {
        $connectionUri = 'https://outlook.contoso.com/powershell'
        $authorizationUri = 'https://login.contoso.com/organizations'
        & $Script:connectionScript @Arguments -ConnectionUri $connectionUri -AzureADAuthorizationEndpointUri $authorizationUri

        $expected = $Script:defaultConnection.Clone()
        $expected.ConnectionUri = $connectionUri
        $expected.AzureADAuthorizationEndpointUri = $authorizationUri
        Assert-ConnectionParameters -Expected $expected
    }

    It 'does not require a connection URI override to forward the authorization endpoint' {
        $authorizationUri = 'https://login.contoso.com/organizations'
        & $Script:connectionScript @Arguments -AzureADAuthorizationEndpointUri $authorizationUri

        $expected = $Script:defaultConnection.Clone()
        $expected.AzureADAuthorizationEndpointUri = $authorizationUri
        Assert-ConnectionParameters -Expected $expected
    }

    It 'keeps the authorization endpoint omitted when only the connection URI is supplied' {
        $connectionUri = 'https://outlook.contoso.com/powershell'
        & $Script:connectionScript @Arguments -ConnectionUri $connectionUri

        $expected = $Script:defaultConnection.Clone()
        $expected.ConnectionUri = $connectionUri
        Assert-ConnectionParameters -Expected $expected
    }

    It 'rejects an explicitly empty authorization endpoint' {
        { & $Script:parameterBinding @Arguments -AzureADAuthorizationEndpointUri '' } | Should -Throw
    }

    It 'rejects an explicitly null authorization endpoint' {
        { & $Script:parameterBinding @Arguments -AzureADAuthorizationEndpointUri $null } | Should -Throw
    }

    It 'still supports the update-only parameter set without operational parameters' {
        $binding = & $Script:parameterBinding -ScriptUpdateOnly

        $binding.ParameterSetName | Should -BeExactly 'ScriptUpdateOnly'
    }

    It 'does not accept the authorization override in the update-only parameter set' {
        { & $Script:parameterBinding -ScriptUpdateOnly -AzureADAuthorizationEndpointUri 'https://login.contoso.com/organizations' } |
            Should -Throw
    }

    if (-not $IsDumpster) {
        It 'preserves credentials with and without the authorization override' {
            $credential = [PSCredential]::new('admin@contoso.com', [SecureString]::new())
            & $Script:connectionScript @Arguments -Credential $credential
            $Script:lastConnectionParameters.Credential | Should -Be $credential
            $Script:lastConnectionParameters.ContainsKey('AzureADAuthorizationEndpointUri') | Should -BeFalse

            & $Script:connectionScript @Arguments -Credential $credential -AzureADAuthorizationEndpointUri 'https://login.contoso.com/organizations'
            $Script:lastConnectionParameters.Credential | Should -Be $credential
            $Script:lastConnectionParameters.AzureADAuthorizationEndpointUri | Should -BeExactly 'https://login.contoso.com/organizations'
            $Script:lastConnectionParameters.Prefix | Should -BeExactly 'Remote'
            $Script:lastConnectionParameters.ErrorAction | Should -Be 'SilentlyContinue'
            $Script:lastConnectionParameters.Count | Should -Be 5
            Should -Invoke -CommandName Connect-ExchangeOnline -Times 2 -Exactly
        }
    }

    if ($IsMigration) {
        It 'does not create a connection for public folders already in Exchange Online' {
            $cloudArguments = $Arguments.Clone()
            $cloudArguments.ArePublicFoldersOnPremises = $false
            & $Script:connectionScript @cloudArguments -ConnectionUri 'https://outlook.contoso.com/powershell' -AzureADAuthorizationEndpointUri 'https://login.contoso.com/organizations'

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    if ($IsDumpster) {
        It 'reuses an existing open Exchange Online session even when overrides are provided' {
            Mock -CommandName Get-PSSession -MockWith {
                [PSCustomObject]@{ Name = 'ExchangeOnlineExample'; State = 'Opened' }
            }
            & $Script:connectionScript @Arguments -ConnectionUri 'https://outlook.contoso.com/powershell' -AzureADAuthorizationEndpointUri 'https://login.contoso.com/organizations'

            Should -Invoke -CommandName Connect-ExchangeOnline -Times 0 -Exactly
        }

        It 'creates a connection when the existing Exchange Online session is closed' {
            Mock -CommandName Get-PSSession -MockWith {
                [PSCustomObject]@{ Name = 'ExchangeOnlineExample'; State = 'Closed' }
            }
            & $Script:connectionScript @Arguments

            Assert-ConnectionParameters -Expected $Script:defaultConnection
        }

        It 'rejects an explicitly empty connection URI' {
            { & $Script:parameterBinding @Arguments -ConnectionUri '' } | Should -Throw
        }

        It 'rejects an explicitly null connection URI' {
            { & $Script:parameterBinding @Arguments -ConnectionUri $null } | Should -Throw
        }

        It 'does not accept the connection override in the update-only parameter set' {
            { & $Script:parameterBinding -ScriptUpdateOnly -ConnectionUri 'https://outlook.contoso.com/powershell' } | Should -Throw
        }
    }
}
