# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Exchange command stubs for Pester')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Mocked Exchange command stubs expose parameter metadata only')]
[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = Split-Path -Path $PSScriptRoot -Parent
    $Script:scriptPath = Join-Path -Path $Script:parentPath -ChildPath "Sync-ModernMailPublicFolders.ps1"
    $parseErrors = $null
    $Script:ast = [System.Management.Automation.Language.Parser]::ParseFile($Script:scriptPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw "The public folder sync script has parsing errors: $parseErrors"
    }

    # Loading definitions only avoids script updates, authentication, and Exchange operations.
    $functionDefinitions = $Script:ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $false)
    foreach ($definition in $functionDefinitions) {
        . ([ScriptBlock]::Create($definition.Extent.Text))
    }

    $localizationAssignment = $Script:ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $_.Left.VariablePath.UserPath -eq 'LocalizedStrings'
    }
    $localizationCommand = $localizationAssignment.Right.PipelineElements[0]
    if ($localizationCommand.GetCommandName() -ne 'ConvertFrom-StringData' -or
        $localizationCommand.CommandElements[1] -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
        throw "Expected a literal localization table."
    }
    $Script:LocalizedStrings = ConvertFrom-StringData -StringData $localizationCommand.CommandElements[1].Value
    $Script:startupCode = ($Script:ast.EndBlock.Statements | Where-Object {
            $_.Extent.StartOffset -gt $localizationAssignment.Extent.EndOffset
        } | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
    $Script:functionCode = ($functionDefinitions | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine

    $Script:parameterBinding = [ScriptBlock]::Create($Script:ast.ParamBlock.Extent.Text + @'

[PSCustomObject]@{
    BoundParameters = $PSBoundParameters
    ConnectionUri = $ConnectionUri
    Credential = $Credential
    AzureADAuthorizationEndpointUri = $AzureADAuthorizationEndpointUri
}
'@)

    $Script:csvSpecialChars = @("`r", "`n")
    $Script:csvEscapeChar = [char]'"'
    $Script:csvFieldDelimiter = [char]','
    $Script:proxyAddressSeparators = [char[]]@(':', '@')
    $Script:authoritativeDomains = @('contoso.com')
    $Script:mailEnabledSystemFolders = [System.Collections.Generic.HashSet[guid]]::new()
    $Script:NewSyncMailPublicFolderCommand = 'New-RemoteSyncMailPublicFolder'
    $Script:SetMailPublicFolderCommand = 'Set-RemoteMailPublicFolder'
    $Script:RemoveSyncMailPublicFolderCommand = 'Remove-RemoteSyncMailPublicFolder'
    $Script:verbose = $false

    function Connect-ExchangeOnline {
        [CmdletBinding()]
        param(
            [string]$ConnectionUri,
            [string]$Prefix,
            [PSCredential]$Credential,
            [string]$AzureADAuthorizationEndpointUri
        )
        throw "An Exchange Online connection must be mocked."
    }

    function Invoke-TestConnectionError {
        [CmdletBinding()]
        param()
        Write-Error -Message "The example authentication request failed."
    }

    function New-RemoteSyncMailPublicFolder {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            $Alias, $DisplayName, $EmailAddresses, $ExternalEmailAddress,
            $HiddenFromAddressListsEnabled, $Name, $OnPremisesObjectId, $WindowsEmailAddress
        )
        throw "An Exchange create operation must be mocked."
    }

    function Set-RemoteMailPublicFolder {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            $Identity, $Alias, $DisplayName, $EmailAddresses, $ExternalEmailAddress,
            $HiddenFromAddressListsEnabled, $Name, $OnPremisesObjectId, $WindowsEmailAddress,
            $IgnoreMissingFolderLink
        )
        throw "An Exchange update operation must be mocked."
    }

    function Remove-RemoteSyncMailPublicFolder {
        [CmdletBinding(SupportsShouldProcess)]
        param($Identity)
        throw "An Exchange remove operation must be mocked."
    }

    function New-TestLocalFolder {
        param($EmailAddresses = @('SMTP:Folder@contoso.com'))
        [PSCustomObject]@{
            Guid                          = [guid]'11111111-1111-1111-1111-111111111111'
            PrimarySmtpAddress            = 'Folder@contoso.com'
            LegacyExchangeDN              = '/o=Contoso/ou=Exchange/cn=Recipients/cn=LocalFolder'
            Alias                         = 'Folder'
            DisplayName                   = 'Example folder'
            HiddenFromAddressListsEnabled = $false
            Name                          = 'Example folder'
            WindowsEmailAddress           = 'Folder@contoso.com'
            EmailAddresses                = $EmailAddresses
        }
    }

    function New-TestRemoteFolder {
        param($EmailAddresses = @('SMTP:Folder@contoso.com'))
        [PSCustomObject]@{
            Guid              = [guid]'22222222-2222-2222-2222-222222222222'
            DistinguishedName = 'CN=ExampleFolder,DC=contoso,DC=com'
            EmailAddresses    = $EmailAddresses
            LegacyExchangeDN  = '/o=Contoso/ou=Exchange/cn=Recipients/cn=RemoteFolder'
        }
    }

    function Invoke-TestFolderOperation {
        param(
            [ValidateSet('Create', 'Update', 'Remove')]
            [string]$Operation,
            $LocalFolder,
            $RemoteFolder
        )
        switch ($Operation) {
            'Create' { NewMailEnabledPublicFolder -localFolder $LocalFolder }
            'Update' { UpdateMailEnabledPublicFolder -localFolder $LocalFolder -remoteFolder $RemoteFolder }
            'Remove' { RemoveMailEnabledPublicFolder -remoteFolder $RemoteFolder }
        }
    }
}

Describe "Exchange Online connection parameters" {
    BeforeEach {
        $Script:ConnectionUri = 'https://outlook.contoso.com/powershell'
        $Script:Credential = $null
        $Script:AzureADAuthorizationEndpointUri = $null
        $Script:isConnectedToExchangeOnline = $false
        Mock -CommandName Import-Module -MockWith {}
        Mock -CommandName Get-Module -MockWith { [PSCustomObject]@{ Name = 'ExchangeOnlineManagement' } }
        Mock -CommandName Connect-ExchangeOnline -MockWith {}
        Mock -CommandName WriteInfoMessage -MockWith {}
        Mock -CommandName WriteWarningMessage -MockWith {}
    }

    It "binds the optional authorization endpoint without running the main script" {
        $endpoint = 'https://login.contoso.com/organizations'
        $result = & $Script:parameterBinding -CsvSummaryFile 'example.csv' -AzureADAuthorizationEndpointUri $endpoint

        $result.AzureADAuthorizationEndpointUri | Should -BeExactly $endpoint
        $result.BoundParameters.ContainsKey('AzureADAuthorizationEndpointUri') | Should -BeTrue
        $parameter = $Script:ast.ParamBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq 'AzureADAuthorizationEndpointUri'
        }
        $parameter.StaticType | Should -Be ([string])
    }

    It "omits the new endpoint and credentials by default while preserving the existing connection default" {
        $result = & $Script:parameterBinding -CsvSummaryFile 'example.csv'
        $connectionParameter = $Script:ast.ParamBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq 'ConnectionUri'
        }

        $result.AzureADAuthorizationEndpointUri | Should -BeNullOrEmpty
        $result.Credential | Should -BeNullOrEmpty
        $result.BoundParameters.ContainsKey('AzureADAuthorizationEndpointUri') | Should -BeFalse
        $result.BoundParameters.ContainsKey('Credential') | Should -BeFalse
        $result.ConnectionUri | Should -BeExactly $connectionParameter.DefaultValue.Value
    }

    It "preserves credential and connection URI binding" {
        $credential = [PSCredential]::new('admin@contoso.com', [SecureString]::new())
        $result = & $Script:parameterBinding -CsvSummaryFile 'example.csv' -Credential $credential -ConnectionUri $Script:ConnectionUri

        $result.Credential | Should -Be $credential
        $result.ConnectionUri | Should -BeExactly $Script:ConnectionUri
    }

    It "imports with Stop and connects with the Remote prefix without optional parameters" {
        InitializeExchangeOnlineRemoteSession

        Should -Invoke -CommandName Import-Module -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'ExchangeOnlineManagement' -and $ErrorAction -eq 'Stop'
        }
        Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
            $ConnectionUri -eq $Script:ConnectionUri -and $Prefix -ceq 'Remote' -and
            $ErrorAction -eq 'Stop' -and
            -not $PesterBoundParameters.ContainsKey('Credential') -and
            -not $PesterBoundParameters.ContainsKey('AzureADAuthorizationEndpointUri')
        }
        $Script:isConnectedToExchangeOnline | Should -BeTrue
        Should -Invoke -CommandName WriteInfoMessage -Times 1 -Exactly -ParameterFilter {
            $message -eq $Script:LocalizedStrings.RemoteSessionCreatedSuccessfully
        }
    }

    It "forwards credentials and the explicit authorization endpoint with the Remote prefix" {
        $Script:Credential = [PSCredential]::new('admin@contoso.com', [SecureString]::new())
        $Script:AzureADAuthorizationEndpointUri = 'https://login.contoso.com/organizations'

        InitializeExchangeOnlineRemoteSession

        Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
            $Credential -eq $Script:Credential -and
            $AzureADAuthorizationEndpointUri -ceq $Script:AzureADAuthorizationEndpointUri -and
            $ConnectionUri -ceq $Script:ConnectionUri -and $Prefix -ceq 'Remote' -and $ErrorAction -eq 'Stop'
        }
    }

    It "does not forward an empty authorization endpoint" {
        $Script:AzureADAuthorizationEndpointUri = ''

        InitializeExchangeOnlineRemoteSession

        Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
            -not $PesterBoundParameters.ContainsKey('AzureADAuthorizationEndpointUri')
        }
    }

    It "clears previous connection state before invoking Connect and sets it only after success" {
        $Script:isConnectedToExchangeOnline = $true
        Mock -CommandName Connect-ExchangeOnline -MockWith {
            $Script:isConnectedToExchangeOnline | Should -BeFalse
        }

        InitializeExchangeOnlineRemoteSession

        $Script:isConnectedToExchangeOnline | Should -BeTrue
    }

    It "makes a nonterminating Connect error terminating and never reports success" {
        $Script:isConnectedToExchangeOnline = $true
        Mock -CommandName Connect-ExchangeOnline -MockWith {
            param($ErrorAction)
            Invoke-TestConnectionError -ErrorAction $ErrorAction
        }

        { InitializeExchangeOnlineRemoteSession } | Should -Throw -ExpectedMessage '*example authentication request failed*'

        $Script:isConnectedToExchangeOnline | Should -BeFalse
        Should -Invoke -CommandName Connect-ExchangeOnline -Times 1 -Exactly
        Should -Invoke -CommandName WriteInfoMessage -Times 0 -Exactly -ParameterFilter {
            $message -eq $Script:LocalizedStrings.RemoteSessionCreatedSuccessfully
        }
    }

    It "does not attempt Connect or report success when module import fails" {
        $Script:isConnectedToExchangeOnline = $true
        Mock -CommandName Import-Module -MockWith { throw 'Example module import failed.' }

        { InitializeExchangeOnlineRemoteSession } | Should -Throw -ExpectedMessage '*module import failed*'

        $Script:isConnectedToExchangeOnline | Should -BeFalse
        Should -Invoke -CommandName Connect-ExchangeOnline -Times 0 -Exactly
        Should -Invoke -CommandName WriteInfoMessage -Times 0 -Exactly -ParameterFilter {
            $message -eq $Script:LocalizedStrings.RemoteSessionCreatedSuccessfully
        }
    }
}

Describe "Email address normalization" {
    It "returns a non-enumerated empty string array for <Name>" -TestCases @(
        @{ Name = 'null'; Addresses = $null }
        @{ Name = 'an empty array'; Addresses = @() }
        @{ Name = 'an empty ArrayList'; Addresses = [System.Collections.ArrayList]::new() }
    ) {
        param($Name, $Addresses)
        $result = ConvertTo-EmailAddressStrings -EmailAddresses $Addresses

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 0
    }

    It "preserves a scalar string as a one-element string array" {
        $result = ConvertTo-EmailAddressStrings -EmailAddresses 'SMTP:Folder@Contoso.com'

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 1
        $result[0] | Should -BeExactly 'SMTP:Folder@Contoso.com'
    }

    It "preserves primary SMTP, secondary smtp and X500 address casing" {
        $addresses = [string[]]@('SMTP:Folder@Contoso.com', 'smtp:Alias@contoso.com', 'X500:/o=Contoso/cn=Example')

        $result = ConvertTo-EmailAddressStrings -EmailAddresses $addresses

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 3
        $result[0] | Should -BeExactly $addresses[0]
        $result[1] | Should -BeExactly $addresses[1]
        $result[2] | Should -BeExactly $addresses[2]
    }

    It "reads the documented ProxyAddressString property from a scalar proxy without collection methods" {
        $proxy = [PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@Contoso.com' }

        $result = ConvertTo-EmailAddressStrings -EmailAddresses $proxy

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 1
        $result[0] | Should -BeExactly $proxy.ProxyAddressString
    }

    It "reads deserialized proxy objects" {
        $proxy = [PSCustomObject]@{
            PSTypeName         = 'Deserialized.Microsoft.Exchange.Data.SmtpProxyAddress'
            ProxyAddressString = 'smtp:Alias@contoso.com'
        }

        $result = ConvertTo-EmailAddressStrings -EmailAddresses @($proxy)

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 1
        $result[0] | Should -BeExactly 'smtp:Alias@contoso.com'
    }

    It "enumerates mixed proxy objects and strings in an ArrayList without collection methods" {
        $addresses = [System.Collections.ArrayList]::new()
        [void]$addresses.Add([PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@Contoso.com' })
        [void]$addresses.Add('smtp:Alias@contoso.com')
        [void]$addresses.Add([PSCustomObject]@{ ProxyAddressString = 'X500:/o=Contoso/cn=Example' })

        $result = ConvertTo-EmailAddressStrings -EmailAddresses $addresses

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 3
        $result[0] | Should -BeExactly 'SMTP:Folder@Contoso.com'
        $result[1] | Should -BeExactly 'smtp:Alias@contoso.com'
        $result[2] | Should -BeExactly 'X500:/o=Contoso/cn=Example'
    }

    It "never calls an optional ToStringArray method" {
        $addresses = [System.Collections.ArrayList]::new()
        [void]$addresses.Add([PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@contoso.com' })
        Add-Member -InputObject $addresses -MemberType ScriptMethod -Name ToStringArray -Value {
            throw "ToStringArray must not be called."
        }

        $result = ConvertTo-EmailAddressStrings -EmailAddresses $addresses

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 1
        $result[0] | Should -BeExactly 'SMTP:Folder@contoso.com'
    }

    It "does not split flattened strings or change casing" {
        $flattened = 'SMTP:Folder@contoso.com smtp:Alias@contoso.com'

        $result = ConvertTo-EmailAddressStrings -EmailAddresses $flattened

        $result.Count | Should -Be 1
        $result[0] | Should -BeExactly $flattened
    }

    It "rejects <Name> explicitly" -TestCases @(
        @{ Name = 'a null collection member'; Addresses = @('SMTP:Folder@contoso.com', $null) }
        @{ Name = 'an empty string'; Addresses = '' }
        @{ Name = 'a whitespace string'; Addresses = " `t " }
        @{ Name = 'a blank collection member'; Addresses = @('SMTP:Folder@contoso.com', '') }
        @{ Name = 'an unsupported object'; Addresses = [PSCustomObject]@{ Address = 'Folder@contoso.com' } }
        @{ Name = 'an unsupported numeric member'; Addresses = @('SMTP:Folder@contoso.com', 42) }
        @{ Name = 'a null proxy property'; Addresses = [PSCustomObject]@{ ProxyAddressString = $null } }
        @{ Name = 'a blank proxy property'; Addresses = [PSCustomObject]@{ ProxyAddressString = ' ' } }
        @{ Name = 'a non-string proxy property'; Addresses = [PSCustomObject]@{ ProxyAddressString = 42 } }
    ) {
        param($Name, $Addresses)
        { ConvertTo-EmailAddressStrings -EmailAddresses $Addresses } | Should -Throw
    }
}

Describe "Email address consolidation" {
    It "returns a string array for <Name>" -TestCases @(
        @{ Name = 'zero addresses'; Addresses = @(); Count = 0 }
        @{ Name = 'one address'; Addresses = 'SMTP:Folder@contoso.com'; Count = 1 }
        @{ Name = 'multiple addresses'; Addresses = @('SMTP:Folder@contoso.com', 'smtp:Alias@contoso.com'); Count = 2 }
    ) {
        param($Name, $Addresses, $Count)
        $result = ConsolidateEmailAddresses -localEmailAddresses $Addresses -remoteEmailAddresses @() -remoteLegDN ''

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be $Count
    }

    It "normalizes both collections, keeps cloud SMTP and matching remote X500, and removes stale local-authoritative addresses" {
        $remoteLegacy = '/o=Contoso/cn=RemoteFolder'
        $localAddresses = [System.Collections.ArrayList]::new()
        [void]$localAddresses.Add([PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@Contoso.com' })
        [void]$localAddresses.Add('smtp:Alias@contoso.com')
        [void]$localAddresses.Add([PSCustomObject]@{ ProxyAddressString = 'X500:/o=Contoso/cn=LocalFolder' })
        $remoteAddresses = [System.Collections.ArrayList]::new()
        foreach ($address in @(
                'smtp:Folder@CONTOSO.COM',
                'SMTP:Stale@contoso.com',
                'smtp:Cloud@fabrikam.com',
                "X500:$remoteLegacy",
                'x500:/o=Contoso/cn=Unrelated',
                'SMTP:Invalid'
            )) {
            [void]$remoteAddresses.Add([PSCustomObject]@{ ProxyAddressString = $address })
        }

        $result = ConsolidateEmailAddresses -localEmailAddresses $localAddresses -remoteEmailAddresses $remoteAddresses -remoteLegDN $remoteLegacy

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 5
        $result[0] | Should -BeExactly 'SMTP:Folder@Contoso.com'
        $result[1] | Should -BeExactly 'smtp:Alias@contoso.com'
        $result[2] | Should -BeExactly 'X500:/o=Contoso/cn=LocalFolder'
        $result[3] | Should -BeExactly 'smtp:Cloud@fabrikam.com'
        $result[4] | Should -BeExactly "X500:$remoteLegacy"
    }

    It "matches domains and SMTP prefixes without case sensitivity but preserves alias case semantics" {
        $localAddresses = @('SMTP:Alias@Fabrikam.com')
        $remoteAddresses = @('smtp:Alias@FABRIKAM.COM', 'smtp:alias@fabrikam.com')

        $result = ConsolidateEmailAddresses -localEmailAddresses $localAddresses -remoteEmailAddresses $remoteAddresses -remoteLegDN ''

        $result.Count | Should -Be 2
        $result[0] | Should -BeExactly 'SMTP:Alias@Fabrikam.com'
        $result[1] | Should -BeExactly 'smtp:alias@fabrikam.com'
    }

    It "normalizes scalar proxies on both sides without concatenating addresses" {
        $localProxy = [PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@contoso.com' }
        $remoteProxy = [PSCustomObject]@{ ProxyAddressString = 'smtp:Cloud@fabrikam.com' }

        $result = ConsolidateEmailAddresses -localEmailAddresses $localProxy -remoteEmailAddresses $remoteProxy -remoteLegDN ''

        ($result -is [string[]]) | Should -BeTrue
        $result.Count | Should -Be 2
        $result[0] | Should -BeExactly 'SMTP:Folder@contoso.com'
        $result[1] | Should -BeExactly 'smtp:Cloud@fabrikam.com'
    }

    It "rejects invalid remote members instead of silently dropping malformed objects" {
        { ConsolidateEmailAddresses -localEmailAddresses @() -remoteEmailAddresses @($null) -remoteLegDN '' } | Should -Throw
    }
}

Describe "Public folder Exchange operations" {
    BeforeEach {
        $Script:ObjectsCreated = 0
        $Script:ObjectsUpdated = 0
        $Script:ObjectsDeleted = 0
        $Script:errorsEncountered = 0
        $Script:WhatIf = $false
        $Script:localFolder = New-TestLocalFolder
        $Script:remoteFolder = New-TestRemoteFolder
        Mock -CommandName New-RemoteSyncMailPublicFolder -MockWith {}
        Mock -CommandName Set-RemoteMailPublicFolder -MockWith {}
        Mock -CommandName Remove-RemoteSyncMailPublicFolder -MockWith {}
        Mock -CommandName WriteOperationSummary -MockWith {}
        Mock -CommandName Write-Error -MockWith {}
    }

    It "creates from <Name> and appends the legacy X500 address as its own element" -TestCases @(
        @{ Name = 'zero addresses'; Addresses = @(); Expected = @() }
        @{ Name = 'a scalar string'; Addresses = 'SMTP:Folder@contoso.com'; Expected = @('SMTP:Folder@contoso.com') }
        @{ Name = 'one proxy'; Addresses = [PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@contoso.com' }; Expected = @('SMTP:Folder@contoso.com') }
        @{ Name = 'multiple strings'; Addresses = @('SMTP:Folder@contoso.com', 'smtp:Alias@contoso.com'); Expected = @('SMTP:Folder@contoso.com', 'smtp:Alias@contoso.com') }
    ) {
        param($Name, $Addresses, $Expected)
        $Script:localFolder.EmailAddresses = $Addresses
        $Script:expectedAddresses = [string[]]@($Expected) + "x500:$($Script:localFolder.LegacyExchangeDN)"

        NewMailEnabledPublicFolder -localFolder $Script:localFolder

        Should -Invoke -CommandName New-RemoteSyncMailPublicFolder -Times 1 -Exactly -ParameterFilter {
            $EmailAddresses -is [array] -and
            ($EmailAddresses -join '|') -ceq ($Script:expectedAddresses -join '|') -and
            $ExternalEmailAddress -ceq 'Folder@contoso.com' -and
            $OnPremisesObjectId -eq $Script:localFolder.Guid -and $ErrorAction -eq 'Stop'
        }
        $Script:ObjectsCreated | Should -Be 1
    }

    It "creates from an ArrayList of proxies and strings without collection methods" {
        $addresses = [System.Collections.ArrayList]::new()
        [void]$addresses.Add([PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@contoso.com' })
        [void]$addresses.Add('smtp:Alias@contoso.com')
        $Script:localFolder.EmailAddresses = $addresses

        NewMailEnabledPublicFolder -localFolder $Script:localFolder

        Should -Invoke -CommandName New-RemoteSyncMailPublicFolder -Times 1 -Exactly -ParameterFilter {
            $EmailAddresses -is [array] -and $EmailAddresses.Count -eq 3 -and
            $EmailAddresses[0] -ceq 'SMTP:Folder@contoso.com' -and
            $EmailAddresses[1] -ceq 'smtp:Alias@contoso.com' -and
            $EmailAddresses[2] -ceq "x500:$($Script:localFolder.LegacyExchangeDN)"
        }
    }

    It "updates from <Name> and appends the legacy X500 address separately" -TestCases @(
        @{ Name = 'zero addresses'; Addresses = @(); Expected = @() }
        @{ Name = 'one scalar proxy'; Addresses = [PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@contoso.com' }; Expected = @('SMTP:Folder@contoso.com') }
        @{ Name = 'multiple addresses'; Addresses = @('SMTP:Folder@contoso.com', 'smtp:Alias@contoso.com'); Expected = @('SMTP:Folder@contoso.com', 'smtp:Alias@contoso.com') }
    ) {
        param($Name, $Addresses, $Expected)
        $Script:localFolder.EmailAddresses = $Addresses
        $Script:remoteFolder.EmailAddresses = @()
        $Script:expectedAddresses = [string[]]@($Expected) + "x500:$($Script:localFolder.LegacyExchangeDN)"

        UpdateMailEnabledPublicFolder -localFolder $Script:localFolder -remoteFolder $Script:remoteFolder

        Should -Invoke -CommandName Set-RemoteMailPublicFolder -Times 1 -Exactly -ParameterFilter {
            $EmailAddresses -is [string[]] -and
            ($EmailAddresses -join '|') -ceq ($Script:expectedAddresses -join '|') -and
            $Identity -ceq $Script:remoteFolder.DistinguishedName -and $ErrorAction -eq 'Stop'
        }
        $Script:ObjectsUpdated | Should -Be 1
    }

    It "updates proxy collections without collection methods or losing cloud and legacy X500 addresses" {
        $localAddresses = [System.Collections.ArrayList]::new()
        [void]$localAddresses.Add([PSCustomObject]@{ ProxyAddressString = 'SMTP:Folder@contoso.com' })
        $remoteAddresses = [System.Collections.ArrayList]::new()
        [void]$remoteAddresses.Add([PSCustomObject]@{ ProxyAddressString = 'smtp:Cloud@fabrikam.com' })
        [void]$remoteAddresses.Add([PSCustomObject]@{ ProxyAddressString = "X500:$($Script:remoteFolder.LegacyExchangeDN)" })
        [void]$remoteAddresses.Add('smtp:Stale@contoso.com')
        $Script:localFolder.EmailAddresses = $localAddresses
        $Script:remoteFolder.EmailAddresses = $remoteAddresses

        UpdateMailEnabledPublicFolder -localFolder $Script:localFolder -remoteFolder $Script:remoteFolder

        Should -Invoke -CommandName Set-RemoteMailPublicFolder -Times 1 -Exactly -ParameterFilter {
            $EmailAddresses -is [string[]] -and $EmailAddresses.Count -eq 4 -and
            $EmailAddresses[0] -ceq 'SMTP:Folder@contoso.com' -and
            $EmailAddresses[1] -ceq "x500:$($Script:localFolder.LegacyExchangeDN)" -and
            $EmailAddresses[2] -ceq 'smtp:Cloud@fabrikam.com' -and
            $EmailAddresses[3] -ceq "X500:$($Script:remoteFolder.LegacyExchangeDN)"
        }
    }

    It "keeps a successful <Operation> counted when summary logging fails without retrying or reclassifying Exchange" -TestCases @(
        @{ Operation = 'Create'; Command = 'New-RemoteSyncMailPublicFolder'; Counter = 'ObjectsCreated' }
        @{ Operation = 'Update'; Command = 'Set-RemoteMailPublicFolder'; Counter = 'ObjectsUpdated' }
        @{ Operation = 'Remove'; Command = 'Remove-RemoteSyncMailPublicFolder'; Counter = 'ObjectsDeleted' }
    ) {
        param($Operation, $Command, $Counter)
        Mock -CommandName WriteOperationSummary -MockWith { throw 'Example summary write failed.' }
        Mock -CommandName WriteErrorSummary -MockWith {}

        {
            Invoke-TestFolderOperation -Operation $Operation -LocalFolder $Script:localFolder -RemoteFolder $Script:remoteFolder
        } | Should -Throw -ExpectedMessage '*summary write failed*'

        Get-Variable -Name $Counter -Scope Script -ValueOnly | Should -Be 1
        $Script:errorsEncountered | Should -Be 0
        Should -Invoke -CommandName $Command -Times 1 -Exactly
        Should -Invoke -CommandName WriteOperationSummary -Times 1 -Exactly
        Should -Invoke -CommandName WriteErrorSummary -Times 0 -Exactly
        Should -Invoke -CommandName Write-Error -Times 0 -Exactly
    }

    It "records a genuine <Operation> failure once without a success count or success row" -TestCases @(
        @{ Operation = 'Create'; Command = 'New-RemoteSyncMailPublicFolder'; Counter = 'ObjectsCreated' }
        @{ Operation = 'Update'; Command = 'Set-RemoteMailPublicFolder'; Counter = 'ObjectsUpdated' }
        @{ Operation = 'Remove'; Command = 'Remove-RemoteSyncMailPublicFolder'; Counter = 'ObjectsDeleted' }
    ) {
        param($Operation, $Command, $Counter)
        Mock -CommandName $Command -MockWith { throw 'Example Exchange operation failed.' }

        Invoke-TestFolderOperation -Operation $Operation -LocalFolder $Script:localFolder -RemoteFolder $Script:remoteFolder

        Get-Variable -Name $Counter -Scope Script -ValueOnly | Should -Be 0
        $Script:errorsEncountered | Should -Be 1
        Should -Invoke -CommandName $Command -Times 1 -Exactly
        Should -Invoke -CommandName WriteOperationSummary -Times 1 -Exactly -ParameterFilter {
            $result -like '*Example Exchange operation failed*' -and $null -ne $folder.Guid
        }
        Should -Invoke -CommandName WriteOperationSummary -Times 0 -Exactly -ParameterFilter {
            $result -eq $Script:LocalizedStrings.CsvSuccessResult
        }
        Should -Invoke -CommandName Write-Error -Times 1 -Exactly
    }

    It "forwards WhatIf for <Operation> without incrementing success counters" -TestCases @(
        @{ Operation = 'Create'; Command = 'New-RemoteSyncMailPublicFolder' }
        @{ Operation = 'Update'; Command = 'Set-RemoteMailPublicFolder' }
        @{ Operation = 'Remove'; Command = 'Remove-RemoteSyncMailPublicFolder' }
    ) {
        param($Operation, $Command)
        $Script:WhatIf = $true

        Invoke-TestFolderOperation -Operation $Operation -LocalFolder $Script:localFolder -RemoteFolder $Script:remoteFolder

        Should -Invoke -CommandName $Command -Times 1 -Exactly -ParameterFilter { $WhatIf }
        $Script:ObjectsCreated | Should -Be 0
        $Script:ObjectsUpdated | Should -Be 0
        $Script:ObjectsDeleted | Should -Be 0
        $Script:errorsEncountered | Should -Be 0
    }
}

Describe "CSV operation summaries" {
    BeforeEach {
        $Script:summaryFilePath = $null
        $Script:summaryFilePaths = [System.Collections.Generic.List[string]]::new()
        $Script:summaryCsvHeader = $null
        $Script:errorsEncountered = 0
        $Script:summaryDirectory = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        [void][System.IO.Directory]::CreateDirectory($Script:summaryDirectory)
        $Script:summaryPath = Join-Path -Path $Script:summaryDirectory -ChildPath 'example.csv'
        Mock -CommandName WriteWarningMessage -MockWith {}
        Mock -CommandName Start-Sleep -MockWith {}
    }

    It "initializes an absolute path and a UTF-8 BOM CSV without changing the header" {
        InitializeOperationSummary -Path $Script:summaryPath

        $Script:summaryFilePath | Should -BeExactly ([System.IO.Path]::GetFullPath($Script:summaryPath))
        ($Script:summaryFilePaths -is [System.Collections.Generic.List[string]]) | Should -BeTrue
        $Script:summaryFilePaths.Count | Should -Be 1
        $Script:summaryFilePaths[0] | Should -BeExactly $Script:summaryFilePath
        $Script:summaryCsvHeader | Should -BeExactly '#Timestamp,Identity,Operation,Result,Command text'
        $bytes = [System.IO.File]::ReadAllBytes($Script:summaryPath)
        ($bytes[0..2] -join ',') | Should -Be '239,187,191'
        [System.IO.File]::ReadAllText($Script:summaryPath).TrimEnd("`r", "`n") |
            Should -BeExactly $Script:summaryCsvHeader
        Should -Invoke -CommandName WriteWarningMessage -Times 0 -Exactly
    }

    It "resolves relative summary paths against the PowerShell location" {
        Push-Location -Path $Script:summaryDirectory
        try {
            InitializeOperationSummary -Path 'relative.csv'

            $Script:summaryFilePath | Should -BeExactly (Join-Path -Path $Script:summaryDirectory -ChildPath 'relative.csv')
            Test-Path -LiteralPath $Script:summaryFilePath | Should -BeTrue
        } finally {
            Pop-Location
        }
    }

    It "never overwrites an existing requested summary and warns about the GUID sibling immediately" {
        [System.IO.File]::WriteAllText($Script:summaryPath, 'Existing example rows')

        InitializeOperationSummary -Path $Script:summaryPath

        [System.IO.File]::ReadAllText($Script:summaryPath) | Should -BeExactly 'Existing example rows'
        $Script:summaryFilePath | Should -Not -Be $Script:summaryPath
        [System.IO.Path]::GetDirectoryName($Script:summaryFilePath) | Should -BeExactly $Script:summaryDirectory
        [System.IO.Path]::GetFileName($Script:summaryFilePath) | Should -Match '^example\.[0-9a-fA-F-]{32,36}\.csv$'
        [System.IO.File]::ReadAllText($Script:summaryFilePath).TrimEnd("`r", "`n") |
            Should -BeExactly $Script:summaryCsvHeader
        $Script:summaryFilePaths.Count | Should -Be 1
        $Script:summaryFilePaths[0] | Should -BeExactly $Script:summaryFilePath
        Should -Invoke -CommandName Start-Sleep -Times 0 -Exactly
        Should -Invoke -CommandName WriteWarningMessage -Times 1 -Exactly -ParameterFilter {
            $message.Contains($Script:summaryFilePath)
        }
    }

    It "fails explicitly if the exclusive initialization fallback name already exists" {
        $Script:fixedGuid = [guid]'33333333-3333-3333-3333-333333333333'
        $siblingPath = Join-Path -Path $Script:summaryDirectory -ChildPath "example.$($Script:fixedGuid.ToString('N')).csv"
        [System.IO.File]::WriteAllText($Script:summaryPath, 'Original example rows')
        [System.IO.File]::WriteAllText($siblingPath, 'Other example rows')
        Mock -CommandName New-Guid -MockWith { $Script:fixedGuid }

        { InitializeOperationSummary -Path $Script:summaryPath } | Should -Throw

        [System.IO.File]::ReadAllText($Script:summaryPath) | Should -BeExactly 'Original example rows'
        [System.IO.File]::ReadAllText($siblingPath) | Should -BeExactly 'Other example rows'
        $Script:summaryFilePaths.Count | Should -Be 0
        Should -Invoke -CommandName Start-Sleep -Times 0 -Exactly
        Should -Invoke -CommandName WriteWarningMessage -Times 0 -Exactly
    }

    It "retries a locked summary at most three times then writes its pending row once and continues in the sibling" {
        InitializeOperationSummary -Path $Script:summaryPath
        Write-SummaryCsv -Line 'first,example,Create,Success,example command'
        $originalContents = [System.IO.File]::ReadAllText($Script:summaryPath)
        $lock = [System.IO.File]::Open($Script:summaryPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            Write-SummaryCsv -Line 'second,example,Update,Success,example command'
        } finally {
            $lock.Dispose()
        }
        $fallbackPath = $Script:summaryFilePath
        Write-SummaryCsv -Line 'third,example,Remove,Success,example command'

        $fallbackPath | Should -Not -Be $Script:summaryPath
        $Script:summaryFilePath | Should -BeExactly $fallbackPath
        [System.IO.File]::ReadAllText($Script:summaryPath) | Should -BeExactly $originalContents
        $lines = [System.IO.File]::ReadAllLines($fallbackPath)
        $lines.Count | Should -Be 3
        $lines[0] | Should -BeExactly $Script:summaryCsvHeader
        $lines[1] | Should -BeExactly 'second,example,Update,Success,example command'
        $lines[2] | Should -BeExactly 'third,example,Remove,Success,example command'
        $Script:summaryFilePaths.Count | Should -Be 2
        $Script:summaryFilePaths[0] | Should -BeExactly $Script:summaryPath
        $Script:summaryFilePaths[1] | Should -BeExactly $fallbackPath
        Should -Invoke -CommandName Start-Sleep -Times 2 -Exactly -ParameterFilter { $Milliseconds -eq 200 }
        Should -Invoke -CommandName Start-Sleep -Times 2 -Exactly
        Should -Invoke -CommandName WriteWarningMessage -Times 1 -Exactly -ParameterFilter {
            $message.Contains($Script:summaryFilePath)
        }
    }

    It "keeps the active path and existing sibling unchanged when fallback creation fails" {
        InitializeOperationSummary -Path $Script:summaryPath
        Write-SummaryCsv -Line 'first,example,Create,Success,example command'
        $originalContents = [System.IO.File]::ReadAllText($Script:summaryPath)
        $Script:fixedGuid = [guid]'33333333-3333-3333-3333-333333333333'
        $siblingPath = Join-Path -Path $Script:summaryDirectory -ChildPath "example.$($Script:fixedGuid.ToString('N')).csv"
        [System.IO.File]::WriteAllText($siblingPath, 'Other example rows')
        Mock -CommandName New-Guid -MockWith { $Script:fixedGuid }
        $lock = [System.IO.File]::Open($Script:summaryPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            { Write-SummaryCsv -Line 'second,example,Update,Success,example command' } | Should -Throw
        } finally {
            $lock.Dispose()
        }

        $Script:summaryFilePath | Should -BeExactly $Script:summaryPath
        $Script:summaryFilePaths.Count | Should -Be 1
        [System.IO.File]::ReadAllText($siblingPath) | Should -BeExactly 'Other example rows'
        [System.IO.File]::ReadAllText($Script:summaryPath) | Should -BeExactly $originalContents
        Should -Invoke -CommandName Start-Sleep -Times 2 -Exactly -ParameterFilter { $Milliseconds -eq 200 }
        Should -Invoke -CommandName WriteWarningMessage -Times 0 -Exactly

        Write-SummaryCsv -Line 'third,example,Update,Success,example command'
        [System.IO.File]::ReadAllLines($Script:summaryPath).Count | Should -Be 3
    }

    It "reuses the original file when a transient lock clears between open attempts" {
        InitializeOperationSummary -Path $Script:summaryPath
        $Script:lockedStream = [System.IO.File]::Open($Script:summaryPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        Mock -CommandName Start-Sleep -MockWith { $Script:lockedStream.Dispose() }
        try {
            Write-SummaryCsv -Line 'first,example,Create,Success,example command'
        } finally {
            $Script:lockedStream.Dispose()
        }

        $Script:summaryFilePath | Should -BeExactly $Script:summaryPath
        $Script:summaryFilePaths.Count | Should -Be 1
        $lines = [System.IO.File]::ReadAllLines($Script:summaryPath)
        $lines.Count | Should -Be 2
        $lines[1] | Should -BeExactly 'first,example,Create,Success,example command'
        Should -Invoke -CommandName Start-Sleep -Times 1 -Exactly -ParameterFilter { $Milliseconds -eq 200 }
        Should -Invoke -CommandName WriteWarningMessage -Times 0 -Exactly
    }

    It "keeps stream writes outside retry loops so partial rows cannot be written again" {
        $writerDefinition = $Script:ast.Find({
                $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $args[0].Name -eq 'Write-SummaryCsv'
            }, $false)
        $writeCalls = $writerDefinition.Body.FindAll({
                $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                $args[0].Member.Value -eq 'WriteLine'
            }, $false)

        $writeCalls.Count | Should -BeGreaterThan 0
        foreach ($writeCall in $writeCalls) {
            $ancestor = $writeCall.Parent
            while ($null -ne $ancestor -and $ancestor -ne $writerDefinition) {
                ($ancestor -is [System.Management.Automation.Language.LoopStatementAst]) | Should -BeFalse
                $ancestor = $ancestor.Parent
            }
        }
    }

    It "does not retry unrelated open failures or choose a fallback for a missing directory" {
        $missingPath = Join-Path -Path $Script:summaryDirectory -ChildPath 'missing\example.csv'
        Mock -CommandName New-Guid -MockWith { throw 'A fallback must not be attempted.' }

        { InitializeOperationSummary -Path $missingPath } | Should -Throw

        Should -Invoke -CommandName Start-Sleep -Times 0 -Exactly
        Should -Invoke -CommandName New-Guid -Times 0 -Exactly
        Should -Invoke -CommandName WriteWarningMessage -Times 0 -Exactly
        $Script:summaryFilePaths.Count | Should -Be 0
    }

    It "stops before validation or Exchange work if initialization is denied under default Continue" {
        $fixedGuid = [guid]'33333333-3333-3333-3333-333333333333'
        $fallbackPath = Join-Path -Path $Script:summaryDirectory -ChildPath "example.$($fixedGuid.ToString('N')).csv"
        [void][System.IO.Directory]::CreateDirectory($Script:summaryPath)
        [void][System.IO.Directory]::CreateDirectory($fallbackPath)

        # An isolated runspace avoids the enclosing catch used by Should -Throw and Pester itself.
        $invocation = [powershell]::Create()
        try {
            $harness = {
                param($Functions, $Startup, $Strings, $SummaryPath, $FixedGuid)
                $ErrorActionPreference = 'Continue'
                $script:LocalizedStrings = $Strings
                $script:CsvSummaryFile = $SummaryPath
                $script:fixedGuid = $FixedGuid
                $script:isConnectedToExchangeOnline = $false
                $script:validationReached = $false
                $script:connectionReached = $false
                . ([ScriptBlock]::Create($Functions))

                function New-Guid { return $script:fixedGuid }
                function ValidateMailEnabledPublicFolders { $script:validationReached = $true }
                function InitializeExchangeOnlineRemoteSession {
                    $script:connectionReached = $true
                    throw 'The example harness must not reach Exchange operations.'
                }
                function checkForInconsistenciesWithMEPF { return $false }

                . ([ScriptBlock]::Create($Startup))
            }
            [void]$invocation.AddScript($harness.ToString())
            [void]$invocation.AddParameters(@{
                    Functions   = $Script:functionCode
                    Startup     = $Script:startupCode
                    Strings     = $Script:LocalizedStrings
                    SummaryPath = $Script:summaryPath
                    FixedGuid   = $fixedGuid
                })
            $invocationFailure = $null
            try {
                $null = $invocation.Invoke()
            } catch [System.Management.Automation.RuntimeException] {
                $invocationFailure = $_
            }
            ($null -ne $invocationFailure -or $invocation.Streams.Error.Count -gt 0) | Should -BeTrue

            $invocation.Commands.Clear()
            $state = $invocation.AddScript(@'
[PSCustomObject]@{
    ValidationReached = $script:validationReached
    ConnectionReached = $script:connectionReached
    SummaryFilesWritten = $script:summaryFilePaths.Count
}
'@).Invoke()[0]
            $state.ValidationReached | Should -BeFalse
            $state.ConnectionReached | Should -BeFalse
            $state.SummaryFilesWritten | Should -Be 0
        } finally {
            $invocation.Dispose()
        }
    }

    It "does not retry permission errors or switch paths" -Skip:($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
        InitializeOperationSummary -Path $Script:summaryPath
        $originalAttributes = [System.IO.File]::GetAttributes($Script:summaryPath)
        [System.IO.File]::SetAttributes($Script:summaryPath, $originalAttributes -bor [System.IO.FileAttributes]::ReadOnly)
        Mock -CommandName New-Guid -MockWith { throw 'A fallback must not be attempted.' }
        try {
            { Write-SummaryCsv -Line 'first,example,Create,Success,example command' } | Should -Throw
        } finally {
            [System.IO.File]::SetAttributes($Script:summaryPath, $originalAttributes)
        }

        $Script:summaryFilePath | Should -BeExactly $Script:summaryPath
        Should -Invoke -CommandName Start-Sleep -Times 0 -Exactly
        Should -Invoke -CommandName New-Guid -Times 0 -Exactly
        Should -Invoke -CommandName WriteWarningMessage -Times 0 -Exactly
    }

    It "adds the header when appending to an empty file and disposes handles for subsequent writes" {
        InitializeOperationSummary -Path $Script:summaryPath
        [System.IO.File]::WriteAllText($Script:summaryPath, '')

        Write-SummaryCsv -Line 'first,example,Create,Success,example command'
        Write-SummaryCsv -Line 'second,example,Update,Success,example command'

        $lines = [System.IO.File]::ReadAllLines($Script:summaryPath)
        $lines.Count | Should -Be 3
        $lines[0] | Should -BeExactly $Script:summaryCsvHeader
        $lines[1] | Should -BeExactly 'first,example,Create,Success,example command'
        $lines[2] | Should -BeExactly 'second,example,Update,Success,example command'
        $bytes = [System.IO.File]::ReadAllBytes($Script:summaryPath)
        ($bytes[0..2] -join ',') | Should -Be '239,187,191'
        $exclusiveStream = [System.IO.File]::Open($Script:summaryPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $exclusiveStream.Dispose()
    }

    It "round trips commas, quotes and newlines in every column including a culture-specific timestamp" {
        InitializeOperationSummary -Path $Script:summaryPath
        Mock -CommandName Get-Date -MockWith { [datetime]::new(2026, 1, 2, 3, 4, 5) }
        $culture = [System.Globalization.CultureInfo]::InvariantCulture.Clone()
        $culture.DateTimeFormat.ShortDatePattern = "yyyy','MM','dd"
        $previousCulture = [System.Globalization.CultureInfo]::CurrentCulture
        try {
            [System.Globalization.CultureInfo]::CurrentCulture = $culture
            $folder = [PSCustomObject]@{ Guid = 'example,"folder"' + "`n" + 'identity' }
            $operation = "Update,`"example`""
            $result = 'Success,"example"' + "`n" + 'result'
            $command = "Set-RemoteMailPublicFolder -Identity `"example,folder`"`n-WhatIf"
            $expectedTimestamp = ([datetime]::new(2026, 1, 2, 3, 4, 5)).ToString()

            WriteOperationSummary -folder $folder -operation $operation -result $result -commandText $command

            # The script's legacy header starts with a comment marker; CSV parsers skip that line.
            $rows = @(ConvertFrom-Csv -InputObject ([System.IO.File]::ReadAllText($Script:summaryPath).Substring(1)))
            $rows.Count | Should -Be 1
            $rows[0].Timestamp | Should -BeExactly $expectedTimestamp
            $rows[0].Identity | Should -BeExactly $folder.Guid
            $rows[0].Operation | Should -BeExactly $operation
            $rows[0].Result | Should -BeExactly $result
            $rows[0].'Command text' | Should -BeExactly $command
        } finally {
            [System.Globalization.CultureInfo]::CurrentCulture = $previousCulture
        }
    }

    It "escapes <Name> according to CSV rules" -TestCases @(
        @{ Name = 'null'; Text = $null; Expected = '' }
        @{ Name = 'an empty value'; Text = ''; Expected = '' }
        @{ Name = 'ordinary text'; Text = 'example'; Expected = 'example' }
        @{ Name = 'a comma'; Text = 'example,folder'; Expected = '"example,folder"' }
        @{ Name = 'a quote'; Text = 'example"folder'; Expected = '"example""folder"' }
        @{ Name = 'a carriage return'; Text = 'example' + "`r" + 'folder'; Expected = '"example' + "`r" + 'folder"' }
        @{ Name = 'a newline'; Text = 'example' + "`n" + 'folder'; Expected = '"example' + "`n" + 'folder"' }
    ) {
        param($Name, $Text, $Expected)
        EscapeCsvColumn -text $Text | Should -BeExactly $Expected
    }

    It "forwards the whole folder to error logging and retains its Guid in the CSV" {
        InitializeOperationSummary -Path $Script:summaryPath
        $folder = New-TestLocalFolder

        WriteErrorSummary -folder $folder -operation 'Create' -errorMessage 'Example Exchange failure' -commandText 'example command'

        $Script:errorsEncountered | Should -Be 1
        $row = ConvertFrom-Csv -InputObject ([System.IO.File]::ReadAllText($Script:summaryPath).Substring(1))
        $row.Identity | Should -BeExactly $folder.Guid.ToString()
        $row.Result | Should -BeExactly 'Example Exchange failure'
        $row.Operation | Should -BeExactly 'Create'
    }

    It "counts an Exchange error even if its error summary cannot be written" {
        Mock -CommandName WriteOperationSummary -MockWith { throw 'Example summary write failed.' }
        $folder = New-TestLocalFolder

        {
            WriteErrorSummary -folder $folder -operation 'Create' -errorMessage 'Example Exchange failure' -commandText 'example command'
        } | Should -Throw -ExpectedMessage '*summary write failed*'

        $Script:errorsEncountered | Should -Be 1
        Should -Invoke -CommandName WriteOperationSummary -Times 1 -Exactly -ParameterFilter {
            $folder.Guid -eq [guid]'11111111-1111-1111-1111-111111111111'
        }
    }

    It "preserves a successful Exchange create when its locked log switches to a fallback" {
        InitializeOperationSummary -Path $Script:summaryPath
        $Script:ObjectsCreated = 0
        $Script:WhatIf = $false
        Mock -CommandName New-RemoteSyncMailPublicFolder -MockWith {}
        Mock -CommandName WriteErrorSummary -MockWith {}
        $lock = [System.IO.File]::Open($Script:summaryPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            NewMailEnabledPublicFolder -localFolder (New-TestLocalFolder)
        } finally {
            $lock.Dispose()
        }

        $Script:ObjectsCreated | Should -Be 1
        $Script:errorsEncountered | Should -Be 0
        $Script:summaryFilePath | Should -Not -Be $Script:summaryPath
        $rows = @(ConvertFrom-Csv -InputObject ([System.IO.File]::ReadAllText($Script:summaryFilePath).Substring(1)))
        $rows.Count | Should -Be 1
        $rows[0].Result | Should -BeExactly $Script:LocalizedStrings.CsvSuccessResult
        Should -Invoke -CommandName New-RemoteSyncMailPublicFolder -Times 1 -Exactly
        Should -Invoke -CommandName WriteErrorSummary -Times 0 -Exactly
    }
}
