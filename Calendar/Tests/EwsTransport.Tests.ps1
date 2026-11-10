# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# cspell:ignore evilcontoso faultcode faultstring Rehoming tzone

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeDiscovery {
    $Script:backOffCases = @(
        @{ Name = 'a positive server value'; MessageXml = '<m:MessageXml><t:Value Name="BackOffMilliseconds">29000</t:Value></m:MessageXml>'; Expected = 29000 }
        @{ Name = 'a missing MessageXml element'; MessageXml = ''; Expected = 0 }
        @{ Name = 'a missing BackOffMilliseconds value'; MessageXml = '<m:MessageXml><t:Value Name="Policy">EWS</t:Value></m:MessageXml>'; Expected = 0 }
        @{ Name = 'a non-numeric value'; MessageXml = '<m:MessageXml><t:Value Name="BackOffMilliseconds">soon</t:Value></m:MessageXml>'; Expected = 0 }
        @{ Name = 'a negative value'; MessageXml = '<m:MessageXml><t:Value Name="BackOffMilliseconds">-5</t:Value></m:MessageXml>'; Expected = 0 }
        @{ Name = 'a zero value'; MessageXml = '<m:MessageXml><t:Value Name="BackOffMilliseconds">0</t:Value></m:MessageXml>'; Expected = 0 }
        @{ Name = 'a value above the Int32 range'; MessageXml = '<m:MessageXml><t:Value Name="BackOffMilliseconds">3000000000</t:Value></m:MessageXml>'; Expected = 0 }
    )
    $Script:retryCases = @(
        @{ Attempt = 0; Server = $null; Expected = 1000 }
        @{ Attempt = 3; Server = $null; Expected = 8000 }
        @{ Attempt = 0; Server = 29000; Expected = 29000 }
        @{ Attempt = 5; Server = 1000; Expected = 32000 }
        @{ Attempt = 10; Server = $null; Expected = 300000 }
        @{ Attempt = 2; Server = 500000; Expected = 300000 }
    )
    $Script:cultureCases = @(
        @{ Culture = 'th-TH' }
        @{ Culture = 'ar-SA' }
    )
    # Hand-computed one-year slice boundaries from 2026-11-01T00:00Z; 2028 is a leap year, so later
    # 365-day boundaries fall on 31 October.
    $Script:sliceCases = @(
        @{ Days = 1825; Boundaries = @('2026-11-01', '2027-11-01', '2028-10-31', '2029-10-31', '2030-10-31', '2031-10-31'); LastSliceDays = 365 }
        @{ Days = 365; Boundaries = @('2026-11-01', '2027-11-01'); LastSliceDays = 365 }
        @{ Days = 400; Boundaries = @('2026-11-01', '2027-11-01', '2027-12-06'); LastSliceDays = 35 }
    )
}

BeforeAll {
    $Script:parentPath = Split-Path -Parent $PSScriptRoot
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\EwsTransport.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\CalendarTimeZoneData.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\MigrationJournal.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Rehoming.ps1
    . $Script:parentPath\CalendarTimeZoneMigrationHelpers\Reconcile.ps1

    function Get-IdentityItem {
        param(
            [string]
            $Id,

            [string]
            $Type,

            [string]
            $Start = '2026-11-09T18:00:00Z',

            [string]
            $End = '2026-11-09T19:00:00Z',

            [string]
            $StartZone = 'Pacific Standard Time',

            [string]
            $EndZone = 'Pacific Standard Time'
        )
        $document = New-Object Xml.XmlDocument
        $document.LoadXml('<t:CalendarItem xmlns:t="' + $script:TypesNamespace + '">' +
            '<t:ItemId Id="' + $Id + '" ChangeKey="key"/><t:CalendarItemType>' + $Type + '</t:CalendarItemType>' +
            '<t:Subject>' + $Id + '</t:Subject><t:IsOrganizer>true</t:IsOrganizer><t:IsAllDayEvent>false</t:IsAllDayEvent>' +
            '<t:Start>' + $Start + '</t:Start><t:End>' + $End + '</t:End>' +
            '<t:StartTimeZone Id="' + $StartZone + '"/><t:EndTimeZone Id="' + $EndZone + '"/></t:CalendarItem>')
        Write-Output -InputObject $document.DocumentElement -NoEnumerate
    }

    $Script:errorsNamespace = 'http://schemas.microsoft.com/exchange/services/2006/errors'
    $Script:fakeEwsUrl = 'https://ews-test.contoso.invalid/EWS/Exchange.asmx'
    $Script:fakeAutodiscoverUrl = 'https://autodiscover-test.contoso.invalid/autodiscover/autodiscover.xml'

    function New-SoapFaultXml {
        param(
            [string]
            $FaultCode,

            [string]
            $DetailCode,

            [string]
            $BackOff
        )
        $detail = ''
        if ($DetailCode -or $BackOff) {
            $detail = '<detail>'
            if ($DetailCode) {
                $detail += '<e:ResponseCode xmlns:e="' + $Script:errorsNamespace + '">' + $DetailCode + '</e:ResponseCode>' +
                '<e:Message xmlns:e="' + $Script:errorsNamespace + '">The request failed.</e:Message>'
            }
            if ($BackOff) {
                $detail += '<t:MessageXml xmlns:t="' + $script:TypesNamespace + '"><t:Value Name="BackOffMilliseconds">' + $BackOff + '</t:Value></t:MessageXml>'
            }
            $detail += '</detail>'
        }
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>' +
        '<faultcode xmlns:a="' + $script:TypesNamespace + '">' + $FaultCode + '</faultcode>' +
        '<faultstring xml:lang="en-US">The server cannot service this request right now.</faultstring>' + $detail +
        '</s:Fault></s:Body></s:Envelope>'
    }

    function New-ResponseMessageXml {
        param(
            [string]
            $Code = 'NoError',

            [string]
            $BackOff
        )
        $class = if ($Code -eq 'NoError') { 'Success' } else { 'Error' }
        $messageXml = if ($BackOff) { '<m:MessageXml><t:Value Name="BackOffMilliseconds">' + $BackOff + '</t:Value></m:MessageXml>' } else { '' }
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="' + $script:MessagesNamespace + '" xmlns:t="' + $script:TypesNamespace + '">' +
        '<s:Header><t:ServerVersionInfo MajorVersion="15" MinorVersion="2" MajorBuildNumber="1544" MinorBuildNumber="4"/></s:Header>' +
        '<s:Body><m:GetFolderResponse><m:ResponseMessages><m:GetFolderResponseMessage ResponseClass="' + $class + '">' +
        '<m:MessageText>Test response.</m:MessageText><m:ResponseCode>' + $Code + '</m:ResponseCode>' + $messageXml +
        '</m:GetFolderResponseMessage></m:ResponseMessages></m:GetFolderResponse></s:Body></s:Envelope>'
    }

    function New-AutodiscoverSettingsXml {
        param(
            [string]
            $InternalUrl,

            [string]
            $ExternalUrl
        )
        $protocols = ''
        if ($InternalUrl) { $protocols += '<Protocol><Type>EXCH</Type><Server>exch1.contoso.com</Server><EwsUrl>' + $InternalUrl + '</EwsUrl></Protocol>' }
        if ($ExternalUrl) { $protocols += '<Protocol><Type>EXPR</Type><Server>mail.contoso.com</Server><EwsUrl>' + $ExternalUrl + '</EwsUrl></Protocol>' }
        '<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">' +
        '<Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"><User><DisplayName>Test User</DisplayName></User>' +
        '<Account><AccountType>email</AccountType><Action>settings</Action>' + $protocols + '</Account></Response></Autodiscover>'
    }

    function New-AutodiscoverRedirectXml {
        param(
            [ValidateSet('redirectAddr', 'redirectUrl')]
            [string]
            $Action,

            [string]
            $Target
        )
        $element = if ($Action -eq 'redirectAddr') { 'RedirectAddr' } else { 'RedirectUrl' }
        '<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">' +
        '<Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">' +
        '<Account><AccountType>email</AccountType><Action>' + $Action + '</Action><' + $element + '>' + $Target + '</' + $element + '></Account></Response></Autodiscover>'
    }

    function New-TestCredential {
        $secret = New-Object Security.SecureString
        foreach ($character in 'not-a-real-value'.ToCharArray()) { $secret.AppendChar($character) }
        New-Object Management.Automation.PSCredential('CONTOSO\user', $secret)
    }

    # Asserts that a credential cache offers the test credential only to Negotiate and NTLM for one authority.
    function Assert-IntegratedCredentialCache {
        param(
            $Cache,

            [uri]
            $Url
        )
        $Cache -is [Net.CredentialCache] | Should -BeTrue
        $Cache.GetCredential($Url, 'Basic') | Should -BeNullOrEmpty
        $Cache.GetCredential($Url, 'Digest') | Should -BeNullOrEmpty
        foreach ($scheme in 'Negotiate', 'NTLM') {
            $networkCredential = $Cache.GetCredential($Url, $scheme)
            $networkCredential | Should -Not -BeNullOrEmpty
            $networkCredential.UserName | Should -BeExactly 'user'
            $networkCredential.Domain | Should -BeExactly 'CONTOSO'
        }
        $Cache.GetCredential([uri]'https://other-host.contoso.invalid/EWS/Exchange.asmx', 'Negotiate') | Should -BeNullOrEmpty
    }

    # Loads the in-memory HTTP endpoint from Data\FakeEwsWebRequest.cs for test host names below .invalid.
    function Register-FakeHttp {
        if (-not ('ExOPTests.FakeEwsWebRequest' -as [type])) {
            Add-Type -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Data\FakeEwsWebRequest.cs') -IgnoreWarnings -WarningAction SilentlyContinue
        }
        foreach ($prefix in 'https://ews-test.contoso.invalid/', 'https://autodiscover-test.contoso.invalid/') {
            $null = [Net.WebRequest]::RegisterPrefix($prefix, (New-Object -TypeName ExOPTests.FakeEwsWebRequestCreator))
        }
    }
}

Describe 'Testing EwsTransport.ps1' {
    Context 'Get-ExOPCredentialAccountFilter' {
        It 'Searches a DOMAIN\user account by its SID' {
            $current = [Security.Principal.WindowsIdentity]::GetCurrent()
            Get-ExOPCredentialAccountFilter -UserName $current.Name | Should -BeExactly "(objectSid=$($current.User.Value))"
        }

        It 'Falls back to the account name when the domain cannot be resolved' {
            Get-ExOPCredentialAccountFilter -UserName 'NO-SUCH-DOMAIN-7F3A\delegate' -Verbose:$false |
                Should -BeExactly '(&(objectCategory=person)(sAMAccountName=delegate))'
        }

        It 'Searches a user principal name as given' {
            Get-ExOPCredentialAccountFilter -UserName 'delegate@contoso.com' | Should -BeExactly '(userPrincipalName=delegate@contoso.com)'
        }
    }

    Context 'Report path relative to the current PowerShell location' {
        BeforeAll {
            $Script:reportLocation = Join-Path -Path $TestDrive -ChildPath 'report-location'
            $null = New-Item -ItemType Directory -Path $Script:reportLocation
            $Script:processDirectory = [Environment]::CurrentDirectory
            Push-Location -LiteralPath $Script:reportLocation
            [Environment]::CurrentDirectory = $env:SystemRoot
        }

        AfterAll {
            [Environment]::CurrentDirectory = $Script:processDirectory
            Pop-Location
        }

        It 'Writes the report below the current location, not the process directory' {
            $exported = [PSCustomObject]@{ Mailbox = 'user@contoso.com'; Subject = 'Sync' } | Export-ExOPCalendarMigrationReport -Path '.\Report.csv'
            $exported.Path | Should -BeExactly (Join-Path -Path $Script:reportLocation -ChildPath 'Report.csv')
            Test-Path -LiteralPath $exported.Path -PathType Leaf | Should -BeTrue
        }

        It 'Protects the existing report it would replace' {
            { [PSCustomObject]@{ Mailbox = 'user@contoso.com'; Subject = 'Sync' } | Export-ExOPCalendarMigrationReport -Path '.\Report.csv' } |
                Should -Throw -ExpectedMessage '*Output already exists*'
        }
    }

    Context 'New-ExOPCalendarSession' {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
        }

        It 'Rejects plain HTTP' {
            { New-ExOPCalendarSession -EwsUrl 'http://mail.contoso.com/EWS/Exchange.asmx' } | Should -Throw -ExpectedMessage '*must be HTTPS*'
        }

        It 'Rejects embedded credentials' {
            { New-ExOPCalendarSession -EwsUrl 'https://user@mail.contoso.com/EWS/Exchange.asmx' } | Should -Throw -ExpectedMessage '*embedded credentials*'
        }

        It 'Creates an HTTPS session without contacting Exchange' {
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx' -Impersonation
            $session.EwsUrl.AbsoluteUri | Should -BeExactly 'https://mail.contoso.com/EWS/Exchange.asmx'
            $session.Impersonation | Should -BeTrue
            $session.Credential | Should -BeNullOrEmpty
            $session.TimeoutSeconds | Should -Be 60
            $session.ReadOperations | Should -Be 0
            $session.WriteOperations | Should -Be 0
            $session.ActiveOperation | Should -BeNullOrEmpty
            $session.ReadConnectionGroup | Should -Match '^[0-9a-f]{32}$'
            Should -Invoke Invoke-ExOPEwsRequest -Times 0 -Exactly -Scope It
        }

        It 'Records Parameter as the default EWS URL source' {
            (New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx').EwsUrlSource | Should -BeExactly 'Parameter'
        }

        It 'Records an explicit EWS URL source' {
            $source = 'Autodiscover SCP https://exch1.contoso.com/autodiscover/autodiscover.xml (EXCH)'
            (New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx' -EwsUrlSource $source).EwsUrlSource | Should -BeExactly $source
        }

        It 'Reads the EWS URL source of a session' {
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx' -EwsUrlSource 'Autodiscover DNS test'
            Get-ExOPSessionEwsUrlSource -Session $session | Should -BeExactly 'Autodiscover DNS test'
        }

        It 'Reports Parameter for a session without an EWS URL source' {
            Get-ExOPSessionEwsUrlSource -Session ([PSCustomObject]@{ EwsUrl = [uri]'https://mail.contoso.com/EWS/Exchange.asmx' }) | Should -BeExactly 'Parameter'
            Get-ExOPSessionEwsUrlSource -Session ([PSCustomObject]@{ EwsUrlSource = '' }) | Should -BeExactly 'Parameter'
        }
    }

    Context 'Throttling back-off' {
        It 'Returns <Expected> for <Name>' -ForEach $Script:backOffCases {
            $document = New-Object Xml.XmlDocument
            $document.LoadXml('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="' + $script:MessagesNamespace +
                '" xmlns:t="' + $script:TypesNamespace + '"><s:Body><m:UpdateItemResponse><m:ResponseMessages>' +
                '<m:UpdateItemResponseMessage ResponseClass="Error"><m:MessageText>The server cannot service this request right now.</m:MessageText>' +
                '<m:ResponseCode>ErrorServerBusy</m:ResponseCode><m:DescriptiveLinkKey>0</m:DescriptiveLinkKey>' + $MessageXml +
                '</m:UpdateItemResponseMessage></m:ResponseMessages></m:UpdateItemResponse></s:Body></s:Envelope>')
            $errorNode = $document.SelectSingleNode("//m:*[@ResponseClass='Error']", (Get-ExOPNamespaceManager -Node $document))
            Get-ExOPServerBackOffMilliseconds -ErrorNode $errorNode | Should -Be $Expected
        }

        It 'Reads the back-off from a SOAP fault detail' {
            $document = ConvertFrom-ExOPXmlContent -Content (New-SoapFaultXml -FaultCode 'a:ErrorServerBusy' -DetailCode 'ErrorServerBusy' -BackOff '1500')
            $fault = $document.SelectSingleNode('//s:Fault', (Get-ExOPNamespaceManager -Node $document))
            Get-ExOPServerBackOffMilliseconds -ErrorNode $fault | Should -Be 1500
        }

        It 'Returns 0 for a SOAP fault without a back-off' {
            $document = ConvertFrom-ExOPXmlContent -Content (New-SoapFaultXml -FaultCode 'a:ErrorServerBusy' -DetailCode 'ErrorServerBusy')
            $fault = $document.SelectSingleNode('//s:Fault', (Get-ExOPNamespaceManager -Node $document))
            Get-ExOPServerBackOffMilliseconds -ErrorNode $fault | Should -Be 0
        }

        It 'Waits <Expected> ms for attempt <Attempt> with server value <Server>' -ForEach $Script:retryCases {
            $delay = Get-ExOPRetryDelayMilliseconds -Attempt $Attempt -ServerMilliseconds $Server
            $delay | Should -BeOfType [int]
            $delay | Should -Be $Expected
        }
    }

    Context 'Instant handling under culture <Culture>' -ForEach $Script:cultureCases {
        It 'Parses and formats instants independently of the culture' {
            $originalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
            $originalUICulture = [Threading.Thread]::CurrentThread.CurrentUICulture
            try {
                [Threading.Thread]::CurrentThread.CurrentCulture = New-Object Globalization.CultureInfo($Culture)
                [Threading.Thread]::CurrentThread.CurrentUICulture = New-Object Globalization.CultureInfo($Culture)
                [Globalization.CultureInfo]::CurrentCulture.Name | Should -BeExactly $Culture
                $instant = ConvertTo-ExOPInstant -Value '2026-11-09T10:00:00-08:00'
                $instant.Offset | Should -Be ([TimeSpan]::Zero)
                $instant.UtcDateTime.Year | Should -Be 2026
                $instant.UtcDateTime.Hour | Should -Be 18
                Format-ExOPInstant -Value $instant | Should -BeExactly '2026-11-09T18:00:00.0000000Z'
                Format-ExOPInstant -Value (ConvertTo-ExOPInstant -Value '2026-11-09T18:00:00') | Should -BeExactly '2026-11-09T18:00:00.0000000Z'
            } finally {
                [Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
                [Threading.Thread]::CurrentThread.CurrentUICulture = $originalUICulture
            }
        }
    }

    Context 'Report keeps case-sensitive EWS identifiers for <Mode>' -ForEach @(
        @{ Mode = 'Singles'; Expected = @('AAAA', 'AAAa') }
        @{ Mode = 'Series'; Expected = @('MasterAAAA', 'MasterAAAa') }
    ) {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
            $Script:identityTestMode = $Mode
            Mock Get-ExOPCalendarTimeZone { [PSCustomObject]@{ Id = 'Pacific Standard Time'; DisplayName = 'Pacific' } }
            Mock Get-ExOPCalendarWindow {
                $type = if ($Script:identityTestMode -eq 'Singles') { 'Single' } else { 'Occurrence' }
                Get-IdentityItem -Id 'AAAA' -Type $type
                Get-IdentityItem -Id 'AAAa' -Type $type
            }
            Mock Get-ExOPCalendarItems {
                foreach ($reference in $References) {
                    $document = New-Object Xml.XmlDocument
                    $document.LoadXml('<root xmlns:t="' + $script:TypesNamespace + '">' + $reference + '</root>')
                    $node = $document.DocumentElement.FirstChild
                    if ($node.LocalName -eq 'RecurringMasterItemId') {
                        $id = if ($node.GetAttribute('OccurrenceId') -ceq 'AAAA') { 'MasterAAAA' } else { 'MasterAAAa' }
                        Get-IdentityItem -Id $id -Type 'RecurringMaster'
                    } else {
                        $type = if ($Script:identityTestMode -eq 'Singles') { 'Single' } else { 'RecurringMaster' }
                        Get-IdentityItem -Id $node.GetAttribute('Id') -Type $type
                    }
                }
            }
            $session = [PSCustomObject]@{ Diagnostics = New-Object 'System.Collections.Generic.List[object]' }
            $start = [DateTimeOffset]::Parse('2026-11-01T00:00:00Z', [Globalization.CultureInfo]::InvariantCulture)
            $Script:rows = @(Get-ExOPCalendarMigrationReport -Session $session -Mailbox 'user@contoso.com' -FromWindowsTimeZoneId 'pacific STANDARD time' -QueryStartDate $start)
        }

        It 'Returns both items without conflating identifiers that differ only by case' {
            $Script:rows | Should -HaveCount 2
            @($Script:rows | Where-Object { $_.ItemId -ceq $Expected[0] }) | Should -HaveCount 1
            @($Script:rows | Where-Object { $_.ItemId -ceq $Expected[1] }) | Should -HaveCount 1
        }

        It 'Writes the server''s exact source time zone ID, not the spelling typed by the operator' {
            @($Script:rows | Where-Object { $_.FromWindowsTimeZoneId -cne 'Pacific Standard Time' }) | Should -HaveCount 0
        }

        It 'Never contacts Exchange' {
            Should -Invoke Invoke-ExOPEwsRequest -Times 0 -Exactly -Scope Context
        }
    }

    Context 'Report queries <Days> days in calendar views of at most 365 days' -ForEach $Script:sliceCases {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
            $Script:windowCalls = New-Object 'System.Collections.Generic.List[object]'
            Mock Get-ExOPCalendarTimeZone { [PSCustomObject]@{ Id = 'Pacific Standard Time'; DisplayName = 'Pacific' } }
            Mock Get-ExOPCalendarItems { }
            Mock Get-ExOPCalendarWindow { $Script:windowCalls.Add([PSCustomObject]@{ Start = $Start; End = $End }) }
            $session = [PSCustomObject]@{ Diagnostics = New-Object 'System.Collections.Generic.List[object]' }
            $start = [DateTimeOffset]::Parse('2026-11-01T00:00:00Z', [Globalization.CultureInfo]::InvariantCulture)
            $Script:rows = @(Get-ExOPCalendarMigrationReport -Session $session -Mailbox 'user@contoso.com' -FromWindowsTimeZoneId 'Pacific Standard Time' `
                    -QueryStartDate $start -QueryWindowInDays $Days)
        }

        It 'Requests one calendar view per slice' {
            $Script:windowCalls | Should -HaveCount ($Boundaries.Count - 1)
            Should -Invoke Get-ExOPCalendarWindow -Times ($Boundaries.Count - 1) -Exactly -Scope Context
        }

        It 'Keeps every slice within the EWS limit' {
            foreach ($call in $Script:windowCalls) {
                ($call.End - $call.Start).TotalDays | Should -BeGreaterThan 0
                ($call.End - $call.Start).TotalDays | Should -BeLessOrEqual 365
            }
            ($Script:windowCalls[-1].End - $Script:windowCalls[-1].Start).TotalDays | Should -Be $LastSliceDays
        }

        It 'Covers the query window with contiguous slices' {
            $actual = @($Script:windowCalls[0].Start) + @($Script:windowCalls | ForEach-Object { $_.End })
            ($actual | ForEach-Object { Format-ExOPInstant -Value $_ }) -join ',' |
                Should -BeExactly (($Boundaries | ForEach-Object { $_ + 'T00:00:00.0000000Z' }) -join ',')
            for ($index = 1; $index -lt $Script:windowCalls.Count; $index++) {
                $Script:windowCalls[$index].Start | Should -Be $Script:windowCalls[$index - 1].End
            }
        }

        It 'Returns no rows for an empty calendar' {
            $Script:rows | Should -HaveCount 0
        }
    }

    Context 'Report merges a series whose occurrences appear in two slices' {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
            Mock Get-ExOPCalendarTimeZone { [PSCustomObject]@{ Id = 'Pacific Standard Time'; DisplayName = 'Pacific' } }
            Mock Get-ExOPCalendarWindow {
                if ((Format-ExOPInstant -Value $Start) -eq '2026-11-01T00:00:00.0000000Z') {
                    Get-IdentityItem -Id 'OccurrenceMarch' -Type 'Occurrence' -Start '2027-03-15T17:00:00Z' -End '2027-03-15T18:00:00Z'
                    Get-IdentityItem -Id 'OccurrenceJanuary' -Type 'Occurrence' -Start '2027-01-15T18:00:00Z' -End '2027-01-15T19:00:00Z'
                } else {
                    Get-IdentityItem -Id 'OccurrenceNovember' -Type 'Occurrence' -Start '2027-11-20T18:00:00Z' -End '2027-11-20T19:00:00Z'
                }
            }
            Mock Get-ExOPCalendarItems {
                foreach ($reference in $References) {
                    Get-IdentityItem -Id 'MasterSeries' -Type 'RecurringMaster' -Start '2027-01-15T18:00:00Z' -End '2027-01-15T19:00:00Z'
                }
            }
            $session = [PSCustomObject]@{ Diagnostics = New-Object 'System.Collections.Generic.List[object]' }
            $start = [DateTimeOffset]::Parse('2026-11-01T00:00:00Z', [Globalization.CultureInfo]::InvariantCulture)
            $Script:rows = @(Get-ExOPCalendarMigrationReport -Session $session -Mailbox 'user@contoso.com' -FromWindowsTimeZoneId 'Pacific Standard Time' `
                    -QueryStartDate $start -QueryWindowInDays 400)
        }

        It 'Queries both slices' {
            Should -Invoke Get-ExOPCalendarWindow -Times 2 -Exactly -Scope Context
        }

        It 'Resolves all three occurrences to their master' {
            Should -Invoke Get-ExOPCalendarItems -Times 1 -Exactly -Scope Context -ParameterFilter { $IdOnly -and $References.Count -eq 3 }
        }

        It 'Returns exactly one row for the series' {
            $Script:rows | Should -HaveCount 1
            $Script:rows[0].ItemId | Should -BeExactly 'MasterSeries'
            $Script:rows[0].RecordType | Should -BeExactly 'RecurringSeries'
            Should -Invoke Get-ExOPCalendarItems -Times 1 -Exactly -Scope Context -ParameterFilter { -not $IdOnly -and $References.Count -eq 1 }
        }

        It 'Reports the earliest occurrence across slices' {
            $Script:rows[0].FirstOccurrenceStartUtc | Should -BeExactly '2027-01-15T18:00:00.0000000Z'
            $Script:rows[0].FirstOccurrenceEndUtc | Should -BeExactly '2027-01-15T19:00:00.0000000Z'
        }
    }

    Context 'Report skips items with an IANA or pseudo time zone' {
        BeforeAll {
            Mock Invoke-ExOPEwsRequest { throw 'Unexpected EWS request in an offline test.' }
            Mock Get-ExOPCalendarTimeZone { [PSCustomObject]@{ Id = 'Pacific Standard Time'; DisplayName = 'Pacific' } }
            $Script:zoneItems = @{
                WindowsItem      = @('Pacific Standard Time', 'Pacific Standard Time')
                IanaStartItem    = @('Europe/Lisbon', 'Europe/Lisbon')
                IanaEndItem      = @('Pacific Standard Time', 'America/Los_Angeles')
                PseudoZoneItem   = @('tzone://Microsoft/Utc', 'tzone://Microsoft/Utc')
                OtherWindowsItem = @('GMT Standard Time', 'GMT Standard Time')
            }
            Mock Get-ExOPCalendarWindow {
                foreach ($id in @($Script:zoneItems.Keys | Sort-Object)) { Get-IdentityItem -Id $id -Type 'Single' }
            }
            Mock Get-ExOPCalendarItems {
                foreach ($reference in $References) {
                    $document = New-Object Xml.XmlDocument
                    $document.LoadXml('<root xmlns:t="' + $script:TypesNamespace + '">' + $reference + '</root>')
                    $id = $document.DocumentElement.FirstChild.GetAttribute('Id')
                    Get-IdentityItem -Id $id -Type 'Single' -StartZone $Script:zoneItems[$id][0] -EndZone $Script:zoneItems[$id][1]
                }
            }
            $Script:session = [PSCustomObject]@{ Diagnostics = New-Object 'System.Collections.Generic.List[object]' }
            $start = [DateTimeOffset]::Parse('2026-11-01T00:00:00Z', [Globalization.CultureInfo]::InvariantCulture)
            $Script:rows = @(Get-ExOPCalendarMigrationReport -Session $Script:session -Mailbox 'user@contoso.com' -FromWindowsTimeZoneId 'Pacific Standard Time' `
                    -QueryStartDate $start -WarningVariable reportWarnings -WarningAction SilentlyContinue)
            $Script:reportWarnings = @($reportWarnings)
        }

        It 'Reports only the item with a matching Windows time zone' {
            $Script:rows | Should -HaveCount 1
            $Script:rows[0].ItemId | Should -BeExactly 'WindowsItem'
        }

        It 'Records <_> as an IANA time zone item' -ForEach @('IanaStartItem', 'IanaEndItem') {
            $diagnostic = @($Script:session.Diagnostics | Where-Object ItemId -CEQ $_)
            $diagnostic | Should -HaveCount 1
            $diagnostic[0].Code | Should -BeExactly 'IanaTimeZone'
            $diagnostic[0].Subject | Should -BeExactly $_
            $diagnostic[0].Mailbox | Should -BeExactly 'user@contoso.com'
        }

        It 'Keeps the pseudo time zone diagnostic for tzone identifiers' {
            $diagnostic = @($Script:session.Diagnostics | Where-Object ItemId -CEQ 'PseudoZoneItem')
            $diagnostic | Should -HaveCount 1
            $diagnostic[0].Code | Should -BeExactly 'NoWindowsTimeZoneDefinition'
        }

        It 'Records no diagnostic for Windows time zones' {
            @($Script:session.Diagnostics | Where-Object { $_.ItemId -in 'WindowsItem', 'OtherWindowsItem' }) | Should -HaveCount 0
            $Script:session.Diagnostics | Should -HaveCount 3
        }

        It 'Warns about each IANA time zone item' {
            @($Script:reportWarnings | Where-Object { $_.Message -like '*IANA time zone*' }) | Should -HaveCount 2
            @($Script:reportWarnings | Where-Object { $_.Message -like '*Europe/Lisbon*' }) | Should -HaveCount 1
            @($Script:reportWarnings | Where-Object { $_.Message -like '*America/Los_Angeles*' }) | Should -HaveCount 1
        }
    }

    Context 'Invoke-ExOPEwsRequest with an in-memory HTTP endpoint' {
        BeforeAll {
            Register-FakeHttp
            Mock Start-Sleep { }
        }

        BeforeEach {
            [ExOPTests.FakeEwsServer]::Reset()
            $Script:session = New-ExOPCalendarSession -EwsUrl $Script:fakeEwsUrl
        }

        It 'Uses the in-memory endpoint instead of the network' {
            [Net.WebRequest]::Create($Script:fakeEwsUrl).GetType().FullName | Should -BeExactly 'ExOPTests.FakeEwsWebRequest'
        }

        It 'Offers an explicit credential only to integrated authentication for a discovered EWS URL' {
            $discovered = New-ExOPCalendarSession -EwsUrl $Script:fakeEwsUrl -Credential (New-TestCredential) -EwsUrlSource "Autodiscover SCP $($Script:fakeAutodiscoverUrl) (EXCH)"
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $null = Invoke-ExOPEwsRequest -Session $discovered -Body '<m:GetFolder/>' -Mailbox 'user@contoso.com' -ReadOnly
            [ExOPTests.FakeEwsServer]::LastUseDefaultCredentials | Should -BeFalse
            Assert-IntegratedCredentialCache -Cache ([ExOPTests.FakeEwsServer]::LastCredentials) -Url $Script:fakeEwsUrl
        }

        It 'Uses the explicit credential directly for an EWS URL given as a parameter' {
            $parameterSession = New-ExOPCalendarSession -EwsUrl $Script:fakeEwsUrl -Credential (New-TestCredential)
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $null = Invoke-ExOPEwsRequest -Session $parameterSession -Body '<m:UpdateItem/>' -Mailbox 'user@contoso.com'
            $credential = [ExOPTests.FakeEwsServer]::LastCredentials
            $credential -is [Net.NetworkCredential] | Should -BeTrue
            $credential.UserName | Should -BeExactly 'user'
            $credential.Domain | Should -BeExactly 'CONTOSO'
            [ExOPTests.FakeEwsServer]::LastUseDefaultCredentials | Should -BeFalse
        }

        It 'Uses the current Windows credentials without an explicit credential' {
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $null = Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:GetFolder/>' -Mailbox 'user@contoso.com' -ReadOnly
            [ExOPTests.FakeEwsServer]::LastUseDefaultCredentials | Should -BeTrue
            [ExOPTests.FakeEwsServer]::LastCredentials | Should -BeNullOrEmpty
        }

        It 'Returns a successful response' {
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $document = Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:GetFolder/>' -Mailbox 'user@contoso.com' -ReadOnly
            $document -is [Xml.XmlDocument] | Should -BeTrue
            $Script:session.LastServerVersion | Should -BeExactly '15.2.1544.4'
            [ExOPTests.FakeEwsServer]::Requests[0] | Should -BeLike '*<m:GetFolder/>*'
            Should -Invoke Start-Sleep -Times 0 -Exactly -Scope It
        }

        It 'Retries a read after a SOAP fault with the ErrorServerBusy fault code' {
            [ExOPTests.FakeEwsServer]::Enqueue(500, (New-SoapFaultXml -FaultCode 'a:ErrorServerBusy' -DetailCode 'ErrorServerBusy' -BackOff '1500'))
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $document = Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:GetFolder/>' -Mailbox 'user@contoso.com' -ReadOnly
            $document -is [Xml.XmlDocument] | Should -BeTrue
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be 2
            $Script:session.ReadOperations | Should -Be 2
            $Script:session.ThrottlingRetries | Should -Be 1
            $Script:session.ThrottlingDelayMilliseconds | Should -Be 1500
            Should -Invoke Start-Sleep -Times 1 -Exactly -Scope It -ParameterFilter { $Milliseconds -eq 1500 }
        }

        It 'Retries a write after a SOAP fault whose detail response code is ErrorServerBusy' {
            [ExOPTests.FakeEwsServer]::Enqueue(500, (New-SoapFaultXml -FaultCode 's:Client' -DetailCode 'ErrorServerBusy' -BackOff '4000'))
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $document = Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:UpdateItem/>' -Mailbox 'user@contoso.com'
            $document -is [Xml.XmlDocument] | Should -BeTrue
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be 2
            $Script:session.WriteOperations | Should -Be 2
            $Script:session.ThrottlingDelayMilliseconds | Should -Be 4000
            Should -Invoke Start-Sleep -Times 1 -Exactly -Scope It -ParameterFilter { $Milliseconds -eq 4000 }
        }

        It 'Waits at least the exponential minimum when a busy fault has no back-off' {
            [ExOPTests.FakeEwsServer]::Enqueue(500, (New-SoapFaultXml -FaultCode 'a:ErrorServerBusy'))
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $null = Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:UpdateItem/>' -Mailbox 'user@contoso.com'
            Should -Invoke Start-Sleep -Times 1 -Exactly -Scope It -ParameterFilter { $Milliseconds -eq 1000 }
        }

        It 'Stops after the maximum number of throttling retries' {
            for ($index = 0; $index -le $script:MAX_THROTTLING_RETRIES; $index++) {
                [ExOPTests.FakeEwsServer]::Enqueue(500, (New-SoapFaultXml -FaultCode 'a:ErrorServerBusy' -DetailCode 'ErrorServerBusy' -BackOff '100'))
            }
            $failure = { Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:UpdateItem/>' -Mailbox 'user@contoso.com' } |
                Should -Throw -ExpectedMessage '*remained busy*' -PassThru
            $failure.Exception.Data['EwsResponseCode'] | Should -BeExactly 'ErrorServerBusy'
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be ($script:MAX_THROTTLING_RETRIES + 1)
            Should -Invoke Start-Sleep -Times $script:MAX_THROTTLING_RETRIES -Exactly -Scope It
        }

        It 'Throws another SOAP fault with the detail response code' {
            [ExOPTests.FakeEwsServer]::Enqueue(500, (New-SoapFaultXml -FaultCode 's:Client' -DetailCode 'ErrorSchemaValidation'))
            $failure = { Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:UpdateItem/>' -Mailbox 'user@contoso.com' } |
                Should -Throw -ExpectedMessage '*SOAP fault*' -PassThru
            $failure.Exception.Data['EwsResponseCode'] | Should -BeExactly 'ErrorSchemaValidation'
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be 1
            Should -Invoke Start-Sleep -Times 0 -Exactly -Scope It
        }

        It 'Throws another SOAP fault without detail with the fault code' {
            [ExOPTests.FakeEwsServer]::Enqueue(500, (New-SoapFaultXml -FaultCode 'a:ErrorInvalidServerVersion'))
            $failure = { Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:GetFolder/>' -Mailbox 'user@contoso.com' -ReadOnly } |
                Should -Throw -ExpectedMessage '*SOAP fault*' -PassThru
            $failure.Exception.Data['EwsResponseCode'] | Should -BeExactly 'ErrorInvalidServerVersion'
            Should -Invoke Start-Sleep -Times 0 -Exactly -Scope It
        }

        It 'Retries a write after a response-level ErrorServerBusy' {
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml -Code 'ErrorServerBusy' -BackOff '2500'))
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $null = Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:UpdateItem/>' -Mailbox 'user@contoso.com'
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be 2
            Should -Invoke Start-Sleep -Times 1 -Exactly -Scope It -ParameterFilter { $Milliseconds -eq 2500 }
        }

        It 'Throws another response-level error with its response code' {
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml -Code 'ErrorItemNotFound'))
            $failure = { Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:GetItem/>' -Mailbox 'user@contoso.com' -ReadOnly } |
                Should -Throw -ExpectedMessage '*ErrorItemNotFound*' -PassThru
            $failure.Exception.Data['EwsResponseCode'] | Should -BeExactly 'ErrorItemNotFound'
        }

        It 'Retries a read after HTTP 503' {
            [ExOPTests.FakeEwsServer]::Enqueue(503, 'Service Unavailable')
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-ResponseMessageXml))
            $null = Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:GetFolder/>' -Mailbox 'user@contoso.com' -ReadOnly
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be 2
            Should -Invoke Start-Sleep -Times 1 -Exactly -Scope It -ParameterFilter { $Milliseconds -eq 1000 }
        }

        It 'Does not retry a write after HTTP 503' {
            [ExOPTests.FakeEwsServer]::Enqueue(503, 'Service Unavailable')
            { Invoke-ExOPEwsRequest -Session $Script:session -Body '<m:UpdateItem/>' -Mailbox 'user@contoso.com' } | Should -Throw
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be 1
            Should -Invoke Start-Sleep -Times 0 -Exactly -Scope It
        }
    }

    Context 'ConvertFrom-ExOPXmlContent' {
        It 'Parses XML into a document' {
            $document = ConvertFrom-ExOPXmlContent -Content '<root><child>value</child></root>'
            $document -is [Xml.XmlDocument] | Should -BeTrue
            $document.DocumentElement.LocalName | Should -BeExactly 'root'
        }

        It 'Rejects a document type definition' {
            { ConvertFrom-ExOPXmlContent -Content '<!DOCTYPE root [<!ENTITY value "expanded">]><root>&value;</root>' } | Should -Throw
        }
    }

    Context 'Select-ExOPAutodiscoverScpUrl' {
        BeforeAll {
            $guid = '77378F46-2C66-4aa9-A6A6-3E7A48B19596'
            $Script:scpRecords = @(
                [PSCustomObject]@{ Url = 'https://other1.contoso.com/autodiscover/autodiscover.xml'; Keywords = @($guid, 'Site=Remote') },
                [PSCustomObject]@{ Url = 'https://generic1.contoso.com/autodiscover/autodiscover.xml'; Keywords = @($guid) },
                [PSCustomObject]@{ Url = 'https://local1.contoso.com/autodiscover/autodiscover.xml'; Keywords = @($guid, 'Site=Main') },
                [PSCustomObject]@{ Url = 'http://insecure.contoso.com/autodiscover/autodiscover.xml'; Keywords = @($guid, 'Site=Main') },
                [PSCustomObject]@{ Url = 'https://LOCAL1.contoso.com/Autodiscover/Autodiscover.xml'; Keywords = @($guid, 'Site=Main') },
                [PSCustomObject]@{ Url = 'https://local2.contoso.com/autodiscover/autodiscover.xml'; Keywords = @($guid, 'Site=Main') },
                [PSCustomObject]@{ Url = 'https://generic2.contoso.com/autodiscover/autodiscover.xml'; Keywords = @() },
                [PSCustomObject]@{ Url = 'not a url'; Keywords = @($guid, 'Site=Main') },
                $null
            )
        }

        It 'Orders the computer site first, then records without a site, then other sites' {
            @(Select-ExOPAutodiscoverScpUrl -Records $Script:scpRecords -SiteName 'Main') -join ',' | Should -BeExactly (@(
                    'https://local1.contoso.com/autodiscover/autodiscover.xml',
                    'https://local2.contoso.com/autodiscover/autodiscover.xml',
                    'https://generic1.contoso.com/autodiscover/autodiscover.xml',
                    'https://generic2.contoso.com/autodiscover/autodiscover.xml',
                    'https://other1.contoso.com/autodiscover/autodiscover.xml') -join ',')
        }

        It 'Puts records without a site first when the computer site is unknown' {
            @(Select-ExOPAutodiscoverScpUrl -Records $Script:scpRecords -SiteName '') -join ',' | Should -BeExactly (@(
                    'https://generic1.contoso.com/autodiscover/autodiscover.xml',
                    'https://generic2.contoso.com/autodiscover/autodiscover.xml',
                    'https://other1.contoso.com/autodiscover/autodiscover.xml',
                    'https://local1.contoso.com/autodiscover/autodiscover.xml',
                    'https://local2.contoso.com/autodiscover/autodiscover.xml') -join ',')
        }

        It 'Returns nothing without records' {
            @(Select-ExOPAutodiscoverScpUrl -Records @() -SiteName 'Main') | Should -HaveCount 0
        }
    }

    Context 'Get-ExOPAutodiscoverResult' {
        BeforeAll {
            $Script:internalEws = 'https://exch1.contoso.com/EWS/Exchange.asmx'
            $Script:externalEws = 'https://mail.contoso.com/EWS/Exchange.asmx'
        }

        It 'Throws the Autodiscover error code and message' {
            $document = ConvertFrom-ExOPXmlContent -Content ('<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">' +
                '<Response><Error Time="10:00:00.0000000" Id="1"><ErrorCode>500</ErrorCode><Message>The email address cannot be found.</Message><DebugData /></Error></Response></Autodiscover>')
            { Get-ExOPAutodiscoverResult -Document $document } | Should -Throw -ExpectedMessage 'Autodiscover error 500: The email address cannot be found.'
        }

        It 'Returns an address redirect as action and target' {
            $result = Get-ExOPAutodiscoverResult -Document (ConvertFrom-ExOPXmlContent -Content (New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'user@sales.contoso.com'))
            $result.Action | Should -BeExactly 'redirectAddr'
            $result.Target | Should -BeExactly 'user@sales.contoso.com'
            $result.EwsUrl | Should -BeExactly ''
        }

        It 'Returns a URL redirect as action and target' {
            $target = 'https://autodiscover.sales.contoso.com/autodiscover/autodiscover.xml'
            $result = Get-ExOPAutodiscoverResult -Document (ConvertFrom-ExOPXmlContent -Content (New-AutodiscoverRedirectXml -Action 'redirectUrl' -Target $target))
            $result.Action | Should -BeExactly 'redirectUrl'
            $result.Target | Should -BeExactly $target
        }

        It 'Picks <Expected> for the <Preference> preference' -ForEach @(
            @{ Preference = 'Internal'; Internal = $true; External = $true; Expected = 'EXCH' }
            @{ Preference = 'External'; Internal = $true; External = $true; Expected = 'EXPR' }
            @{ Preference = 'Internal'; Internal = $false; External = $true; Expected = 'EXPR' }
            @{ Preference = 'External'; Internal = $true; External = $false; Expected = 'EXCH' }
        ) {
            $internalUrl = if ($Internal) { $Script:internalEws } else { '' }
            $externalUrl = if ($External) { $Script:externalEws } else { '' }
            $result = Get-ExOPAutodiscoverResult -Document (ConvertFrom-ExOPXmlContent -Content (New-AutodiscoverSettingsXml -InternalUrl $internalUrl -ExternalUrl $externalUrl)) -Preference $Preference
            $result.Action | Should -BeExactly 'settings'
            $result.ProtocolType | Should -BeExactly $Expected
            $result.EwsUrl | Should -BeExactly $(if ($Expected -eq 'EXCH') { $Script:internalEws } else { $Script:externalEws })
        }

        It 'Skips an internal URL that is <Name>' -ForEach @(
            @{ Name = 'not HTTPS'; Url = 'http://exch1.contoso.com/EWS/Exchange.asmx' }
            @{ Name = 'carrying credentials'; Url = 'https://user@exch1.contoso.com/EWS/Exchange.asmx' }
        ) {
            $result = Get-ExOPAutodiscoverResult -Document (ConvertFrom-ExOPXmlContent -Content (New-AutodiscoverSettingsXml -InternalUrl $Url -ExternalUrl $Script:externalEws)) -Preference Internal
            $result.ProtocolType | Should -BeExactly 'EXPR'
            $result.EwsUrl | Should -BeExactly $Script:externalEws
        }

        It 'Throws when no usable EWS URL exists' {
            $document = ConvertFrom-ExOPXmlContent -Content (New-AutodiscoverSettingsXml -InternalUrl 'http://exch1.contoso.com/EWS/Exchange.asmx')
            { Get-ExOPAutodiscoverResult -Document $document } | Should -Throw -ExpectedMessage '*no HTTPS EWS URL*'
        }

        It 'Throws for a response without account settings' {
            $document = ConvertFrom-ExOPXmlContent -Content '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006"><Response/></Autodiscover>'
            { Get-ExOPAutodiscoverResult -Document $document } | Should -Throw -ExpectedMessage '*no account settings*'
        }
    }

    Context 'Invoke-ExOPAutodiscoverRequest' {
        BeforeAll {
            Register-FakeHttp
        }

        BeforeEach {
            [ExOPTests.FakeEwsServer]::Reset()
        }

        It 'Rejects <Name> without sending a request' -ForEach @(
            @{ Name = 'an HTTP URL'; Url = 'http://autodiscover-test.contoso.invalid/autodiscover/autodiscover.xml' }
            @{ Name = 'a URL with credentials'; Url = 'https://user@autodiscover-test.contoso.invalid/autodiscover/autodiscover.xml' }
        ) {
            { Invoke-ExOPAutodiscoverRequest -Url $Url -EmailAddress 'user@contoso.com' } | Should -Throw -ExpectedMessage '*not an HTTPS URL without embedded credentials*'
            [ExOPTests.FakeEwsServer]::Requests.Count | Should -Be 0
        }

        It 'Posts the escaped address and returns the parsed response' {
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-AutodiscoverSettingsXml -InternalUrl 'https://exch1.contoso.com/EWS/Exchange.asmx'))
            $document = Invoke-ExOPAutodiscoverRequest -Url $Script:fakeAutodiscoverUrl -EmailAddress 'o&brien@contoso.com'
            $document -is [Xml.XmlDocument] | Should -BeTrue
            [ExOPTests.FakeEwsServer]::Urls[0] | Should -BeExactly $Script:fakeAutodiscoverUrl
            [ExOPTests.FakeEwsServer]::Requests[0] | Should -BeLike '*<EMailAddress>o&amp;brien@contoso.com</EMailAddress>*'
        }

        It 'Uses the current Windows credentials without -Credential' {
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-AutodiscoverSettingsXml -InternalUrl 'https://exch1.contoso.com/EWS/Exchange.asmx'))
            $null = Invoke-ExOPAutodiscoverRequest -Url $Script:fakeAutodiscoverUrl -EmailAddress 'user@contoso.com'
            [ExOPTests.FakeEwsServer]::LastUseDefaultCredentials | Should -BeTrue
            [ExOPTests.FakeEwsServer]::LastCredentials | Should -BeNullOrEmpty
        }

        It 'Offers an explicit credential only to integrated authentication for the Autodiscover host' {
            [ExOPTests.FakeEwsServer]::Enqueue(200, (New-AutodiscoverSettingsXml -InternalUrl 'https://exch1.contoso.com/EWS/Exchange.asmx'))
            $null = Invoke-ExOPAutodiscoverRequest -Url $Script:fakeAutodiscoverUrl -EmailAddress 'user@contoso.com' -Credential (New-TestCredential)
            [ExOPTests.FakeEwsServer]::LastUseDefaultCredentials | Should -BeFalse
            Assert-IntegratedCredentialCache -Cache ([ExOPTests.FakeEwsServer]::LastCredentials) -Url $Script:fakeAutodiscoverUrl
        }
    }

    Context 'New-ExOPIntegratedCredentialCache' {
        It 'Offers the credential only to Negotiate and NTLM for the URL authority' {
            $cache = New-ExOPIntegratedCredentialCache -Url 'https://mail.contoso.com/EWS/Exchange.asmx' -Credential (New-TestCredential)
            Assert-IntegratedCredentialCache -Cache $cache -Url 'https://mail.contoso.com/autodiscover/autodiscover.xml'
            $cache.GetCredential([uri]'https://mail.contoso.com:444/EWS/Exchange.asmx', 'Negotiate') | Should -BeNullOrEmpty
        }
    }

    Context 'Resolve-ExOPEwsUrl' {
        BeforeAll {
            $Script:scpMain = 'https://scp-main.contoso.com/autodiscover/autodiscover.xml'
            $Script:scpRemote = 'https://scp-remote.contoso.com/autodiscover/autodiscover.xml'
            $Script:internalEws = 'https://exch1.contoso.com/EWS/Exchange.asmx'
            $Script:externalEws = 'https://mail.contoso.com/EWS/Exchange.asmx'
            Mock Get-ExOPAutodiscoverScpRecord { $Script:scpRecordsForTest }
            Mock Get-ExOPComputerSiteName { 'Main' }
            Mock Invoke-ExOPAutodiscoverRequest {
                $key = $Url.AbsoluteUri + '|' + $EmailAddress
                $Script:autodiscoverCalls.Add($key)
                if (-not $Script:autodiscoverResponses.ContainsKey($key)) { throw 'The remote name could not be resolved.' }
                ConvertFrom-ExOPXmlContent -Content $Script:autodiscoverResponses[$key]
            }

            function Get-DnsUrl {
                param(
                    [string]
                    $Domain,

                    [switch]
                    $AutodiscoverHost
                )
                if ($AutodiscoverHost) { "https://autodiscover.$Domain/autodiscover/autodiscover.xml" } else { "https://$Domain/autodiscover/autodiscover.xml" }
            }
        }

        BeforeEach {
            $Script:autodiscoverCalls = New-Object 'System.Collections.Generic.List[string]'
            $Script:autodiscoverResponses = @{}
            $Script:scpRecordsForTest = @(
                [PSCustomObject]@{ Url = $Script:scpRemote; Keywords = @('Site=Remote') },
                [PSCustomObject]@{ Url = $Script:scpMain; Keywords = @('Site=Main') }
            )
        }

        It 'Uses the SCP first and prefers the internal EWS URL' {
            $Script:autodiscoverResponses["$($Script:scpMain)|user@contoso.com"] = New-AutodiscoverSettingsXml -InternalUrl $Script:internalEws -ExternalUrl $Script:externalEws
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.EwsUrl.AbsoluteUri | Should -BeExactly $Script:internalEws
            $result.EmailAddress | Should -BeExactly 'user@contoso.com'
            $result.AutodiscoverUrl | Should -BeExactly $Script:scpMain
            $result.Source | Should -BeExactly "Autodiscover SCP $($Script:scpMain) (EXCH)"
            $Script:autodiscoverCalls -join ',' | Should -BeExactly "$($Script:scpMain)|user@contoso.com"
        }

        It 'Falls back to the domain URL and prefers the external EWS URL' {
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverSettingsXml -InternalUrl $Script:internalEws -ExternalUrl $Script:externalEws
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.EwsUrl.AbsoluteUri | Should -BeExactly $Script:externalEws
            $result.Source | Should -BeExactly "Autodiscover DNS $(Get-DnsUrl -Domain 'contoso.com') (EXPR)"
            $Script:autodiscoverCalls -join ',' | Should -BeExactly (@(
                    "$($Script:scpMain)|user@contoso.com",
                    "$($Script:scpRemote)|user@contoso.com",
                    "$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com") -join ',')
        }

        It 'Uses the domain URLs directly when no SCP exists' {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com' -AutodiscoverHost)|user@contoso.com"] = New-AutodiscoverSettingsXml -InternalUrl $Script:internalEws
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.EwsUrl.AbsoluteUri | Should -BeExactly $Script:internalEws
            $result.Source | Should -BeExactly "Autodiscover DNS $(Get-DnsUrl -Domain 'contoso.com' -AutodiscoverHost) (EXCH)"
            $Script:autodiscoverCalls -join ',' | Should -BeExactly (@(
                    "$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com",
                    "$(Get-DnsUrl -Domain 'contoso.com' -AutodiscoverHost)|user@contoso.com") -join ',')
        }

        It 'Lists every attempt when Autodiscover fails' {
            $failure = { Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com' } | Should -Throw -PassThru
            $message = $failure.Exception.Message
            $message | Should -Match ([regex]::Escape('Specify -EwsUrl'))
            foreach ($url in $Script:scpMain, $Script:scpRemote, (Get-DnsUrl -Domain 'contoso.com'), (Get-DnsUrl -Domain 'contoso.com' -AutodiscoverHost)) {
                $message | Should -Match ([regex]::Escape("$($url): The remote name could not be resolved."))
            }
            $Script:autodiscoverCalls | Should -HaveCount 4
        }

        It 'Follows an address redirect within the original domain to its DNS endpoints' {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'alias@contoso.com'
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|alias@contoso.com"] = New-AutodiscoverSettingsXml -ExternalUrl $Script:externalEws
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.EmailAddress | Should -BeExactly 'alias@contoso.com'
            $result.EwsUrl.AbsoluteUri | Should -BeExactly $Script:externalEws
            $result.Source | Should -BeExactly "Autodiscover DNS $(Get-DnsUrl -Domain 'contoso.com') (EXPR)"
            $Script:autodiscoverCalls -join ',' | Should -BeExactly (@(
                    "$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com",
                    "$(Get-DnsUrl -Domain 'contoso.com')|alias@contoso.com") -join ',')
        }

        It 'Treats a redirect to the original domain in other letter case as the same domain' {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'alias@CONTOSO.COM'
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|alias@CONTOSO.COM"] = New-AutodiscoverSettingsXml -ExternalUrl $Script:externalEws
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.EmailAddress | Should -BeExactly 'alias@CONTOSO.COM'
            $Script:autodiscoverCalls | Should -HaveCount 2
        }

        It 'Uses only SCP endpoints after a redirect to another domain' {
            $Script:autodiscoverResponses["$($Script:scpMain)|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'user@sales.contoso.com'
            $Script:autodiscoverResponses["$($Script:scpMain)|user@sales.contoso.com"] = New-AutodiscoverSettingsXml -InternalUrl $Script:internalEws
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.EmailAddress | Should -BeExactly 'user@sales.contoso.com'
            $result.Source | Should -BeExactly "Autodiscover SCP $($Script:scpMain) (EXCH)"
            $Script:autodiscoverCalls -join ',' | Should -BeExactly (@(
                    "$($Script:scpMain)|user@contoso.com",
                    "$($Script:scpMain)|user@sales.contoso.com") -join ',')
        }

        It 'Never contacts DNS endpoints of another domain after a redirect' {
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'user@sales.contoso.com'
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'sales.contoso.com')|user@sales.contoso.com"] = New-AutodiscoverSettingsXml -ExternalUrl $Script:externalEws
            $failure = { Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com' } | Should -Throw -PassThru
            $message = $failure.Exception.Message
            $message | Should -Match ([regex]::Escape('Specify -EwsUrl'))
            $message | Should -Match ([regex]::Escape('user@contoso.com redirected to user@sales.contoso.com'))
            $message | Should -Match ([regex]::Escape('DNS endpoints of sales.contoso.com are not used after a redirect from contoso.com'))
            @($Script:autodiscoverCalls | Where-Object { $_ -like '*sales.contoso.com/*' }) | Should -HaveCount 0
            @($Script:autodiscoverCalls | Where-Object { $_ -like '*|user@sales.contoso.com' }) -join ',' | Should -BeExactly (@(
                    "$($Script:scpMain)|user@sales.contoso.com",
                    "$($Script:scpRemote)|user@sales.contoso.com") -join ',')
        }

        It 'Detects an address redirect loop' {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'alias@contoso.com'
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|alias@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'User@Contoso.com'
            $failure = { Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com' } | Should -Throw -PassThru
            $failure.Exception.Message | Should -Match ([regex]::Escape('user@contoso.com redirected to alias@contoso.com'))
            $failure.Exception.Message | Should -Match ([regex]::Escape('Redirect loop at User@Contoso.com'))
            $failure.Exception.Message | Should -Match ([regex]::Escape('Specify -EwsUrl'))
            $Script:autodiscoverCalls | Should -HaveCount 2
        }

        It 'Stops after three addresses and reports every redirect' {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'alias1@contoso.com'
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|alias1@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'alias2@contoso.com'
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|alias2@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'alias3@contoso.com'
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|alias3@contoso.com"] = New-AutodiscoverSettingsXml -ExternalUrl $Script:externalEws
            $failure = { Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com' } | Should -Throw -PassThru
            $message = $failure.Exception.Message
            $message | Should -Match ([regex]::Escape('Specify -EwsUrl'))
            foreach ($step in 'user@contoso.com redirected to alias1@contoso.com', 'alias1@contoso.com redirected to alias2@contoso.com',
                'alias2@contoso.com redirected to alias3@contoso.com', 'Stopped after 3 addresses') {
                $message | Should -Match ([regex]::Escape($step))
            }
            $Script:autodiscoverCalls | Should -HaveCount 3
            @($Script:autodiscoverCalls | Where-Object { $_ -like '*|alias3@contoso.com' }) | Should -HaveCount 0
        }
        It 'Does not follow a URL redirect' {
            $Script:scpRecordsForTest = @()
            $redirectUrl = Get-DnsUrl -Domain 'sales.contoso.com' -AutodiscoverHost
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectUrl' -Target $redirectUrl
            $Script:autodiscoverResponses["$redirectUrl|user@contoso.com"] = New-AutodiscoverSettingsXml -ExternalUrl $Script:externalEws
            $failure = { Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com' } | Should -Throw -PassThru
            $failure.Exception.Message | Should -Match ([regex]::Escape("redirectUrl to '$redirectUrl' is not followed"))
            @($Script:autodiscoverCalls | Where-Object { $_ -like "$redirectUrl|*" }) | Should -HaveCount 0
            $Script:autodiscoverCalls | Should -HaveCount 2
        }

        It 'Continues with the next candidate after a URL redirect' {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectUrl' -Target (Get-DnsUrl -Domain 'sales.contoso.com')
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com' -AutodiscoverHost)|user@contoso.com"] = New-AutodiscoverSettingsXml -ExternalUrl $Script:externalEws
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.AutodiscoverUrl | Should -BeExactly (Get-DnsUrl -Domain 'contoso.com' -AutodiscoverHost)
        }

        It 'Rejects an invalid address without a request' {
            { Resolve-ExOPEwsUrl -EmailAddress 'not-an-address' } | Should -Throw -ExpectedMessage '*not a valid SMTP address*'
            $Script:autodiscoverCalls | Should -HaveCount 0
        }

        It 'Rejects a redirect to an invalid address' {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverRedirectXml -Action 'redirectAddr' -Target 'broken-address'
            { Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com' } | Should -Throw -ExpectedMessage '*not a valid SMTP address*'
        }

        It 'Accepts a DNS answer whose EWS host is <Name>' -ForEach @(
            @{ Name = 'the mailbox domain'; EwsUrl = 'https://contoso.com/EWS/Exchange.asmx'; Address = 'user@contoso.com' }
            @{ Name = 'a direct subdomain'; EwsUrl = 'https://mail.contoso.com/EWS/Exchange.asmx'; Address = 'user@contoso.com' }
            @{ Name = 'a deeper subdomain'; EwsUrl = 'https://ews.eu.contoso.com/EWS/Exchange.asmx'; Address = 'user@contoso.com' }
            @{ Name = 'in other letter case'; EwsUrl = 'https://MAIL.Contoso.COM/EWS/Exchange.asmx'; Address = 'user@CONTOSO.com' }
        ) {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|$Address"] = New-AutodiscoverSettingsXml -ExternalUrl $EwsUrl
            $result = Resolve-ExOPEwsUrl -EmailAddress $Address
            $result.EwsUrl.AbsoluteUri | Should -BeExactly ([uri]$EwsUrl).AbsoluteUri
            $result.AutodiscoverUrl | Should -BeExactly "https://$($Address.Split('@')[1])/autodiscover/autodiscover.xml"
            $Script:autodiscoverCalls | Should -HaveCount 1
        }

        It 'Rejects a DNS answer whose EWS host is <Name> and tries the next candidate' -ForEach @(
            @{ Name = 'a look-alike domain'; EwsHost = 'evilcontoso.com' }
            @{ Name = 'a look-alike subdomain'; EwsHost = 'mail.evilcontoso.com' }
            @{ Name = 'another domain'; EwsHost = 'mail.example.net' }
            @{ Name = 'a domain that only starts like the mailbox domain'; EwsHost = 'contoso.com.example.net' }
        ) {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverSettingsXml -ExternalUrl "https://$EwsHost/EWS/Exchange.asmx"
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com' -AutodiscoverHost)|user@contoso.com"] = New-AutodiscoverSettingsXml -ExternalUrl $Script:externalEws
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.EwsUrl.AbsoluteUri | Should -BeExactly $Script:externalEws
            $result.AutodiscoverUrl | Should -BeExactly (Get-DnsUrl -Domain 'contoso.com' -AutodiscoverHost)
            $Script:autodiscoverCalls | Should -HaveCount 2
        }

        It 'Lists a rejected DNS answer when no candidate is usable' {
            $Script:scpRecordsForTest = @()
            $Script:autodiscoverResponses["$(Get-DnsUrl -Domain 'contoso.com')|user@contoso.com"] = New-AutodiscoverSettingsXml -ExternalUrl 'https://mail.evilcontoso.com/EWS/Exchange.asmx'
            $failure = { Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com' } | Should -Throw -PassThru
            $failure.Exception.Message | Should -Match ([regex]::Escape(
                    "$(Get-DnsUrl -Domain 'contoso.com'): EWS URL host 'mail.evilcontoso.com' is outside 'contoso.com' and was not used"))
            $failure.Exception.Message | Should -Match ([regex]::Escape('Specify -EwsUrl'))
        }

        It 'Accepts an SCP answer with an EWS host outside the mailbox domain' {
            $Script:autodiscoverResponses["$($Script:scpMain)|user@contoso.com"] = New-AutodiscoverSettingsXml -InternalUrl 'https://mail.example.net/EWS/Exchange.asmx'
            $result = Resolve-ExOPEwsUrl -EmailAddress 'user@contoso.com'
            $result.EwsUrl.AbsoluteUri | Should -BeExactly 'https://mail.example.net/EWS/Exchange.asmx'
            $result.Source | Should -BeExactly "Autodiscover SCP $($Script:scpMain) (EXCH)"
        }
    }

    Context 'Resolve-ExOPSendPermission' {
        BeforeAll {
            $Script:callerSid = 'S-1-5-21-1-2-3-1101'
            $Script:groupSid = 'S-1-5-21-1-2-3-2201'
            $Script:otherSid = 'S-1-5-21-1-2-3-9999'
            function New-Owner {
                param ([object[]]$SendAs = @(), [string[]]$DelegateSids = @(), [string]$MasterSid = '')
                [PSCustomObject]@{ Sid = 'S-1-5-21-1-2-3-1000'; MasterSid = $MasterSid; DelegateSids = $DelegateSids; SendAs = $SendAs }
            }
            function New-Ace {
                param ([string]$Sid, [bool]$Allow = $true, [bool]$Inherited = $false)
                [PSCustomObject]@{ Sid = $Sid; Allow = $Allow; Inherited = $Inherited }
            }
            $Script:caller = [PSCustomObject]@{ Sid = $Script:callerSid; GroupSids = @($Script:groupSid) }
        }

        It 'Returns <Expected> when <Name>' -ForEach @(
            @{ Name = 'the caller is the owner'; Expected = 'Owner'; Owner = { [PSCustomObject]@{ Sid = $Script:callerSid; MasterSid = ''; DelegateSids = @(); SendAs = @() } } }
            @{ Name = 'the caller is the linked master account'; Expected = 'Owner'; Owner = { New-Owner -MasterSid $Script:callerSid } }
            @{ Name = 'the caller has an explicit Send As'; Expected = 'SendAs'; Owner = { New-Owner -SendAs @(New-Ace $Script:callerSid) } }
            @{ Name = 'a group of the caller has an inherited Send As'; Expected = 'SendAs'; Owner = { New-Owner -SendAs @(New-Ace $Script:groupSid -Inherited $true) } }
            @{ Name = 'Everyone has Send As'; Expected = 'SendAs'; Owner = { New-Owner -SendAs @(New-Ace 'S-1-1-0') } }
            @{ Name = 'an explicit deny beats an explicit allow'; Expected = 'None'; Owner = { New-Owner -SendAs @((New-Ace $Script:callerSid), (New-Ace $Script:groupSid -Allow $false)) } }
            @{ Name = 'an explicit deny beats an inherited allow'; Expected = 'None'; Owner = { New-Owner -SendAs @((New-Ace $Script:callerSid -Inherited $true), (New-Ace $Script:callerSid -Allow $false)) } }
            @{ Name = 'an explicit allow beats an inherited deny'; Expected = 'SendAs'; Owner = { New-Owner -SendAs @((New-Ace $Script:callerSid), (New-Ace $Script:groupSid -Allow $false -Inherited $true)) } }
            @{ Name = 'a deny for Send As still allows Send on Behalf'; Expected = 'SendOnBehalf'; Owner = { New-Owner -SendAs @(New-Ace $Script:callerSid -Allow $false) -DelegateSids @($Script:callerSid) } }
            @{ Name = 'the caller is a Send on Behalf delegate'; Expected = 'SendOnBehalf'; Owner = { New-Owner -DelegateSids @($Script:otherSid, $Script:callerSid) } }
            @{ Name = 'a group of the caller is a Send on Behalf delegate'; Expected = 'SendOnBehalf'; Owner = { New-Owner -DelegateSids @($Script:groupSid) } }
            @{ Name = 'only other accounts have rights'; Expected = 'None'; Owner = { New-Owner -SendAs @(New-Ace $Script:otherSid) -DelegateSids @($Script:otherSid) } }
            @{ Name = 'nobody has rights'; Expected = 'None'; Owner = { New-Owner } }
        ) {
            Resolve-ExOPSendPermission -Caller $Script:caller -Owner (& $Owner) | Should -BeExactly $Expected
        }
    }

    Context 'ConvertFrom-ExOPSendAsRules' {
        BeforeAll {
            $Script:sid = New-Object Security.Principal.SecurityIdentifier('S-1-5-21-1-2-3-1101')
            function New-Rule {
                param (
                    [DirectoryServices.ActiveDirectoryRights]$Rights = 'ExtendedRight', [Guid]$ObjectType = $Script:SendAsRightGuid,
                    [Guid]$InheritedObjectType = [Guid]::Empty, [bool]$Inherited = $false, [string]$Propagation = 'None', [string]$Type = 'Allow'
                )
                [PSCustomObject]@{
                    ActiveDirectoryRights = $Rights; ObjectType = $ObjectType; InheritedObjectType = $InheritedObjectType; IsInherited = $Inherited
                    PropagationFlags = [Security.AccessControl.PropagationFlags]$Propagation; AccessControlType = $Type; IdentityReference = $Script:sid
                }
            }
        }

        It 'Keeps <Name>' -ForEach @(
            @{ Name = 'an explicit Send As allow'; Rule = { New-Rule } }
            @{ Name = 'an explicit Send As deny'; Rule = { New-Rule -Type 'Deny' } }
            @{ Name = 'all extended rights'; Rule = { New-Rule -ObjectType ([Guid]::Empty) } }
            @{ Name = 'full control'; Rule = { New-Rule -Rights 'GenericAll' -ObjectType ([Guid]::Empty) } }
            @{ Name = 'Send As inherited for user objects'; Rule = { New-Rule -Inherited $true -InheritedObjectType 'bf967aba-0de6-11d0-a285-00aa003049e2' } }
        ) {
            $entries = @(ConvertFrom-ExOPSendAsRules -Rules @(& $Rule))
            $entries | Should -HaveCount 1
            $entries[0].Sid | Should -BeExactly 'S-1-5-21-1-2-3-1101'
        }

        It 'Ignores <Name>' -ForEach @(
            @{ Name = 'another extended right'; Rule = { New-Rule -ObjectType '00299570-246d-11d0-a768-00aa006e0529' } }
            @{ Name = 'read and write rights'; Rule = { New-Rule -Rights 'ReadProperty, WriteProperty' } }
            @{ Name = 'Send As inherited for group objects'; Rule = { New-Rule -Inherited $true -InheritedObjectType 'bf967a9c-0de6-11d0-a285-00aa003049e2' } }
            @{ Name = 'an inherit-only entry'; Rule = { New-Rule -Propagation 'InheritOnly' } }
        ) {
            @(ConvertFrom-ExOPSendAsRules -Rules @(& $Rule)) | Should -HaveCount 0
        }
    }

    Context 'Get-ExOPSendPermission and Assert-ExOPSendPermission' {
        BeforeEach {
            Mock Get-ExOPCallerIdentity { [PSCustomObject]@{ Sid = 'S-1-5-21-1-2-3-1101'; GroupSids = @() } }
            Mock Get-ExOPMailboxSendRights { [PSCustomObject]@{ Sid = 'S-1-5-21-1-2-3-1000'; MasterSid = ''; DelegateSids = @(); SendAs = @() } }
        }

        It 'Does not read Active Directory for impersonation' {
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx' -Impersonation
            (Get-ExOPSendPermission -Session $session -Mailbox 'owner@contoso.com').Mode | Should -BeExactly 'Impersonation'
            Should -Invoke Get-ExOPMailboxSendRights -Times 0 -Exactly -Scope It
        }

        It 'Reads Active Directory once per mailbox' {
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            foreach ($mailbox in 'owner@contoso.com', 'OWNER@contoso.com', 'other@contoso.com') {
                (Get-ExOPSendPermission -Session $session -Mailbox $mailbox).Mode | Should -BeExactly 'None'
            }
            Should -Invoke Get-ExOPMailboxSendRights -Times 2 -Exactly -Scope It
        }

        It 'Reports Unknown when Active Directory cannot be read' {
            Mock Get-ExOPMailboxSendRights { throw 'The server is not operational.' }
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            $permission = Get-ExOPSendPermission -Session $session -Mailbox 'owner@contoso.com'
            $permission.Mode | Should -BeExactly 'Unknown'
            $permission.Error | Should -BeExactly 'The server is not operational.'
        }

        It 'Passes the session credential to both directory reads' {
            $credential = New-Object PSCredential('CONTOSO\delegate', (New-Object Security.SecureString))
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx' -Credential $credential
            $null = Get-ExOPSendPermission -Session $session -Mailbox 'owner@contoso.com'
            Should -Invoke Get-ExOPCallerIdentity -Times 1 -Exactly -Scope It -ParameterFilter { $Credential.UserName -eq 'CONTOSO\delegate' }
            Should -Invoke Get-ExOPMailboxSendRights -Times 1 -Exactly -Scope It -ParameterFilter { $Credential.UserName -eq 'CONTOSO\delegate' -and $Mailbox -eq 'owner@contoso.com' }
        }

        It 'Throws <Code> for mode <Mode>' -ForEach @(
            @{ Mode = 'None'; Code = 'SendPermissionMissing'; Message = '*has neither Send on Behalf nor Send As for owner@contoso.com*' }
            @{ Mode = 'Unknown'; Code = 'SendPermissionUnknown'; Message = '*could not be checked in Active Directory: boom*' }
        ) {
            Mock Get-ExOPSendPermission { [PSCustomObject]@{ Mode = $Mode; Error = 'boom' } }
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            $failure = $null
            try { Assert-ExOPSendPermission -Session $session -Mailbox 'owner@contoso.com' } catch { $failure = $_ }
            $failure | Should -Not -BeNullOrEmpty
            $failure.Exception.Message | Should -BeLike $Message
            $failure.Exception.Data['EwsResponseCode'] | Should -BeExactly $Code
        }

        It 'Allows mode <_>' -ForEach @('Impersonation', 'Owner', 'SendAs', 'SendOnBehalf') {
            $mode = $_
            Mock Get-ExOPSendPermission { [PSCustomObject]@{ Mode = $mode; Error = '' } }
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            { Assert-ExOPSendPermission -Session $session -Mailbox 'owner@contoso.com' } | Should -Not -Throw
        }

        It 'Skips the check with -SkipSendPermissionCheck' {
            Mock Get-ExOPSendPermission { [PSCustomObject]@{ Mode = 'None'; Error = '' } }
            $session = New-ExOPCalendarSession -EwsUrl 'https://mail.contoso.com/EWS/Exchange.asmx'
            { Assert-ExOPSendPermission -Session $session -Mailbox 'owner@contoso.com' -SkipSendPermissionCheck } | Should -Not -Throw
            Should -Invoke Get-ExOPSendPermission -Times 0 -Exactly -Scope It
        }
    }

    Context 'ConvertTo-ExOPLdapFilterValue' {
        It 'Escapes LDAP filter characters' {
            ConvertTo-ExOPLdapFilterValue -Value 'a*b(c)d\e' | Should -BeExactly 'a\2ab\28c\29d\5ce'
        }
    }
}
