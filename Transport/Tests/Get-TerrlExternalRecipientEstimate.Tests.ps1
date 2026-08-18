# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore Terrl

[CmdletBinding()]
param()

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Get-TerrlExternalRecipientEstimate.ps1 -DefineFunctionsOnly

    function Get-TerrlTraceRow {
        param(
            [string]$MessageTraceId,
            [string]$MessageId,
            [AllowNull()]
            [string]$SenderAddress,
            [string]$RecipientAddress,
            [string]$Status = 'Delivered',
            [datetime]$Received = [datetime]'2026-08-05T12:00:00Z'
        )

        [PSCustomObject]@{
            MessageTraceId   = $MessageTraceId
            MessageId        = $MessageId
            SenderAddress    = $SenderAddress
            RecipientAddress = $RecipientAddress
            Status           = $Status
            Received         = $Received
        }
    }
}

Describe 'Get-TerrlExternalRecipientEstimate' {
    Context 'Measure-TerrlFromTraceRows classification' {
        It 'excludes accepted-domain recipients and counts external rows' {
            $rows = @(
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'user@contoso.com'
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'user@example.net'
            )

            $result = Measure-TerrlFromTraceRows -Rows $rows -AcceptedDomain @(
                ' CONTOSO.COM '
                '@tenant.onmicrosoft.com'
            )

            $result.TraceRows | Should -Be 2
            $result.ExternalRecipientsCounted | Should -Be 1
            $result.AcceptedRecipientRows | Should -Be 1
            $result.DistinctExternalRecipients | Should -Be 1
            $result.DistinctOutboundMessages | Should -Be 1
        }

        It 'deduplicates each message-recipient pair case-insensitively' {
            $rows = @(
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'User@Example.net'
                Get-TerrlTraceRow -MessageTraceId 'TRACE-1' -MessageId 'MESSAGE-1' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'user@example.NET'
            )

            $result = Measure-TerrlFromTraceRows -Rows $rows -AcceptedDomain 'contoso.com'

            $result.ExternalRecipientsCounted | Should -Be 1
            $result.DistinctExternalRecipients | Should -Be 1
            $result.DistinctOutboundMessages | Should -Be 1
        }

        It 'counts repeat messages to the same external recipient separately' {
            $rows = @(
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'user@example.net'
                Get-TerrlTraceRow -MessageTraceId 'trace-2' -MessageId 'message-2' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'user@example.net'
            )

            $result = Measure-TerrlFromTraceRows -Rows $rows -AcceptedDomain 'contoso.com'

            $result.ExternalRecipientsCounted | Should -Be 2
            $result.DistinctExternalRecipients | Should -Be 1
            $result.DistinctOutboundMessages | Should -Be 2
        }

        It 'excludes expanded distribution-group placeholder rows' {
            $rows = @(
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'group@example.net' `
                    -Status ' Expanded '
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'member@example.net'
            )

            $result = Measure-TerrlFromTraceRows -Rows $rows -AcceptedDomain 'contoso.com'

            $result.ExternalRecipientsCounted | Should -Be 1
            ($result.Exclusions | Where-Object Reason -EQ 'ExpandedDistributionGroup').RecipientRows |
                Should -Be 1
        }

        It 'excludes null and built-in system senders' {
            $rows = @(
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress '<>' -RecipientAddress 'one@example.net'
                Get-TerrlTraceRow -MessageTraceId 'trace-2' -MessageId 'message-2' `
                    -SenderAddress 'Postmaster@contoso.com' -RecipientAddress 'two@example.net'
                Get-TerrlTraceRow -MessageTraceId 'trace-3' -MessageId 'message-3' `
                    -SenderAddress 'MicrosoftExchange329e71ec88ae4615bbc36ab6ce41109e@contoso.com' `
                    -RecipientAddress 'three@example.net'
                Get-TerrlTraceRow -MessageTraceId 'trace-4' -MessageId 'message-4' `
                    -SenderAddress 'microsoftexchange329e71ec88ae4615bbc36ab6ce41109e@contoso.com' `
                    -RecipientAddress 'four@example.net'
                Get-TerrlTraceRow -MessageTraceId 'trace-5' -MessageId 'message-5' `
                    -SenderAddress 'sender@contoso.com' -RecipientAddress 'five@example.net'
            )

            $result = Measure-TerrlFromTraceRows -Rows $rows -AcceptedDomain 'contoso.com' `
                -ExcludeNullSender $true

            $result.ExternalRecipientsCounted | Should -Be 1
            ($result.Exclusions | Where-Object Reason -EQ 'NullSender (NDR/DSN/system)').RecipientRows |
                Should -Be 1
            ($result.Exclusions | Where-Object Reason -EQ 'SystemSender (NDR/DSN)').RecipientRows |
                Should -Be 3
        }

        It 'counts a null sender when null-sender exclusion is disabled' {
            $row = Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                -SenderAddress $null -RecipientAddress 'user@example.net'

            $result = Measure-TerrlFromTraceRows -Rows @($row) -AcceptedDomain 'contoso.com' `
                -ExcludeNullSender $false

            $result.ExternalRecipientsCounted | Should -Be 1
            $result.TopSenders[0].Sender | Should -Be '(null sender)'
        }

        It 'excludes an EXO journal row only when sender and journal destination match' {
            $rows = @(
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress '<JournalSender@contoso.com>' `
                    -RecipientAddress '<Archive@journal.example>'
                Get-TerrlTraceRow -MessageTraceId 'trace-2' -MessageId 'message-2' `
                    -SenderAddress 'journalsender@contoso.com' `
                    -RecipientAddress 'other@journal.example'
                Get-TerrlTraceRow -MessageTraceId 'trace-3' -MessageId 'message-3' `
                    -SenderAddress 'other@contoso.com' `
                    -RecipientAddress 'archive@journal.example'
            )

            $result = Measure-TerrlFromTraceRows -Rows $rows -AcceptedDomain 'contoso.com' `
                -JournalRecipient 'archive@journal.example' `
                -JournalReportSender 'journalsender@contoso.com'

            $result.ExternalRecipientsCounted | Should -Be 2
            $result.ExchangeOnlineJournalRows | Should -Be 1
            ($result.Exclusions | Where-Object Reason -EQ 'ExchangeOnlineJournalReport').RecipientRows |
                Should -Be 1
        }

        It 'returns normalized top sender and recipient-domain aggregates' {
            $rows = @(
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress 'SenderA@Contoso.com' -RecipientAddress 'one@Example.NET'
                Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                    -SenderAddress 'SenderA@Contoso.com' -RecipientAddress 'two@example.net'
                Get-TerrlTraceRow -MessageTraceId 'trace-2' -MessageId 'message-2' `
                    -SenderAddress 'senderb@contoso.com' -RecipientAddress 'three@Other.org'
            )

            $result = Measure-TerrlFromTraceRows -Rows $rows -AcceptedDomain 'contoso.com'

            $result.TopSenders[0].Sender | Should -Be 'sendera@contoso.com'
            $result.TopSenders[0].ExternalRecipients | Should -Be 2
            $result.TopSenders[0].Messages | Should -Be 1
            $result.TopSenders[0].PercentOfTotal | Should -Be 66.7
            $result.TopRecipientDomains[0].RecipientDomain | Should -Be 'example.net'
            $result.TopRecipientDomains[0].ExternalRecipients | Should -Be 2
            $result.TopRecipientDomains[0].PercentOfTotal | Should -Be 66.7
        }
    }

    Context 'Get-TerrlAddressDomain parsing' {
        It 'normalizes valid addresses and rejects unparsable addresses' {
            Get-TerrlAddressDomain -Address ' <User@EXAMPLE.NET> ' | Should -Be 'example.net'
            Get-TerrlAddressDomain -Address 'alias@route@Example.ORG' | Should -Be 'example.org'
            Get-TerrlAddressDomain -Address $null | Should -BeNullOrEmpty
            Get-TerrlAddressDomain -Address '<>' | Should -BeNullOrEmpty
            Get-TerrlAddressDomain -Address 'missing-at-sign' | Should -BeNullOrEmpty
            Get-TerrlAddressDomain -Address 'user@' | Should -BeNullOrEmpty
            Get-TerrlAddressDomain -Address 'user@   ' | Should -BeNullOrEmpty
        }
    }

    Context 'Get-TerrlTraceRows continuation' {
        It 'uses the final row continuation values until a short page is returned' {
            $Script:traceCalls = [System.Collections.Generic.List[object]]::new()
            $firstReceived = [datetime]'2026-08-05T11:00:00Z'
            $traceCommand = {
                param($startDate, $endDate, $pageSize, $startingRecipientAddress)

                $Script:traceCalls.Add([PSCustomObject]@{
                        StartDate                = $startDate
                        EndDate                  = $endDate
                        PageSize                 = $pageSize
                        StartingRecipientAddress = $startingRecipientAddress
                    })

                if ($Script:traceCalls.Count -eq 1) {
                    return @(
                        Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                            -SenderAddress 'sender@contoso.com' -RecipientAddress 'one@example.net' `
                            -Received ([datetime]'2026-08-05T11:30:00Z')
                        Get-TerrlTraceRow -MessageTraceId 'trace-2' -MessageId 'message-2' `
                            -SenderAddress 'sender@contoso.com' -RecipientAddress 'two@example.net' `
                            -Received $firstReceived
                    )
                }

                return @(
                    Get-TerrlTraceRow -MessageTraceId 'trace-3' -MessageId 'message-3' `
                        -SenderAddress 'sender@contoso.com' -RecipientAddress 'three@example.net' `
                        -Received ([datetime]'2026-08-05T10:30:00Z')
                )
            }

            $startDate = [datetime]'2026-08-05T10:00:00Z'
            $endDate = [datetime]'2026-08-05T12:00:00Z'
            $result = Get-TerrlTraceRows -StartDate $startDate -EndDate $endDate -PageSize 2 `
                -TraceCommand $traceCommand

            $result.Count | Should -Be 3
            $Script:traceCalls.Count | Should -Be 2
            $Script:traceCalls[0].StartDate | Should -Be $startDate
            $Script:traceCalls[0].EndDate | Should -Be $endDate
            $Script:traceCalls[0].PageSize | Should -Be 2
            $Script:traceCalls[0].StartingRecipientAddress | Should -BeNullOrEmpty
            $Script:traceCalls[1].EndDate | Should -Be $firstReceived
            $Script:traceCalls[1].StartingRecipientAddress | Should -Be 'two@example.net'
        }

        It 'throws instead of looping when the continuation cursor repeats' {
            $received = [datetime]'2026-08-05T11:00:00Z'
            $traceCommand = {
                param($startDate, $endDate, $pageSize, $startingRecipientAddress)

                return @(
                    Get-TerrlTraceRow -MessageTraceId 'trace-1' -MessageId 'message-1' `
                        -SenderAddress 'sender@contoso.com' -RecipientAddress 'one@example.net' `
                        -Received ([datetime]'2026-08-05T11:30:00Z')
                    Get-TerrlTraceRow -MessageTraceId 'trace-2' -MessageId 'message-2' `
                        -SenderAddress 'sender@contoso.com' -RecipientAddress 'two@example.net' `
                        -Received $received
                )
            }

            {
                Get-TerrlTraceRows -StartDate ([datetime]'2026-08-05T10:00:00Z') `
                    -EndDate ([datetime]'2026-08-05T12:00:00Z') -PageSize 2 `
                    -TraceCommand $traceCommand
            } | Should -Throw '*same continuation cursor more than once*'
        }
    }
}
