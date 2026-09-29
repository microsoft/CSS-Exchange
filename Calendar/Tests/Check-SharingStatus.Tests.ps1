# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Script parameters are set to exercise dot-sourced functions')]
[CmdletBinding()]
param()

# cSpell:ignore Sharee Sharees
BeforeAll {
    $Script:parentPath = Split-Path -Parent $PSScriptRoot

    function Get-Mailbox { param($Identity, $ErrorAction) }
    function Get-MailboxFolderStatistics { param($Identity, $FolderScope, $ErrorAction) }
    function Get-MailboxFolderPermission { param($Identity, $ErrorAction) }
    function Get-MailboxPermission { param($Identity, $ErrorAction) }
    function Get-MailboxCalendarFolder { param($Identity, $ErrorAction) }
    function Get-CalendarActiveSharingInformation { param($Identity, $ErrorAction) }
    function Get-CalendarEntries { param($Identity, $ErrorAction) }
    function Export-MailboxDiagnosticLogs { param($Identity, $ComponentName) }

    . "$Script:parentPath\Check-SharingStatus.ps1" `
        -Owner "owner@contoso.com" `
        -Receiver "receiver@contoso.com" `
        -SkipMainExecution

    $Script:expectedRuleIds = @(
        "SHR100", "SHR101", "SHR110", "SHR111", "SHR120", "SHR121", "SHR122", "SHR123",
        "SHR130",
        "SHR200", "SHR201", "SHR210", "SHR211", "SHR212", "SHR213", "SHR214", "SHR220",
        "SHR230", "SHR231", "SHR232", "SHR233", "SHR240", "SHR241", "SHR242", "SHR243",
        "SHR300", "SHR301", "SHR310", "SHR311", "SHR312", "SHR320", "SHR321", "SHR322",
        "SHR323", "SHR400", "SHR401", "SHR402", "SHR403", "SHR410", "SHR411", "SHR412", "SHR413",
        "SHR420", "SHR430", "SHR431", "SHR432", "SHR433"
    )
    $Script:collectorNames = @(
        "OwnerMailbox", "ReceiverMailbox", "OwnerFolderStatistics", "ReceiverFolderStatistics",
        "OwnerCalendarPermissions", "OwnerMailboxPermissions", "OwnerInviteLog", "OwnerCalendarFolder",
        "ActiveSharing", "ReceiverAcceptLog", "CalendarEntries", "ReceiverLocalCalendarFolder",
        "InternetCalendar"
    )

    function Initialize-SharingTestState {
        $script:SharingFindings = [System.Collections.Generic.List[object]]::new()
        $script:RunStartedAt = [DateTime]::new(2022, 1, 2, 13, 22, 0)
        $script:SharingFindingRuleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $script:ConsoleFindingEvidence = @{}
        $script:CollectorStatuses = [ordered]@{}
        foreach ($collectorName in $Script:collectorNames) {
            $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{
                status = "NotRun"
                error  = $null
            }
        }
        $script:CollectionErrors = [System.Collections.Generic.List[object]]::new()
        $script:EvaluationErrors = [System.Collections.Generic.List[object]]::new()
        $script:SanitizedIdentityMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $script:SanitizedIdentitySequence = 0
        $script:IncludeSensitiveData = $false
        $script:ModernSharingOnly = $true
        $script:Owner = "owner@contoso.com"
        $script:Receiver = "receiver@contoso.com"
        $script:PIIAccess = $true
        $script:ModernSharing = $false
        $script:SharingType = $null
        $script:OwnerMB = $null
        $script:ReceiverMB = $null
        $script:OwnerInviteData = @()
        $script:OwnerInviteCheckAvailable = $false
        $script:OwnerCalendarPerms = @()
        $script:OwnerCalendarPermsAvailable = $false
        $script:OwnerCalendarStats = @()
        $script:OwnerSelectedCalendar = $null
        $script:OwnerCalendarFolder = $null
        $script:OwnerCalendarFolderIdentity = $null
        $script:OwnerCalendarRootName = $null
        $script:OwnerCalendarLeafName = $null
        $script:OwnerCalendarLeafNameCandidate = $null
        $script:OwnerCalendarFolderPathSpecified = $false
        $script:NormalizedOwnerCalendarFolderPath = $null
        $script:RequestedOwnerCalendarLeafName = $null
        $script:ReceiverAcceptLogEntries = @()
        $script:ReceiverSelectedAcceptLogEntries = @()
        $script:OwnerActiveReceiver = $null
        $script:OwnerActiveSharingAvailable = $false
        $script:ReceiverMatchedCalendar = $null
        $script:ReceiverCalendarCandidates = @()
        $script:CalendarStatisticsComparisonPerformed = $false
        $script:CalendarStatisticsComparison = $null
        $script:FatalPrerequisiteFailure = $null
    }

    function Get-CalendarFlagTestValue {
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        $flag = [PSCustomObject]@{
            Name = $Name
        }
        $flag | Add-Member -MemberType ScriptMethod -Name ToString -Value {
            return $this.Name
        } -Force
        return $flag
    }

    function Initialize-OwnerMocks {
        $Script:ownerMailbox = [PSCustomObject]@{
            DisplayName            = "Owner Display"
            OrganizationalUnitRoot = "OU1"
            GrantSendOnBehalfTo    = @()
        }
        $Script:ownerCalendarFolder = [PSCustomObject]@{
            Identity                        = "owner@contoso.com:\Calendar"
            CreationTime                    = (Get-Date).AddDays(-60)
            PublishEnabled                  = $false
            ExtendedFolderFlags             = @("SharedOut", "ExchangeShareFolder")
            CalendarSharingFolderFlags      = @("None")
            CalendarSharingOwnerSmtpAddress = $null
            CalendarSharingPermissionLevel  = "Reviewer"
            SharingLevelOfDetails           = "FullDetails"
            SharingPermissionFlags          = @("Delegate")
            LastAttemptedSyncTime           = Get-Date
            LastSuccessfulSyncTime          = Get-Date
            SharedCalendarSyncStartDate     = (Get-Date).AddDays(-30)
        }
        $Script:activeSharees = @(
            [PSCustomObject]@{
                EmailAddress           = "receiver@contoso.com"
                SharingPermissionFlags = @("Delegate")
                ActiveShareeFlags      = @("None")
                LastSyncTime           = Get-Date
            }
        )

        Mock Get-Mailbox { $Script:ownerMailbox }
        Mock Get-MailboxFolderStatistics {
            [PSCustomObject]@{
                FolderType             = "Calendar"
                Name                   = "Calendar"
                FolderPath             = "/Calendar"
                FolderSize             = "1 KB (1,024 bytes)"
                FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                VisibleItemsInFolder   = 10
            }
        }
        Mock Get-MailboxFolderPermission { @() }
        Mock Get-MailboxPermission { @() }
        Mock ProcessCalendarSharingInviteLogs {}
        Mock Get-MailboxCalendarFolder { $Script:ownerCalendarFolder }
        Mock Get-CalendarActiveSharingInformation {
            [PSCustomObject]@{
                ActiveShareesDataSet = [PSCustomObject]@{
                    Sharees = @($Script:activeSharees)
                }
            }
        }
    }

    function Initialize-ReceiverMocks {
        $Script:receiverMailbox = [PSCustomObject]@{
            DisplayName            = "Receiver Display"
            OrganizationalUnitRoot = "OU1"
        }
        $Script:receiverStats = @(
            [PSCustomObject]@{
                FolderType             = "Calendar"
                Name                   = "Calendar"
                FolderPath             = "/Calendar"
                FolderSize             = "1 KB"
                FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                VisibleItemsInFolder   = 10
            },
            [PSCustomObject]@{
                FolderType             = "User Created"
                Name                   = "Owner Display"
                FolderPath             = "/Owner Display"
                FolderSize             = "1 KB"
                FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                VisibleItemsInFolder   = 10
            }
        )
        $Script:calendarEntries = @(
            [PSCustomObject]@{
                CalendarGroupName = "People's calendars"
                CalendarName      = "Owner Display"
                OwnerEmailAddress = "owner@contoso.com"
                SharingModelType  = "New"
                IsOrphanedEntry   = $false
            }
        )
        $now = Get-Date
        $Script:receiverCalendarFolder = [PSCustomObject]@{
            Identity                        = "receiver:\Calendar\Owner Display"
            CreationTime                    = $now.AddDays(-30)
            ExtendedFolderFlags             = @("SharedIn", "ExchangeShareFolder")
            CalendarSharingOwnerSmtpAddress = "owner@contoso.com"
            SharingPermissionFlags          = @("Delegate")
            LastAttemptedSyncTime           = $now
            LastSuccessfulSyncTime          = $now
            SharedCalendarSyncStartDate     = $now.AddDays(-30)
        }

        Mock Get-Mailbox { $Script:receiverMailbox }
        Mock Get-MailboxFolderStatistics { @($Script:receiverStats) }
        Mock ProcessCalendarSharingAcceptLogs {}
        Mock ProcessInternetCalendarLogs {}
        Mock Get-CalendarEntries { @($Script:calendarEntries) }
        Mock Get-MailboxCalendarFolder { $Script:receiverCalendarFolder }

        $script:OwnerMB = [PSCustomObject]@{
            DisplayName            = "Owner Display"
            OrganizationalUnitRoot = "OU1"
        }
        $script:OwnerCalendarPerms = @()
        $script:OwnerCalendarPermsAvailable = $false
        $script:OwnerActiveReceiver = $null
        $script:OwnerActiveSharingAvailable = $false
    }
}

Describe "Check-SharingStatus structured diagnostics" {
    BeforeEach {
        Initialize-SharingTestState
    }

    Context "Structured finding contract and rule catalog" {
        It "creates the stable contract with catalog-owned values and structured evidence" {
            Add-SharingFinding -RuleId "SHR301" -Status Detected -Area "Invite" -Evidence @{
                owner    = "owner@contoso.com"
                receiver = "receiver@contoso.com"
                count    = 0
            }

            $finding = $script:SharingFindings[0]
            $finding.PSObject.Properties.Name | Should -Be @(
                "ruleId", "severity", "status", "title", "evidence", "recommendedNextStep", "area"
            )
            $finding.ruleId | Should -Be "SHR301"
            $finding.severity | Should -Be "Error"
            $finding.status | Should -Be "Detected"
            $finding.title | Should -Be "Pair-specific sharing invite is missing"
            $finding.evidence.owner | Should -Be "Owner"
            $finding.evidence.receiver | Should -Be "Receiver"
            $finding.evidence.count | Should -Be 0
            $finding.recommendedNextStep | Should -Not -BeNullOrEmpty
            $finding.area | Should -Be "Invite"
        }

        It "maps legacy call arguments to a registered rule and NotEvaluated status" {
            Add-SharingFinding -Severity Warning -Area "Owner" `
                -Issue "The owner invite-log check was unavailable." `
                -Evidence "Access denied" -RecommendedNextStep "Retry" -Incomplete

            $script:SharingFindings.Count | Should -Be 1
            $script:SharingFindings[0].ruleId | Should -Be "SHR300"
            $script:SharingFindings[0].status | Should -Be "NotEvaluated"
        }

        It "rejects unregistered findings" {
            {
                Add-SharingFinding -Severity Warning -Area "Unknown" -Issue "Unknown issue" `
                    -Evidence $null -RecommendedNextStep "None"
            } | Should -Throw "No sharing rule is registered*"
        }

        It "contains the complete unique catalog with supported values" {
            @($script:SharingRuleCatalog.RuleId | Sort-Object) | Should -Be @($Script:expectedRuleIds | Sort-Object)
            @($script:SharingRuleCatalog.RuleId | Sort-Object -Unique).Count | Should -Be $Script:expectedRuleIds.Count
            @($script:SharingRuleCatalog | Where-Object {
                    $_.RuleId -notmatch "^SHR\d{3}$" -or
                    $_.Severity -notin @("Critical", "Error", "Warning", "Information") -or
                    [string]::IsNullOrWhiteSpace($_.Title) -or
                    [string]::IsNullOrWhiteSpace($_.NextStep)
                }).Count | Should -Be 0
        }

        It "finalizes every rule exactly once with only supported statuses" {
            Complete-SharingFindings

            $script:SharingFindings.Count | Should -Be $Script:expectedRuleIds.Count
            @($script:SharingFindings.ruleId | Sort-Object -Unique).Count | Should -Be $Script:expectedRuleIds.Count
            @($script:SharingFindings | Where-Object {
                    $_.status -notin @("Detected", "NotDetected", "NotEvaluated", "NotApplicable")
                }).Count | Should -Be 0
        }

        It "does not duplicate or replace an existing finding during repeat updates and finalization" {
            Add-SharingFinding -RuleId "SHR121" -Status Detected -Evidence @{ extendedFolderFlags = @() }
            Add-SharingFinding -RuleId "SHR121" -Status NotDetected -Evidence @{}
            Complete-SharingFindings
            Complete-SharingFindings

            @($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR121").Count | Should -Be 1
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR121").status | Should -Be "Detected"
            $script:SharingFindings.Count | Should -Be $Script:expectedRuleIds.Count
        }

        It "retains healthy states and classifies optional old-model and InternetCalendar rules as NotApplicable" {
            foreach ($collectorName in $Script:collectorNames) {
                $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "Success"; error = $null }
            }
            $script:ReceiverCalendarCandidates = @([PSCustomObject]@{ Name = "Owner Display" })
            $script:ReceiverMatchedCalendar = $script:ReceiverCalendarCandidates[0]
            $script:CalendarStatisticsComparisonPerformed = $true
            Complete-SharingFindings

            @($script:SharingFindings | Where-Object -Property status -EQ "NotDetected").Count |
                Should -Be ($Script:expectedRuleIds.Count - 2)
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR233").status |
                Should -Be "NotApplicable"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR420").status |
                Should -Be "NotApplicable"
            $script:CollectorStatuses["InternetCalendar"].status | Should -Be "Success"
        }

        It "evaluates the optional InternetCalendar rule when ModernSharingOnly is false" {
            $ModernSharingOnly = $false
            $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "NoData"; error = $null }

            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR420").status |
                Should -Be "NotDetected"
        }
    }

    Context "Collectors, failures, and bounded diagnostics" {
        It "records success for a value and permits an explicit null result" {
            Invoke-SharingCollector -Name "OwnerMailbox" -Action { "value" } | Should -Be "value"
            $script:CollectorStatuses["OwnerMailbox"].status | Should -Be "Success"

            Invoke-SharingCollector -Name "OwnerCalendarPermissions" -Action { $null } -AllowNull |
                Should -BeNullOrEmpty
            $script:CollectorStatuses["OwnerCalendarPermissions"].status | Should -Be "Success"
        }

        It "treats null and empty output as failures unless null is allowed" -TestCases @(
            @{ CollectorName = "OwnerMailbox"; Action = { $null } }
            @{ CollectorName = "ReceiverMailbox"; Action = { @() } }
        ) {
            param($CollectorName, $Action)

            { Invoke-SharingCollector -Name $CollectorName -Action $Action } | Should -Throw

            $script:CollectorStatuses[$CollectorName].status | Should -Be "Failed"
            $script:CollectionErrors.collector | Should -Contain $CollectorName
        }

        It "keeps collection and evaluation failures in distinct collections" {
            { Invoke-SharingCollector -Name "OwnerMailbox" -Action { throw "collector failure" } } |
                Should -Throw
            Invoke-SharingEvaluation -Name "Rule evaluation" -RuleIds @("SHR301") -Action {
                throw "evaluation failure"
            }

            $script:CollectionErrors.Count | Should -Be 1
            $script:CollectionErrors[0].collector | Should -Be "OwnerMailbox"
            $script:EvaluationErrors.Count | Should -Be 1
            $script:EvaluationErrors[0].evaluation | Should -Be "Rule evaluation"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR301").status |
                Should -Be "NotEvaluated"
            @($script:SharingFindings | Where-Object -Property status -EQ "Detected").Count |
                Should -Be 0
        }

        It "marks rules dependent on failed collectors as NotEvaluated" {
            { Invoke-SharingCollector -Name "OwnerMailbox" -Action { throw "failure" } } | Should -Throw

            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR100").status |
                Should -Be "NotEvaluated"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR101").status |
                Should -Be "NotEvaluated"
        }

        It "uses bounded sanitized collector metadata by default" {
            $secret = "owner@contoso.com C:\Users\Owner\secret.txt https://contoso.example/private"
            { Invoke-SharingCollector -Name "OwnerMailbox" -Action { throw $secret } } | Should -Throw

            $errorInfo = $script:CollectionErrors[0].error
            $errorInfo.message | Should -Be "Error details omitted in sanitized mode."
            $errorInfo.message.Length | Should -BeLessOrEqual 1024
            ($errorInfo | ConvertTo-Json -Compress) | Should -Not -Match "owner@contoso|secret\.txt|https://"
        }

        It "bounds reason text and omits arbitrary diagnostic strings in sanitized evidence" {
            $reason = "x" * 300
            $evidence = ConvertTo-SharingEvidence -RuleId "SHR430" -Evidence @{
                reason     = $reason
                diagnostic = "owner@contoso.com C:\Private\file.txt https://contoso.example"
            }

            $evidence.reason.Length | Should -Be 256
            $evidence.diagnostic | Should -Be "ValueOmitted"
        }
    }

    Context "Privacy and sensitive-data behavior" {
        It "uses stable role and deterministic identity placeholders without leaking paths or URLs" {
            $first = ConvertTo-SharingEvidence -RuleId "SHR243" -Evidence @{
                expectedOwner = "owner@contoso.com"
                actualOwner   = "other@contoso.com"
                receiver      = "receiver@contoso.com"
                folderPath    = "/Calendar/Owner Secret"
                publishingUrl = "https://contoso.example/calendar/private"
                identity      = "other@contoso.com"
            }
            $second = ConvertTo-SharingEvidence -RuleId "SHR243" -Evidence @{
                actualOwner = "other@contoso.com"
            }

            $first.expectedOwner | Should -Be "Owner"
            $first.receiver | Should -Be "Receiver"
            $first.actualOwner | Should -Be "Identity-1"
            $first.identity | Should -Be "Identity-1"
            $second.actualOwner | Should -Be "Identity-1"
            $first.folderPath | Should -Be "Folder"
            $first.publishingUrl | Should -Be "UrlOmitted"
            ($first | ConvertTo-Json -Compress) |
                Should -Not -Match "owner@contoso|receiver@contoso|other@contoso|Owner Secret|https://"
        }

        It "uses default placeholders for legacy string evidence" {
            $evidence = ConvertTo-SharingEvidence -RuleId "SHR301" `
                -Evidence "No invite for [receiver@contoso.com] from [owner@contoso.com]."

            $evidence.owner | Should -Be "Owner"
            $evidence.receiver | Should -Be "Receiver"
            $evidence.matchingInviteFound | Should -BeFalse
        }

        It "returns full-fidelity structured evidence when IncludeSensitiveData is enabled" {
            $IncludeSensitiveData = $true
            $evidence = [ordered]@{
                owner         = "owner@contoso.com"
                folderPath    = "/Calendar/Owner Secret"
                publishingUrl = "https://contoso.example/calendar/private"
            }
            $result = ConvertTo-SharingEvidence -RuleId "SHR243" -Evidence $evidence
            $result = ConvertTo-SharingEvidence -RuleId "SHR243" -Evidence $evidence

            $result.owner | Should -Be "owner@contoso.com"
            $result.folderPath | Should -Be "/Calendar/Owner Secret"
            $result.publishingUrl | Should -Be "https://contoso.example/calendar/private"
        }

        It "retains bounded full-fidelity error details only when IncludeSensitiveData is enabled" {
            $IncludeSensitiveData = $true
            $message = "owner@contoso.com/" + ("x" * 1100)

            $errorInfo = ConvertTo-SharingErrorInfo -ErrorRecord $message

            $errorInfo.message.Length | Should -Be 1024
            $errorInfo.message | Should -Match "^owner@contoso\.com/"
        }
    }

    Context "Test-SmtpAddressEqual" {
        It "compares case-insensitively after trimming whitespace" {
            Test-SmtpAddressEqual -First " OWNER@Contoso.com " -Second "owner@contoso.COM" | Should -BeTrue
        }

        Context "Owner calendar folder path helpers" {
            It "normalizes supported path forms to the same path and identity" -TestCases @(
                @{ FolderPath = "Calendar\Project Calendar" }
                @{ FolderPath = "/Calendar/Project Calendar" }
                @{ FolderPath = "\Calendar\Project Calendar" }
            ) {
                param($FolderPath)

                ConvertTo-NormalizedCalendarFolderPath -FolderPath $FolderPath |
                    Should -Be "\Calendar\Project Calendar"
                Get-CanonicalMailboxFolderIdentity -Mailbox "owner@contoso.com" `
                    -CalendarRootName "Calendar" -FolderPath $FolderPath |
                    Should -Be "owner@contoso.com:\Calendar\Project Calendar"
            }

            It "prefixes the default Calendar root when statistics omit it" {
                Get-CanonicalMailboxFolderIdentity -Mailbox "owner@contoso.com" `
                    -CalendarRootName "Calendar" -FolderPath "/Project Calendar" |
                    Should -Be "owner@contoso.com:\Calendar\Project Calendar"
                Get-CanonicalMailboxFolderIdentity -Mailbox "owner@contoso.com" `
                    -CalendarRootName "Calendar" -FolderPath "/Calendar/Project Calendar" |
                    Should -Be "owner@contoso.com:\Calendar\Project Calendar"
            }

            It "rejects a full mailbox folder identity with owner-relative guidance" {
                {
                    ConvertTo-NormalizedCalendarFolderPath -FolderPath "owner@contoso.com:\Calendar\Project Calendar"
                } | Should -Throw "*only the owner-relative path*"
                {
                    & "$Script:parentPath\Check-SharingStatus.ps1" `
                        -Owner "owner@contoso.com" `
                        -Receiver "receiver@contoso.com" `
                        -OwnerCalendarFolderPath "owner@contoso.com:\Calendar\Project Calendar" `
                        -SkipMainExecution
                } | Should -Throw "*only the owner-relative path*"
            }

            It "exposes the optional validated public parameter" {
                $command = Get-Command -Name "$Script:parentPath\Check-SharingStatus.ps1"

                $command.Parameters.Keys | Should -Contain "OwnerCalendarFolderPath"
                $command.Parameters["OwnerCalendarFolderPath"].Attributes.TypeId.Name |
                    Should -Contain "ValidateNotNullOrEmptyAttribute"
            }
        }

        It "returns false when either value is null" {
            Test-SmtpAddressEqual -First $null -Second "owner@contoso.com" | Should -BeFalse
            Test-SmtpAddressEqual -First "owner@contoso.com" -Second $null | Should -BeFalse
        }
    }

    Context "CalendarSharingInvite pair detection" {
        It "does not report a finding when the expected receiver is present" {
            Mock Export-MailboxDiagnosticLogs {
                [PSCustomObject]@{
                    MailboxLog = "9/17/2026,Mailbox: owner,Entry MailboxOwner: owner,Recipient: receiver@contoso.com,RecipientType: Internal,Handler=ms-exchange-Modern,DetailLevel=Full"
                }
            }

            ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com"

            @($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR301").Count | Should -Be 0
            $script:CollectorStatuses["OwnerInviteLog"].status | Should -Be "Success"
        }

        It "reports a confirmed pair-specific finding when the receiver is absent" {
            Mock Export-MailboxDiagnosticLogs {
                [PSCustomObject]@{
                    MailboxLog = "9/17/2026,Mailbox: owner,Entry MailboxOwner: owner,Recipient: other@contoso.com,RecipientType: Internal,Handler=ms-exchange-Modern,DetailLevel=Full"
                }
            }

            ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com"

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR301").status |
                Should -Be "Detected"
        }

        It "records unavailable and empty log data as NotEvaluated" -TestCases @(
            @{ ThrowFromCmdlet = $true; ExpectedStatus = "Failed" }
            @{ ThrowFromCmdlet = $false; ExpectedStatus = "NoData" }
        ) {
            param($ThrowFromCmdlet, $ExpectedStatus)

            if ($ThrowFromCmdlet) {
                Mock Export-MailboxDiagnosticLogs { throw "Access denied" }
            } else {
                Mock Export-MailboxDiagnosticLogs { [PSCustomObject]@{ MailboxLog = $null } }
            }

            ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com"

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR300").status |
                Should -Be "NotEvaluated"
            $script:CollectorStatuses["OwnerInviteLog"].status | Should -Be $ExpectedStatus
        }
    }

    Context "Fatal prerequisite orchestration" {
        BeforeEach {
            Initialize-OwnerMocks
            $Script:prerequisiteOwnerMailbox = $Script:ownerMailbox
            $Script:prerequisiteOwnerFolder = $Script:ownerCalendarFolder
            Initialize-ReceiverMocks
            $Script:prerequisiteReceiverMailbox = $Script:receiverMailbox
            $Script:prerequisiteReceiverFolder = $Script:receiverCalendarFolder
            $script:OwnerMB = $null

            $Script:prerequisiteOwnerStats = @(
                [PSCustomObject]@{
                    FolderType             = "Calendar"
                    Name                   = "Calendar"
                    FolderPath             = "/Calendar"
                    FolderSize             = "1 KB (1,024 bytes)"
                    FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                    VisibleItemsInFolder   = 10
                }
            )

            Mock Get-Mailbox {
                if ($Identity -eq "owner@contoso.com") {
                    return $Script:prerequisiteOwnerMailbox
                }
                return $Script:prerequisiteReceiverMailbox
            }
            Mock Get-MailboxFolderStatistics {
                if ($Identity -eq "owner@contoso.com") {
                    return @($Script:prerequisiteOwnerStats)
                }
                return @($Script:receiverStats)
            }
            Mock Get-MailboxCalendarFolder {
                if ($Identity -like "owner@contoso.com:*") {
                    return $Script:prerequisiteOwnerFolder
                }
                return $Script:prerequisiteReceiverFolder
            }
            Mock Write-Host {}
        }

        It "stops on a confirmed missing owner mailbox and suppresses cascade findings" {
            Mock Get-Mailbox {
                if ($Identity -eq "owner@contoso.com") {
                    return $null
                }
                return $Script:prerequisiteReceiverMailbox
            }

            Invoke-SharingDiagnostics

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR100").status |
                Should -Be "Detected"
            @($script:SharingFindings | Where-Object {
                    $_.ruleId -ne "SHR100" -and $_.status -ne "NotApplicable"
                }).Count | Should -Be 0
            @($script:SharingFindings | Where-Object {
                    $_.status -in @("Detected", "NotEvaluated")
                }).Count | Should -Be 1
            Should -Invoke Get-Mailbox -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "owner@contoso.com"
            }
            Should -Not -Invoke Get-Mailbox -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
            Should -Not -Invoke Get-MailboxFolderStatistics
            Should -Not -Invoke ProcessCalendarSharingInviteLogs
            Should -Not -Invoke ProcessCalendarSharingAcceptLogs
            Should -Not -Invoke Get-CalendarEntries
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and ($Object -eq "Fatal prerequisite failure")
            }
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and
                ($Object -eq "Summary (from run on $($script:RunStartedAt.ToString('g'))):")
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                ($Object -like "*backend*Modern Calendar Sharing*") -or
                ($Object -like "*No confirmed issues were detected*")
            }
        }

        It "stops on a redacted owner DisplayName before resolving the receiver or folder" -TestCases @(
            @{ DisplayName = "REDACTED-owner-hash" }
            @{ DisplayName = "  rEdAcTeD-owner-hash  " }
        ) {
            param($DisplayName)

            $Script:prerequisiteOwnerMailbox.DisplayName = $DisplayName
            $Script:prerequisiteOwnerMailbox |
                Add-Member -NotePropertyName Database -NotePropertyValue "OwnerDatabase" -Force

            Invoke-SharingDiagnostics

            $rootFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR101"
            $rootFinding.status | Should -Be "Detected"
            $rootFinding.evidence.mailboxRole | Should -Be "Owner"
            $rootFinding.evidence.fieldName | Should -Be "DisplayName"
            $rootFinding.evidence.redactedValue | Should -Be "ValueOmitted"
            $rootFinding.evidence.database | Should -Be "ValueOmitted"
            ($rootFinding.evidence | ConvertTo-Json -Compress) |
                Should -Not -Match "owner-hash|OwnerDatabase"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR110").status |
                Should -Be "NotApplicable"
            @($script:SharingFindings | Where-Object {
                    $_.ruleId -ne "SHR101" -and $_.status -ne "NotApplicable"
                }).Count | Should -Be 0
            Should -Invoke Get-Mailbox -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "owner@contoso.com"
            }
            Should -Not -Invoke Get-Mailbox -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
            Should -Not -Invoke Get-MailboxFolderStatistics
            Should -Not -Invoke ProcessCalendarSharingInviteLogs
            Should -Not -Invoke Get-CalendarEntries
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and
                ($Object -like "*Owner mailbox name is redacted*Obtain PII access*OwnerDatabase*rerun*")
            }
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and ($Object -eq "Fatal prerequisite failure")
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                ($Object -like "*backend*Modern Calendar Sharing*") -or
                ($Object -like "*No confirmed issues were detected*")
            }
        }

        It "detects a redacted owner Alias when the DisplayName is healthy" {
            $Script:prerequisiteOwnerMailbox |
                Add-Member -NotePropertyName Alias -NotePropertyValue " REDACTED-owner-alias" -Force

            Invoke-SharingDiagnostics

            $rootFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR101"
            $rootFinding.status | Should -Be "Detected"
            $rootFinding.evidence.fieldName | Should -Be "Alias"
            Should -Not -Invoke Get-Mailbox -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
        }

        It "retains redacted mailbox evidence only when sensitive data is enabled" {
            $IncludeSensitiveData = $true
            $Script:prerequisiteOwnerMailbox.DisplayName = "REDACTED-owner-hash"
            $Script:prerequisiteOwnerMailbox |
                Add-Member -NotePropertyName Database -NotePropertyValue "OwnerDatabase" -Force

            Invoke-SharingDiagnostics

            $rootFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR101"
            $rootFinding.evidence.redactedValue | Should -Be "REDACTED-owner-hash"
            $rootFinding.evidence.database | Should -Be "OwnerDatabase"
        }

        It "preserves unavailable evidence semantics for an owner lookup exception" {
            Mock Get-Mailbox {
                if ($Identity -eq "owner@contoso.com") {
                    throw "Access denied"
                }
                return $Script:prerequisiteReceiverMailbox
            }

            Invoke-SharingDiagnostics

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR100").status |
                Should -Be "NotEvaluated"
            @($script:SharingFindings | Where-Object {
                    $_.ruleId -ne "SHR100" -and $_.status -ne "NotApplicable"
                }).Count | Should -Be 0
            Should -Not -Invoke Get-Mailbox -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -like "*returned no Owner mailbox object*"
            }
        }

        It "stops before owner details when receiver mailbox resolution fails" -TestCases @(
            @{ FailureMode = "NoData"; ExpectedStatus = "Detected" }
            @{ FailureMode = "Exception"; ExpectedStatus = "NotEvaluated" }
        ) {
            param($FailureMode, $ExpectedStatus)

            Mock Get-Mailbox {
                if ($Identity -eq "owner@contoso.com") {
                    return $Script:prerequisiteOwnerMailbox
                }
                if ($FailureMode -eq "Exception") {
                    throw "Session unavailable"
                }
                return $null
            }

            Invoke-SharingDiagnostics

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR200").status |
                Should -Be $ExpectedStatus
            @($script:SharingFindings | Where-Object {
                    $_.ruleId -ne "SHR200" -and $_.status -ne "NotApplicable"
                }).Count | Should -Be 0
            Should -Invoke Get-Mailbox -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "owner@contoso.com"
            }
            Should -Invoke Get-Mailbox -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
            Should -Not -Invoke Get-MailboxFolderStatistics
            Should -Not -Invoke Get-MailboxFolderPermission
            Should -Not -Invoke ProcessCalendarSharingInviteLogs
            if ($FailureMode -eq "Exception") {
                Should -Not -Invoke Write-Host -ParameterFilter {
                    $Object -like "*returned no Receiver mailbox object*"
                }
            }
        }

        It "stops on a redacted receiver DisplayName before owner folder resolution" {
            $Script:prerequisiteReceiverMailbox.DisplayName = " REDACTED-receiver-hash "
            $Script:prerequisiteReceiverMailbox |
                Add-Member -NotePropertyName Database -NotePropertyValue "ReceiverDatabase" -Force

            Invoke-SharingDiagnostics

            $rootFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR201"
            $rootFinding.status | Should -Be "Detected"
            $rootFinding.evidence.mailboxRole | Should -Be "Receiver"
            $rootFinding.evidence.fieldName | Should -Be "DisplayName"
            $rootFinding.evidence.redactedValue | Should -Be "ValueOmitted"
            $rootFinding.evidence.database | Should -Be "ValueOmitted"
            ($rootFinding.evidence | ConvertTo-Json -Compress) |
                Should -Not -Match "receiver-hash|ReceiverDatabase"
            @($script:SharingFindings | Where-Object {
                    $_.ruleId -ne "SHR201" -and $_.status -ne "NotApplicable"
                }).Count | Should -Be 0
            Should -Invoke Get-Mailbox -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "owner@contoso.com"
            }
            Should -Invoke Get-Mailbox -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
            Should -Not -Invoke Get-MailboxFolderStatistics
            Should -Not -Invoke ProcessCalendarSharingInviteLogs
            Should -Not -Invoke Get-CalendarEntries
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and
                ($Object -like "*Receiver mailbox name is redacted*Obtain PII access*ReceiverDatabase*rerun*")
            }
        }

        It "stops when selected owner folder resolution is missing or ambiguous" -TestCases @(
            @{ DuplicateRequestedFolder = $false }
            @{ DuplicateRequestedFolder = $true }
        ) {
            param($DuplicateRequestedFolder)

            $script:OwnerCalendarFolderPathSpecified = $true
            $script:NormalizedOwnerCalendarFolderPath = "\Calendar\Project Calendar"
            $script:RequestedOwnerCalendarLeafName = "Project Calendar"
            if ($DuplicateRequestedFolder) {
                $Script:prerequisiteOwnerStats += @(
                    [PSCustomObject]@{
                        FolderType = "User Created"
                        Name       = "Project Calendar"
                        FolderPath = "/Project Calendar"
                    },
                    [PSCustomObject]@{
                        FolderType = "User Created"
                        Name       = "Project Calendar"
                        FolderPath = "/Calendar/Project Calendar"
                    }
                )
            }

            Invoke-SharingDiagnostics

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR110").status |
                Should -Be "NotEvaluated"
            @($script:SharingFindings | Where-Object {
                    $_.ruleId -ne "SHR110" -and $_.status -ne "NotApplicable"
                }).Count | Should -Be 0
            Should -Not -Invoke Get-MailboxFolderPermission
            Should -Not -Invoke Get-CalendarEntries
            Should -Not -Invoke ProcessCalendarSharingInviteLogs
            Should -Not -Invoke ProcessCalendarSharingAcceptLogs
            Should -Not -Invoke Get-MailboxFolderStatistics -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
        }

        It "stops on SHR123 and retains reversed-input guidance" {
            $Script:prerequisiteOwnerFolder.CalendarSharingOwnerSmtpAddress =
            "receiver@contoso.com"

            Invoke-SharingDiagnostics

            $rootFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR123"
            $rootFinding.status | Should -Be "Detected"
            $rootFinding.evidence.inputsReversed | Should -BeTrue
            @($script:SharingFindings | Where-Object {
                    $_.ruleId -ne "SHR123" -and $_.status -ne "NotApplicable"
                }).Count | Should -Be 0
            Should -Not -Invoke Get-MailboxFolderPermission
            Should -Not -Invoke Get-CalendarEntries
            Should -Not -Invoke ProcessCalendarSharingInviteLogs
            Should -Not -Invoke ProcessCalendarSharingAcceptLogs
            Should -Not -Invoke Get-MailboxFolderStatistics -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and
                ($Object -like "*Owner and Receiver appear reversed*Owner and Receiver swapped*")
            }
        }

        It "reuses healthy prerequisite objects and continues the full diagnostic path" {
            Invoke-SharingDiagnostics

            $script:FatalPrerequisiteFailure | Should -BeNullOrEmpty
            Should -Invoke Get-Mailbox -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "owner@contoso.com"
            }
            Should -Invoke Get-Mailbox -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
            Should -Invoke Get-MailboxFolderStatistics -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "owner@contoso.com"
            }
            Should -Invoke Get-MailboxFolderStatistics -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "receiver@contoso.com"
            }
            Should -Invoke Get-MailboxFolderPermission
            Should -Invoke Get-CalendarEntries
        }
    }

    Context "Owner calendar and active-sharing checks" {
        BeforeEach {
            Initialize-OwnerMocks
        }

        It "reports both missing owner calendar flags and an absent receiver" {
            $Script:ownerCalendarFolder.ExtendedFolderFlags = @()
            $Script:activeSharees = @()

            GetOwnerInformation -Owner "owner@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR121"
            $script:SharingFindings.ruleId | Should -Contain "SHR122"
            $script:SharingFindings.ruleId | Should -Contain "SHR311"
        }

        It "does not report flag or ActiveShareeFlags findings for healthy values" {
            GetOwnerInformation -Owner "owner@contoso.com"

            $script:SharingFindings.ruleId | Should -Not -Contain "SHR121"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR122"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR312"
        }

        It "normalizes enum-like owner folder flags before validation" {
            $Script:ownerCalendarFolder.ExtendedFolderFlags = @(
                (Get-CalendarFlagTestValue -Name "SharedOut"),
                (Get-CalendarFlagTestValue -Name "ExchangeShareFolder")
            )

            GetOwnerInformation -Owner "owner@contoso.com"

            $script:SharingFindings.ruleId | Should -Not -Contain "SHR121"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR122"
        }

        It "normalizes one comma-delimited owner flag value before validation" {
            $Script:ownerCalendarFolder.ExtendedFolderFlags = @(
                (Get-CalendarFlagTestValue -Name "ReadOnly, SharedOut, ExchangeShareFolder")
            )

            GetOwnerInformation -Owner "owner@contoso.com"

            $script:SharingFindings.ruleId | Should -Not -Contain "SHR121"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR122"
        }

        It "outputs only relevant owner calendar properties" {
            $output = GetOwnerInformation -Owner "owner@contoso.com" | Out-String

            foreach ($propertyName in @(
                    "Identity", "CreationTime", "PublishEnabled", "ExtendedFolderFlags")) {
                $output | Should -Match "$propertyName\s+:"
            }

            foreach ($propertyName in @(
                    "CalendarSharingFolderFlags", "CalendarSharingOwnerSmtpAddress",
                    "CalendarSharingPermissionLevel", "SharingLevelOfDetails",
                    "SharingPermissionFlags", "LastAttemptedSyncTime",
                    "LastSuccessfulSyncTime", "SharedCalendarSyncStartDate")) {
                $output | Should -Not -Match "$propertyName\s+:"
            }
        }

        It "reports non-None ActiveShareeFlags for the expected receiver" {
            $Script:activeSharees[0].ActiveShareeFlags = @("NeedsSync")

            GetOwnerInformation -Owner "owner@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR312"
        }

        It "treats an empty owner-folder sharing owner as the actual owner calendar" {
            $Script:ownerCalendarFolder.CalendarSharingOwnerSmtpAddress = $null

            GetOwnerInformation -Owner "owner@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR123").status |
                Should -Be "NotDetected"
        }

        It "detects reversed Owner and Receiver inputs with sanitized evidence and guidance" {
            $Script:ownerCalendarFolder.CalendarSharingOwnerSmtpAddress = "receiver@contoso.com"
            Mock Write-Host {}

            GetOwnerInformation -Owner "owner@contoso.com"

            $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR123"
            $finding.status | Should -Be "Detected"
            $finding.evidence.expectedOwner | Should -Be "Owner"
            $finding.evidence.actualOwner | Should -Be "Receiver"
            $finding.evidence.inputsReversed | Should -BeTrue
            $finding.recommendedNextStep | Should -Match "appear reversed.*swapped"
            $script:ConsoleFindingEvidence["SHR123"].expectedOwner | Should -Be "owner@contoso.com"
            $script:ConsoleFindingEvidence["SHR123"].actualOwner | Should -Be "receiver@contoso.com"
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and
                ($Object -like "*Expected Owner:*owner@contoso.com*") -and
                ($Object -like "*Actual calendar owner:*receiver@contoso.com*") -and
                ($Object -like "*Owner and Receiver appear reversed*Owner and Receiver swapped*")
            }
        }

        It "detects a third-party owner without claiming the supplied pair is reversed" {
            $Script:ownerCalendarFolder.CalendarSharingOwnerSmtpAddress = "third@contoso.com"
            Mock Write-Host {}

            GetOwnerInformation -Owner "owner@contoso.com"

            $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR123"
            $finding.status | Should -Be "Detected"
            $finding.evidence.expectedOwner | Should -Be "Owner"
            $finding.evidence.actualOwner | Should -Be "Identity-1"
            $finding.evidence.inputsReversed | Should -BeFalse
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and
                ($Object -like "*Expected Owner:*owner@contoso.com*") -and
                ($Object -like "*Actual calendar owner:*third@contoso.com*") -and
                ($Object -like "*shared copy owned by another mailbox*")
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -like "*appear reversed*"
            }
        }

        It "treats a non-empty matching owner-folder sharing owner as valid" {
            $Script:ownerCalendarFolder.CalendarSharingOwnerSmtpAddress = " OWNER@CONTOSO.COM "

            GetOwnerInformation -Owner "owner@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR123").status |
                Should -Be "NotDetected"
        }

        It "preserves the default calendar identities when the optional path is omitted" {
            GetOwnerInformation -Owner "owner@contoso.com"

            $script:OwnerCalendarFolderIdentity | Should -Be "owner@contoso.com:\Calendar"
            $script:OwnerCalendarLeafNameCandidate | Should -BeNullOrEmpty
            Should -Invoke Get-MailboxFolderPermission -ParameterFilter {
                $Identity -eq "owner@contoso.com:\Calendar"
            }
            Should -Invoke Get-MailboxCalendarFolder -ParameterFilter {
                $Identity -eq "owner@contoso.com:\Calendar"
            }
            Should -Invoke Get-CalendarActiveSharingInformation -ParameterFilter {
                $Identity -eq "owner@contoso.com:\Calendar"
            }
        }

        It "uses the selected nested folder identity and thresholds" -TestCases @(
            @{ StatisticsFolderPath = "/Project Calendar" }
            @{ StatisticsFolderPath = "/Calendar/Project Calendar" }
        ) {
            param($StatisticsFolderPath)

            $script:OwnerCalendarFolderPathSpecified = $true
            $script:NormalizedOwnerCalendarFolderPath = "\calendar\PROJECT CALENDAR"
            $script:RequestedOwnerCalendarLeafName = "Project Calendar"
            Mock Get-MailboxFolderStatistics {
                @(
                    [PSCustomObject]@{
                        FolderType           = "Calendar"
                        Name                 = "Calendar"
                        FolderPath           = "/Calendar"
                        FolderSize           = "1 KB (1,024 bytes)"
                        VisibleItemsInFolder = 10
                    },
                    [PSCustomObject]@{
                        FolderType           = "User Created"
                        Name                 = "Project Calendar"
                        FolderPath           = $StatisticsFolderPath
                        FolderSize           = "2 GB (2,000,000,001 bytes)"
                        VisibleItemsInFolder = 100001
                    }
                )
            }

            GetOwnerInformation -Owner "owner@contoso.com"

            $script:OwnerCalendarFolderIdentity |
                Should -Be "owner@contoso.com:\Calendar\Project Calendar"
            $script:OwnerCalendarLeafNameCandidate | Should -Be "Project Calendar"
            $script:SharingFindings.ruleId | Should -Contain "SHR430"
            $script:SharingFindings.ruleId | Should -Contain "SHR431"
            Should -Invoke Get-MailboxFolderPermission -ParameterFilter {
                $Identity -eq "owner@contoso.com:\Calendar\Project Calendar"
            }
            Should -Invoke Get-MailboxCalendarFolder -ParameterFilter {
                $Identity -eq "owner@contoso.com:\Calendar\Project Calendar"
            }
            Should -Invoke Get-CalendarActiveSharingInformation -ParameterFilter {
                $Identity -eq "owner@contoso.com:\Calendar\Project Calendar"
            }
        }

        It "resolves the production owner statistics path that omits the Calendar root" {
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:NormalizedOwnerCalendarFolderPath = "\Calendar\MI Events Around the World"
            $script:RequestedOwnerCalendarLeafName = "MI Events Around the World"
            Mock Get-MailboxFolderStatistics {
                @(
                    [PSCustomObject]@{
                        FolderType           = "Calendar"
                        Name                 = "Calendar"
                        FolderPath           = "/Calendar"
                        FolderSize           = "1 KB (1,024 bytes)"
                        VisibleItemsInFolder = 10
                    },
                    [PSCustomObject]@{
                        FolderType           = "User Created"
                        Name                 = "MI Events Around the World"
                        FolderPath           = "/MI Events Around the World"
                        FolderSize           = "1 KB (1,024 bytes)"
                        VisibleItemsInFolder = 52
                    }
                )
            }

            GetOwnerInformation -Owner "myra.tse@mplus.org.hk"

            $script:OwnerCalendarFolderIdentity |
                Should -Be "myra.tse@mplus.org.hk:\Calendar\MI Events Around the World"
        }

        It "does not fall back when the requested owner folder path is missing" {
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:NormalizedOwnerCalendarFolderPath = "\Calendar\Missing"
            $script:RequestedOwnerCalendarLeafName = "Missing"
            Mock Get-MailboxFolderStatistics {
                @(
                    [PSCustomObject]@{
                        FolderType           = "Calendar"
                        Name                 = "Calendar"
                        FolderPath           = "/Calendar"
                        FolderSize           = "1 KB (1,024 bytes)"
                        VisibleItemsInFolder = 10
                    },
                    [PSCustomObject]@{
                        FolderType           = "User Created"
                        Name                 = "Renamed Calendar"
                        FolderPath           = "/Renamed Calendar"
                        FolderSize           = "1 KB (1,024 bytes)"
                        VisibleItemsInFolder = 52
                    }
                )
            }
            Mock Write-Host {}

            GetOwnerInformation -Owner "owner@contoso.com"

            $script:OwnerSelectedCalendar | Should -BeNullOrEmpty
            $script:CollectorStatuses["OwnerFolderStatistics"].status | Should -Be "NoData"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR110").status |
                Should -Be "NotEvaluated"
            Should -Invoke Write-Host -ParameterFilter {
                ($Object -match "Name\s+FolderPath\s+ItemsInFolder") -and
                ($Object -match "Calendar\s+/Calendar\s+10") -and
                ($Object -match "Renamed Calendar\s+/Renamed Calendar\s+52")
            }
            Should -Not -Invoke Get-MailboxFolderPermission
            Should -Not -Invoke Get-MailboxCalendarFolder
            Should -Not -Invoke Get-CalendarActiveSharingInformation
            Should -Not -Invoke ProcessCalendarSharingInviteLogs

            Complete-SharingFindings
            foreach ($ruleId in @("SHR111", "SHR120", "SHR310", "SHR430", "SHR431")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status |
                    Should -Be "NotApplicable"
            }
        }
    }

    Context "Receiver matching and calendar entries" {
        BeforeEach {
            Initialize-ReceiverMocks
        }

        It "reports a missing local folder and missing pair-specific New entry" {
            $Script:receiverStats = @($Script:receiverStats[0])
            $Script:calendarEntries = @()

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR213"
            $script:SharingFindings.ruleId | Should -Contain "SHR231"
        }

        It "requests more access when receiver calendar folder names are redacted" {
            $Script:receiverStats = @(
                [PSCustomObject]@{
                    FolderType             = "Calendar"
                    Name                   = "REDACTED-Calendar00"
                    FolderPath             = "REDACTED-Calendar00"
                    FolderSize             = "338.8 MB"
                    FolderAndSubfolderSize = "338.8 MB (355,266,492 bytes)"
                    VisibleItemsInFolder   = 349
                },
                [PSCustomObject]@{
                    FolderType             = "User Created"
                    Name                   = "REDACTED-User Created01"
                    FolderPath             = "REDACTED-User Created01"
                    FolderSize             = "13.04 MB"
                    FolderAndSubfolderSize = "13.04 MB (13,670,864 bytes)"
                    VisibleItemsInFolder   = 435
                }
            )
            Mock Write-Host {}

            GetReceiverInformation -Receiver "receiver@contoso.com"

            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "Cannot read [Owner Display] calendar folder names. Get more access."
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -like "Warning: Could not Identify the Owner's*"
            }
            $script:PIIAccess | Should -BeFalse
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR201").status |
                Should -Be "Detected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR213").status |
                Should -Be "NotEvaluated"
        }

        It "reports duplicate local folders" {
            $Script:receiverStats += [PSCustomObject]@{
                FolderType           = "User Created"
                Name                 = "Owner Display (1)"
                FolderPath           = "/Owner Display (1)"
                FolderSize           = "1 KB"
                VisibleItemsInFolder = 5
            }

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR211"
        }

        It "reports an orphaned New entry and a relevant Old entry" {
            $ModernSharingOnly = $false
            $Script:calendarEntries[0].IsOrphanedEntry = $true
            $Script:calendarEntries += [PSCustomObject]@{
                CalendarGroupName = "People's calendars"
                CalendarName      = "Owner Display"
                OwnerEmailAddress = " OWNER@CONTOSO.COM "
                SharingModelType  = "Old"
                IsOrphanedEntry   = $false
            }

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR232"
            $script:SharingFindings.ruleId | Should -Contain "SHR233"
        }

        It "reports a numeric suffix on the uniquely matched folder" {
            $Script:receiverStats[1].Name = "Owner Display (1)"
            $Script:receiverStats[1].FolderPath = "/Calendar/Owner Display (1)"
            $Script:calendarEntries[0].CalendarName = "Owner Display (1)"

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR214"
        }

        It "constructs the same receiver identity from root and Calendar-relative paths" {
            Get-ReceiverFolderIdentity -Receiver "receiver@contoso.com" `
                -ReceiverCalendarName "Calendar" -FolderPath "/Owner Display" |
                Should -Be "receiver@contoso.com:\Calendar\Owner Display"
            Get-ReceiverFolderIdentity -Receiver "receiver@contoso.com" `
                -ReceiverCalendarName "Calendar" -FolderPath "/Calendar/Owner Display" |
                Should -Be "receiver@contoso.com:\Calendar\Owner Display"
        }

        It "matches a selected subfolder by its leaf name" {
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:RequestedOwnerCalendarLeafName = "Project Calendar"
            $script:OwnerCalendarLeafNameCandidate = "Project Calendar"
            $Script:receiverStats[1].Name = "Project Calendar"
            $Script:receiverStats[1].FolderPath = "/Project Calendar"
            $Script:calendarEntries[0].CalendarName = "Project Calendar"

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:ReceiverMatchedCalendar.Name | Should -Be "Project Calendar"
        }

        It "uses pair-specific calendar entries to uniquely match a folder from all statistics" {
            $Script:receiverStats[1].Name = "Project Calendar"
            $Script:receiverStats[1].FolderPath = "/Project Calendar"
            $Script:calendarEntries[0].CalendarName = "Project Calendar"

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:ReceiverMatchedCalendar.Name | Should -Be "Project Calendar"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR213"
            Should -Invoke Get-MailboxCalendarFolder -ParameterFilter {
                $Identity -eq "receiver@contoso.com:\Calendar\Project Calendar"
            }
        }

        It "does not fall back to an owner display-name folder in selected-subfolder mode" {
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:RequestedOwnerCalendarLeafName = "Missing Project Calendar"

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:ReceiverMatchedCalendar | Should -BeNullOrEmpty
            $script:SharingFindings.ruleId | Should -Contain "SHR213"
            Should -Not -Invoke Get-MailboxCalendarFolder -ParameterFilter {
                $Identity -eq "receiver@contoso.com:\Calendar\Owner Display"
            }
        }

        It "uses the production selected folder and does not accept other same-owner entries" {
            $Owner = "myra.tse@mplus.org.hk"
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:NormalizedOwnerCalendarFolderPath = "\Calendar\MI Events Around the World"
            $script:RequestedOwnerCalendarLeafName = "MI Events Around the World"
            $script:OwnerCalendarLeafNameCandidate = "MI Events Around the World"
            $script:OwnerMB = [PSCustomObject]@{
                DisplayName            = "Myra Tse"
                OrganizationalUnitRoot = "OU1"
            }
            $Script:receiverStats = @(
                [PSCustomObject]@{
                    FolderType = "Calendar"
                    Name       = "Calendar"
                    FolderPath = "/Calendar"
                },
                [PSCustomObject]@{
                    FolderType = "User Created"
                    Name       = "MI Events Around the World"
                    FolderPath = "/MI Events Around the World"
                },
                [PSCustomObject]@{
                    FolderType = "User Created"
                    Name       = "Myra Tse"
                    FolderPath = "/Myra Tse"
                }
            )
            $Script:calendarEntries = @(
                [PSCustomObject]@{
                    CalendarName      = "Myra Tse"
                    OwnerEmailAddress = "myra.tse@mplus.org.hk"
                    SharingModelType  = "New"
                    IsOrphanedEntry   = $false
                },
                [PSCustomObject]@{
                    CalendarName      = "Trial"
                    OwnerEmailAddress = "myra.tse@mplus.org.hk"
                    SharingModelType  = "New"
                    IsOrphanedEntry   = $false
                }
            )
            $Script:receiverCalendarFolder.CalendarSharingOwnerSmtpAddress = "myra.tse@mplus.org.hk"

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:ReceiverMatchedCalendar.Name | Should -Be "MI Events Around the World"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR231").status |
                Should -Be "Detected"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR243"
            Should -Invoke Get-MailboxCalendarFolder -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "receiver@contoso.com:\Calendar\MI Events Around the World"
            }
            Should -Not -Invoke Get-MailboxCalendarFolder -ParameterFilter {
                $Identity -eq "receiver@contoso.com:\Calendar\Myra Tse"
            }
        }

        It "scopes old-model entries to the selected calendar" -TestCases @(
            @{ CalendarName = "Trial"; ExpectedFinding = $false }
            @{ CalendarName = "Project Calendar"; ExpectedFinding = $true }
        ) {
            param($CalendarName, $ExpectedFinding)

            $ModernSharingOnly = $false
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:RequestedOwnerCalendarLeafName = "Project Calendar"
            $Script:receiverStats[1].Name = "Project Calendar"
            $Script:receiverStats[1].FolderPath = "/Project Calendar"
            $Script:calendarEntries = @(
                [PSCustomObject]@{
                    CalendarName      = "Project Calendar"
                    OwnerEmailAddress = "owner@contoso.com"
                    SharingModelType  = "New"
                    IsOrphanedEntry   = $false
                },
                [PSCustomObject]@{
                    CalendarName      = $CalendarName
                    OwnerEmailAddress = "owner@contoso.com"
                    SharingModelType  = "Old"
                    IsOrphanedEntry   = $false
                }
            )

            GetReceiverInformation -Receiver "receiver@contoso.com"

            ($script:SharingFindings.ruleId -contains "SHR233") | Should -Be $ExpectedFinding
        }

        It "preserves receiver folder owner validation" -TestCases @(
            @{ ActualOwner = ""; ExpectedStatus = "Detected" }
            @{ ActualOwner = "other@contoso.com"; ExpectedStatus = "Detected" }
            @{ ActualOwner = " OWNER@CONTOSO.COM "; ExpectedStatus = "NotDetected" }
        ) {
            param($ActualOwner, $ExpectedStatus)

            $Script:receiverCalendarFolder.CalendarSharingOwnerSmtpAddress = $ActualOwner

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR243").status |
                Should -Be $ExpectedStatus
        }

        It "normalizes enum-like receiver folder flags before validation" {
            $Script:receiverCalendarFolder.ExtendedFolderFlags = @(
                (Get-CalendarFlagTestValue -Name "SharedIn"),
                (Get-CalendarFlagTestValue -Name "ExchangeShareFolder")
            )

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Not -Contain "SHR241"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR242"
        }

        It "normalizes the production comma-delimited receiver flag value" {
            $Script:receiverCalendarFolder.ExtendedFolderFlags = @(
                (Get-CalendarFlagTestValue -Name "ReadOnly, SharedIn, ExcludeReminders, SharedExchangeValid, ExclusivelyBound, ExchangeShareFolder")
            )

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Not -Contain "SHR241"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR242"
        }

        It "stores comma-delimited flags as normalized structured evidence" {
            $Script:receiverCalendarFolder.ExtendedFolderFlags = @(
                (Get-CalendarFlagTestValue -Name "ReadOnly, SharedIn, ExcludeReminders")
            )

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $finding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR242"
            $finding.status | Should -Be "Detected"
            $finding.evidence.extendedFolderFlags |
                Should -Be @("ReadOnly", "SharedIn", "ExcludeReminders")
        }

        It "reports genuinely missing receiver folder flags" {
            $Script:receiverCalendarFolder.ExtendedFolderFlags = @()

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR241"
            $script:SharingFindings.ruleId | Should -Contain "SHR242"
        }
    }

    Context "Owner and receiver statistics comparison" {
        BeforeEach {
            $script:CollectorStatuses["OwnerFolderStatistics"] =
            [PSCustomObject]@{ status = "Success"; error = $null }
            $script:CollectorStatuses["ReceiverFolderStatistics"] =
            [PSCustomObject]@{ status = "Success"; error = $null }
        }

        It "detects the production item-count and size asymmetry with structured evidence" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 52
                FolderAndSubfolderSize = "370.1 KB (379,018 bytes)"
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 1061
                FolderAndSubfolderSize = "4.369 MB (4,581,441 bytes)"
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics

            $countFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR432"
            $sizeFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR433"
            $countFinding.status | Should -Be "Detected"
            $countFinding.evidence.ownerCount | Should -Be 52
            $countFinding.evidence.receiverCount | Should -Be 1061
            $countFinding.evidence.delta | Should -Be 1009
            $countFinding.evidence.ratio | Should -Be 20.4
            $sizeFinding.status | Should -Be "Detected"
            $sizeFinding.evidence.ownerBytes | Should -Be 379018
            $sizeFinding.evidence.receiverBytes | Should -Be 4581441
            $sizeFinding.evidence.deltaBytes | Should -Be 4202423
            $sizeFinding.evidence.ratio | Should -Be 12.09
        }

        It "does not detect when receiver values are below twice the owner values" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 200
                FolderAndSubfolderSize = "1 MB (1,048,576 bytes)"
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 399
                FolderAndSubfolderSize = "1.9 MB (1,992,294 bytes)"
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotDetected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR433").status |
                Should -Be "NotDetected"
        }

        It "does not detect when receiver deltas are below the absolute guards" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 1
                FolderAndSubfolderSize = "100 bytes (100 bytes)"
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 100
                FolderAndSubfolderSize = "1 MB (1,048,675 bytes)"
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotDetected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR433").status |
                Should -Be "NotDetected"
        }

        It "detects exact absolute thresholds safely when owner values are zero" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 0
                FolderAndSubfolderSize = "0 bytes (0 bytes)"
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 100
                FolderAndSubfolderSize = "1 MB (1,048,576 bytes)"
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "Detected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR433").status |
                Should -Be "Detected"
            $script:CalendarStatisticsComparison.countRatio | Should -BeNullOrEmpty
            $script:CalendarStatisticsComparison.sizeRatio | Should -BeNullOrEmpty
        }

        It "keeps owner-larger comparisons informational" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 500
                FolderAndSubfolderSize = "5 MB (5,242,880 bytes)"
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 100
                FolderAndSubfolderSize = "1 MB (1,048,576 bytes)"
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotDetected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR433").status |
                Should -Be "NotDetected"
            $script:CalendarStatisticsComparison.countDelta | Should -Be -400
            $script:CalendarStatisticsComparison.sizeDeltaBytes | Should -Be -4194304
        }

        It "uses a ByteQuantifiedSize-style Value ToBytes method" {
            $byteValue = [PSCustomObject]@{ Bytes = 2097152 }
            $byteValue | Add-Member -MemberType ScriptMethod -Name ToBytes -Value {
                return $this.Bytes
            } -Force
            $ownerSize = [PSCustomObject]@{ Value = $byteValue }

            ConvertTo-FolderStatisticsSizeBytes -FolderStatistics ([PSCustomObject]@{
                    FolderAndSubfolderSize = $ownerSize
                }) | Should -Be 2097152
        }

        It "falls back to FolderSize when FolderAndSubfolderSize cannot be converted" {
            ConvertTo-FolderStatisticsSizeBytes -FolderStatistics ([PSCustomObject]@{
                    FolderAndSubfolderSize = "Unavailable"
                    FolderSize             = "2 MB (2,097,152 bytes)"
                }) | Should -Be 2097152
        }

        It "marks only an unavailable metric NotEvaluated" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = "Unavailable"
                FolderAndSubfolderSize = "1 KB (1,024 bytes)"
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder   = 10
                FolderAndSubfolderSize = "Unavailable"
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotEvaluated"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR433").status |
                Should -Be "NotEvaluated"
        }

        It "marks the comparison NotApplicable without a unique receiver match" {
            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics ([PSCustomObject]@{
                    VisibleItemsInFolder   = 10
                    FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                }) `
                -ReceiverFolderStatistics $null

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotApplicable"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR433").status |
                Should -Be "NotApplicable"
        }

        It "marks the comparison NotEvaluated when receiver statistics are unavailable" {
            $script:CollectorStatuses["ReceiverFolderStatistics"] =
            [PSCustomObject]@{ status = "Unavailable"; error = "Access denied" }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics ([PSCustomObject]@{
                    VisibleItemsInFolder   = 10
                    FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                }) `
                -ReceiverFolderStatistics $null

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotEvaluated"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR433").status |
                Should -Be "NotEvaluated"
        }
    }

    Context "Selected-folder accept logs" {
        It "filters entries by both expected owner and selected folder" {
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:RequestedOwnerCalendarLeafName = "MI Events Around the World"
            Mock Export-MailboxDiagnosticLogs {
                [PSCustomObject]@{
                    MailboxLog = @(
                        "9/22/2026 6:35:50 AM,Mailbox: receiver,Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for owner@contoso.com,calendar name MI Events Around the World",
                        "9/22/2026 6:35:49 AM,Mailbox: receiver,Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for owner@contoso.com,calendar name Trial",
                        "9/22/2026 6:35:48 AM,Mailbox: receiver,Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for other@contoso.com,calendar name MI Events Around the World"
                    ) -join "`r`n"
                }
            }

            ProcessCalendarSharingAcceptLogs -Identity "receiver@contoso.com"

            $script:ReceiverAcceptLogEntries.Count | Should -Be 3
            $script:ReceiverSelectedAcceptLogEntries.Count | Should -Be 1
            $script:ReceiverSelectedAcceptLogEntries[0].SharedCalendarOwner |
                Should -Be "owner@contoso.com"
            $script:ReceiverSelectedAcceptLogEntries[0].FolderName |
                Should -Be "MI Events Around the World"
        }
    }

    Context "Periodic synchronization and start-date classifications" {
        BeforeEach {
            Initialize-ReceiverMocks
        }

        It "detects production-shaped year-one synchronization sentinels without stale or backfill output" {
            $uninitializedDate = [DateTime]::new(1, 2, 1)
            $Script:receiverCalendarFolder.LastAttemptedSyncTime = $uninitializedDate
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = $uninitializedDate
            $Script:receiverCalendarFolder.SharedCalendarSyncStartDate = $uninitializedDate
            Mock Write-Host {}

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $neverSynchronizedFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR403"
            $neverSynchronizedFinding.status | Should -Be "Detected"
            $neverSynchronizedFinding.severity | Should -Be "Error"
            $neverSynchronizedFinding.evidence.attemptedSyncTimeUninitialized | Should -BeTrue
            $neverSynchronizedFinding.evidence.successfulSyncTimeUninitialized | Should -BeTrue
            $neverSynchronizedFinding.evidence.syncStartDateUninitialized | Should -BeTrue
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR400").status |
                Should -Be "NotApplicable"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR402").status |
                Should -Be "NotApplicable"
            foreach ($ruleId in @("SHR410", "SHR411", "SHR412")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status |
                    Should -Be "NotApplicable"
            }
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR413").status |
                Should -Be "Detected"
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and
                ($Object -like "*selected receiver calendar appears never to have synchronized*")
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -like "*Periodic calendar synchronization is stale*"
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -like "*should have data back to:*"
            }
        }

        It "detects year-one sync sentinels with null or real start dates" -TestCases @(
            @{ StartDate = $null; ExpectedStartUnavailable = $true }
            @{ StartDate = (Get-Date).AddDays(-30); ExpectedStartUnavailable = $false }
        ) {
            param($StartDate, $ExpectedStartUnavailable)

            $uninitializedDate = [DateTime]::new(1, 2, 1)
            $Script:receiverCalendarFolder.LastAttemptedSyncTime = $uninitializedDate
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = $uninitializedDate
            $Script:receiverCalendarFolder.SharedCalendarSyncStartDate = $StartDate

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR403").status |
                Should -Be "Detected"
            $startFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR413"
            if ($ExpectedStartUnavailable) {
                $startFinding.status | Should -Be "Detected"
            } else {
                $startFinding.status | Should -Be "NotDetected"
            }
            foreach ($ruleId in @("SHR400", "SHR402", "SHR410", "SHR411", "SHR412")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status |
                    Should -Be "NotApplicable"
            }
        }

        It "treats one year-one sync timestamp as incomplete" -TestCases @(
            @{ AttemptIsUninitialized = $true }
            @{ AttemptIsUninitialized = $false }
        ) {
            param($AttemptIsUninitialized)

            $uninitializedDate = [DateTime]::new(1, 2, 1)
            if ($AttemptIsUninitialized) {
                $Script:receiverCalendarFolder.LastAttemptedSyncTime = $uninitializedDate
                $Script:receiverCalendarFolder.LastSuccessfulSyncTime = Get-Date
            } else {
                $Script:receiverCalendarFolder.LastAttemptedSyncTime = Get-Date
                $Script:receiverCalendarFolder.LastSuccessfulSyncTime = $uninitializedDate
            }

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR401").status |
                Should -Be "NotEvaluated"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR403").status |
                Should -Be "NotDetected"
            @($script:SharingFindings | Where-Object {
                    $_.ruleId -in @("SHR400", "SHR402") -and $_.status -eq "Detected"
                }).Count | Should -Be 0
        }

        It "treats a year-one start date as unavailable with valid sync times" {
            $now = Get-Date
            $Script:receiverCalendarFolder.LastAttemptedSyncTime = $now
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = $now
            $Script:receiverCalendarFolder.SharedCalendarSyncStartDate = [DateTime]::new(1, 2, 1)
            Mock Write-Host {}

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR403").status |
                Should -Be "NotDetected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR413").status |
                Should -Be "Detected"
            foreach ($ruleId in @("SHR410", "SHR411", "SHR412")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status |
                    Should -Be "NotApplicable"
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -like "*should have data back to:*"
            }
        }

        It "treats equal recent timestamps as healthy and reports a null start date" {
            $now = Get-Date
            $Script:receiverCalendarFolder.LastAttemptedSyncTime = $now
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = $now
            $Script:receiverCalendarFolder.SharedCalendarSyncStartDate = $null

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Not -Contain "SHR400"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR401"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR402"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR403"
            $script:SharingFindings.ruleId | Should -Contain "SHR413"
        }

        It "reports a failed latest attempt and recent backfill context" {
            $now = Get-Date
            $Script:receiverCalendarFolder.CreationTime = $now.AddDays(-2)
            $Script:receiverCalendarFolder.LastAttemptedSyncTime = $now
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = $now.AddMinutes(-30)
            $Script:receiverCalendarFolder.SharedCalendarSyncStartDate = $now.AddMinutes(-10)

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR402"
            $script:SharingFindings.ruleId | Should -Contain "SHR411"
            $script:SharingFindings.ruleId | Should -Contain "SHR412"
        }

        It "reports both timestamps older than 24 hours as stale rather than failed" {
            $Script:receiverCalendarFolder.LastAttemptedSyncTime = (Get-Date).AddHours(-30)
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = (Get-Date).AddHours(-31)

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR400"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR402"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR403"
        }

        It "records incomplete timestamps as NotEvaluated" -TestCases @(
            @{ Attempt = $null; Success = (Get-Date) }
            @{ Attempt = (Get-Date); Success = $null }
        ) {
            param($Attempt, $Success)

            $Script:receiverCalendarFolder.LastAttemptedSyncTime = $Attempt
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = $Success

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR401"
            $finding.status | Should -Be "NotEvaluated"
        }
    }

    Context "Final summary focused output" {
        BeforeEach {
            Mock Write-Host {}
        }

        It "states that no confirmed issues or incomplete checks were recorded" {
            foreach ($collectorName in $Script:collectorNames) {
                $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "Success"; error = $null }
            }
            $script:CalendarStatisticsComparisonPerformed = $true

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Blue") -and
                ($Object -eq "Summary (from run on $($script:RunStartedAt.ToString('g'))):")
            }
            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "No confirmed issues were detected with the evidence available."
            }
            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "No incomplete checks were recorded."
            }
        }

        It "warns that health is indeterminate when checks are incomplete" {
            Add-SharingFinding -RuleId "SHR300" -Status NotEvaluated -Evidence @{
                reason = "No data"
            }

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "The sharing state should not be considered healthy until the incomplete checks are resolved."
            }
        }

        It "retains detected findings in the final summary" {
            Add-SharingFinding -RuleId "SHR121" -Status Detected -Evidence @{
                extendedFolderFlags = @()
            }

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR121").status |
                Should -Be "Detected"
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -eq "No confirmed issues were detected with the evidence available."
            }
        }

        It "wraps long finding evidence without truncation" {
            $longEvidence = ("Long evidence text " * 12) + "END-EVIDENCE"
            Add-SharingFinding -RuleId "SHR231" -Status Detected -Evidence $longEvidence

            $output = Write-SharingSummary `
                -Owner "owner@contoso.com" `
                -Receiver "receiver@contoso.com" |
                Out-String -Width 100

            $output | Should -Match "END-EVIDENCE"
            $output | Should -Not -Match "\.\.\."
        }
    }
}
