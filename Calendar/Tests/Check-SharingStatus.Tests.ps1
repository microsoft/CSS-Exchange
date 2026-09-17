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
        "SHR100", "SHR101", "SHR110", "SHR111", "SHR120", "SHR121", "SHR122", "SHR130",
        "SHR200", "SHR201", "SHR210", "SHR211", "SHR212", "SHR213", "SHR214", "SHR220",
        "SHR230", "SHR231", "SHR232", "SHR233", "SHR240", "SHR241", "SHR242", "SHR243",
        "SHR300", "SHR301", "SHR310", "SHR311", "SHR312", "SHR320", "SHR321", "SHR322",
        "SHR323", "SHR400", "SHR401", "SHR402", "SHR410", "SHR411", "SHR412", "SHR413",
        "SHR420", "SHR430", "SHR431"
    )
    $Script:collectorNames = @(
        "OwnerMailbox", "ReceiverMailbox", "OwnerFolderStatistics", "ReceiverFolderStatistics",
        "OwnerCalendarPermissions", "OwnerMailboxPermissions", "OwnerInviteLog", "OwnerCalendarFolder",
        "ActiveSharing", "ReceiverAcceptLog", "CalendarEntries", "ReceiverLocalCalendarFolder",
        "InternetCalendar"
    )

    function Initialize-SharingTestState {
        $script:SharingFindings = [System.Collections.Generic.List[object]]::new()
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
        $script:PIIAccess = $true
        $script:ModernSharing = $false
        $script:SharingType = $null
        $script:OwnerMB = $null
        $script:ReceiverMB = $null
        $script:OwnerInviteData = @()
        $script:OwnerInviteCheckAvailable = $false
        $script:OwnerCalendarPerms = @()
        $script:OwnerCalendarPermsAvailable = $false
        $script:OwnerActiveReceiver = $null
        $script:OwnerActiveSharingAvailable = $false
        $script:ReceiverMatchedCalendar = $null
        $script:ReceiverCalendarCandidates = @()
    }

    function Initialize-OwnerMocks {
        $Script:ownerMailbox = [PSCustomObject]@{
            DisplayName            = "Owner Display"
            OrganizationalUnitRoot = "OU1"
            GrantSendOnBehalfTo    = @()
        }
        $Script:ownerCalendarFolder = [PSCustomObject]@{
            PublishEnabled      = $false
            ExtendedFolderFlags = @("SharedOut", "ExchangeShareFolder")
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
                FolderType           = "Calendar"
                Name                 = "Calendar"
                FolderPath           = "/Calendar"
                FolderSize           = "1 KB (1,024 bytes)"
                VisibleItemsInFolder = 10
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
                FolderType           = "Calendar"
                Name                 = "Calendar"
                FolderPath           = "/Calendar"
                FolderSize           = "1 KB"
                VisibleItemsInFolder = 10
            },
            [PSCustomObject]@{
                FolderType           = "User Created"
                Name                 = "Owner Display"
                FolderPath           = "/Owner Display"
                FolderSize           = "1 KB"
                VisibleItemsInFolder = 10
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

        It "reports non-None ActiveShareeFlags for the expected receiver" {
            $Script:activeSharees[0].ActiveShareeFlags = @("NeedsSync")

            GetOwnerInformation -Owner "owner@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR312"
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
    }

    Context "Periodic synchronization and start-date classifications" {
        BeforeEach {
            Initialize-ReceiverMocks
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

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

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
    }
}
