# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Script parameters are set to exercise dot-sourced functions')]
[CmdletBinding()]
param()

# cSpell:ignore Sharee Sharees SRES Kalender
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
        "SHR100", "SHR101", "SHR110", "SHR111", "SHR112", "SHR113", "SHR120", "SHR121", "SHR122", "SHR123",
        "SHR130",
        "SHR200", "SHR201", "SHR210", "SHR211", "SHR212", "SHR213", "SHR214", "SHR215", "SHR220",
        "SHR230", "SHR231", "SHR232", "SHR233", "SHR240", "SHR241", "SHR242", "SHR243",
        "SHR300", "SHR301", "SHR310", "SHR311", "SHR312", "SHR320", "SHR321", "SHR322",
        "SHR323", "SHR324", "SHR325", "SHR400", "SHR401", "SHR402", "SHR403", "SHR404", "SHR405", "SHR406", "SHR407", "SHR408", "SHR409",
        "SHR410", "SHR411", "SHR412", "SHR413", "SHR414",
        "SHR420", "SHR421", "SHR422", "SHR423", "SHR424", "SHR430", "SHR431", "SHR432"
    )
    $Script:collectorNames = @(
        "OwnerMailbox", "ReceiverMailbox", "OwnerFolderStatistics", "ReceiverFolderStatistics",
        "OwnerCalendarPermissions", "OwnerMailboxPermissions", "OwnerInviteLog", "OwnerCalendarFolder",
        "ActiveSharing", "ReceiverAcceptLog", "CalendarEntries", "ReceiverLocalCalendarFolder",
        "InternetCalendar", "ReceiverSharingSyncAssistantLog", "ReceiverSharingLog"
    )

    function Initialize-SharingTestState {
        $script:SharingFindings = [System.Collections.Generic.List[object]]::new()
        $script:RunStartedAt = [DateTime]::new(2026, 10, 23, 13, 22, 0)
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
        $script:Owner = "owner@contoso.com"
        $script:Receiver = "receiver@contoso.com"
        $script:PIIAccess = $true
        $script:ModernSharing = $false
        $script:LegacyMapiSharing = $false
        $script:PublishedSharing = $false
        $script:ExternalSharing = $false
        $script:OwnerPublished = $false
        $script:OwnerPublishedICalUrl = $null
        $script:ReceiverInternetCalendarEntries = @()
        $script:ReceiverPublishedCalendarEntry = $null
        $script:ReceiverPublishedCalendarFolder = $null
        $script:SharingType = $null
        $script:OwnerMB = $null
        $script:ReceiverMB = $null
        $script:OwnerInviteData = @()
        $script:OwnerInviteCheckAvailable = $false
        $script:OwnerCalendarPerms = @()
        $script:OwnerCalendarPermsAvailable = $false
        $script:OwnerMailboxPerms = @()
        $script:OwnerMailboxPermsAvailable = $false
        $script:OwnerCalendarStats = @()
        $script:OwnerSelectedCalendar = $null
        $script:OwnerCalendarFolder = $null
        $script:OwnerCalendarFolderIdentity = $null
        $script:OwnerCalendarRootName = $null
        $script:OwnerCalendarLeafName = $null
        $script:OwnerCalendarLeafNameCandidate = $null
        $script:OwnerCalendarFolderPathSpecified = $false
        $script:OwnerCalendarSubfolderSelected = $false
        $script:NormalizedOwnerCalendarFolderPath = $null
        $script:RequestedOwnerCalendarLeafName = $null
        $script:ReceiverAcceptLogEntries = @()
        $script:ReceiverSelectedAcceptLogEntries = @()
        $script:OwnerActiveReceiver = $null
        $script:OwnerActiveSharingAvailable = $false
        $script:ReceiverMatchedCalendar = $null
        $script:ReceiverLocalCalendarFolder = $null
        $script:ReceiverCalendarEntries = @()
        $script:ReceiverFolderStatistics = @()
        $script:ReceiverCalendarCandidates = @()
        $script:CalendarStatisticsComparisonPerformed = $false
        $script:CalendarStatisticsComparison = $null
        $script:FatalPrerequisiteFailure = $null
        $script:SharingLogScanPerformed = $true
        $script:OwnerInviteLogRaw = $null
        $script:ReceiverAcceptLogRaw = $null
        $script:SharingDiagnosticLogs = [ordered]@{}
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
            PublishedCalendarUrl            = $null
            PublishedICalUrl                = $null
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

Describe "Check-SharingStatus source layout" {
    It "keeps diagnostic functions in helpers and orchestration in the entry script" {
        $parseErrors = $null
        $entryAst = [System.Management.Automation.Language.Parser]::ParseFile(
            "$Script:parentPath\Check-SharingStatus.ps1",
            [ref]$null,
            [ref]$parseErrors)

        $parseErrors | Should -BeNullOrEmpty
        $entryFunctions = @($entryAst.EndBlock.Statements | Where-Object -FilterScript {
                $_ -is [System.Management.Automation.Language.FunctionDefinitionAst]
            })
        $entryFunctions.Name | Should -Be @("Invoke-SharingDiagnostics")
    }
}

Describe "Check-SharingStatus resolved permission identities" {
    BeforeEach {
        Initialize-SharingTestState
        $script:ReceiverMB = [PSCustomObject]@{
            DisplayName        = "Receiver Name/Department/Location"
            PrimarySmtpAddress = "receiver@contoso.com"
            EmailAddresses     = @("SMTP:receiver@contoso.com", "smtp:old.receiver@contoso.com", "X500:/o=Example/ou=Receiver")
        }
    }

    It -Name "matches <Case> as Match=<Match>" -TestCases @(
        @{ Case = "primary SMTP"; User = "receiver@contoso.com"; Match = $true }
        @{ Case = "SMTP alias"; User = " OLD.RECEIVER@CONTOSO.COM "; Match = $true }
        @{ Case = "display name"; User = "Receiver Name/Department/Location"; Match = $true }
        @{ Case = "display name with casing and whitespace"; User = " receiver name/department/location "; Match = $true }
        @{ Case = "display-name property"; User = [PSCustomObject]@{ DisplayName = "Receiver Name/Department/Location" }; Match = $true }
        @{ Case = "AD recipient SMTP alias"; User = [PSCustomObject]@{ ADRecipient = [PSCustomObject]@{ PrimarySmtpAddress = "old.receiver@contoso.com" } }; Match = $true }
        @{ Case = "recipient principal SMTP alias"; User = [PSCustomObject]@{ RecipientPrincipal = [PSCustomObject]@{ PrimarySmtpAddress = "old.receiver@contoso.com" } }; Match = $true }
        @{ Case = "primary SMTP property"; User = [PSCustomObject]@{ PrimarySmtpAddress = "receiver@contoso.com" }; Match = $true }
        @{ Case = "another SMTP recipient"; User = "other@contoso.com"; Match = $false }
        @{ Case = "partial display name"; User = "Receiver Name"; Match = $false }
        @{ Case = "different display name"; User = "Receiver Name/Another Department/Location"; Match = $false }
        @{ Case = "non-SMTP proxy"; User = "/o=Example/ou=Receiver"; Match = $false }
        @{ Case = "Default"; User = "Default"; Match = $false }
        @{ Case = "Anonymous"; User = "Anonymous"; Match = $false }
        @{ Case = "mailbox self"; User = "NT AUTHORITY\SELF"; Match = $false }
        @{ Case = "missing user"; User = $null; Match = $false }
        @{ Case = "empty user"; User = ""; Match = $false }
        @{ Case = "conflicting SMTP identity"; User = [PSCustomObject]@{ DisplayName = "Receiver Name/Department/Location"; PrimarySmtpAddress = "other@contoso.com" }; Match = $false }
        @{ Case = "conflicting AD identity"; User = [PSCustomObject]@{ DisplayName = "Receiver Name/Department/Location"; ADRecipient = [PSCustomObject]@{ PrimarySmtpAddress = "other@contoso.com" } }; Match = $false }
        @{ Case = "a group with the same name"; User = [PSCustomObject]@{ DisplayName = "Receiver Name/Department/Location"; RecipientTypeDetails = "MailUniversalSecurityGroup" }; Match = $false }
    ) {
        param($Case, $User, $Match)

        $permissions = @([PSCustomObject]@{ User = $User; AccessRights = @("Editor") })
        $matchedPermissions = @(Get-PermissionEntriesForIdentity -PermissionEntries $permissions `
                -Identity $Receiver -Mailbox $script:ReceiverMB)

        $matchedPermissions.Count | Should -Be ([int]$Match)
    }

    It "matches the primary SMTP when the supplied identity is an alias" {
        $permissions = @([PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("Editor") })

        @(Get-PermissionEntriesForIdentity -PermissionEntries $permissions `
                -Identity "old.receiver@contoso.com" -Mailbox $script:ReceiverMB).Count | Should -Be 1
    }

    It "does not confuse empty mailbox properties with a missing permission user" {
        $permissions = @([PSCustomObject]@{ User = ""; AccessRights = @("Editor") })
        $script:ReceiverMB = [PSCustomObject]@{ DisplayName = ""; PrimarySmtpAddress = ""; EmailAddresses = @("smtp:") }

        @(Get-PermissionEntriesForIdentity -PermissionEntries $permissions `
                -Identity $Receiver -Mailbox $script:ReceiverMB).Count | Should -Be 0
    }

    It "preserves direct SMTP matching without a resolved mailbox" {
        $permissions = @([PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("Editor") })

        @(Get-PermissionEntriesForIdentity -PermissionEntries $permissions -Identity $Receiver).Count | Should -Be 1
    }

    It -Name "summarizes named calendar and alias mailbox permissions with Deny=<Deny>" -TestCases @(
        @{ Deny = $false }
        @{ Deny = $true }
    ) {
        param($Deny)
        $script:OwnerCalendarPerms = @(
            [PSCustomObject]@{ User = $script:ReceiverMB.DisplayName; AccessRights = @("Editor") }
        )
        $script:OwnerMailboxPerms = @(
            [PSCustomObject]@{ User = "old.receiver@contoso.com"; AccessRights = @("FullAccess"); Deny = $Deny }
        )
        $script:OwnerCalendarPermsAvailable = $true
        $script:OwnerMailboxPermsAvailable = $true
        Mock -CommandName Write-Host -MockWith {}

        Write-OwnerReceiverPermissionSummary -Receiver $Receiver

        if ($Deny) {
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] is using [Editor] on the owner Calendar folder."
            }
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] has Deny entries for [FullAccess] on the owner Mailbox."
            }
        } else {
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] has [Editor] on the owner Calendar folder and [FullAccess] on the owner Mailbox."
            }
        }
        Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -like "*does not have an individual permission entry*"
        }
    }

    It "recognizes a named Editor entry without treating it as calendar delegate permission" {
        $script:OwnerCalendarPermsAvailable = $true
        $script:OwnerCalendarPerms = @(
            [PSCustomObject]@{ User = $script:ReceiverMB.DisplayName; AccessRights = @("Editor"); SharingPermissionFlags = $null }
        )
        $script:OwnerActiveReceiver = [PSCustomObject]@{ SharingPermissionFlags = @("Delegate") }
        Mock -CommandName Write-Host -MockWith {}

        Test-ReceiverDelegatePermissions

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325"
        $finding.evidence.individualPermissionFound | Should -BeTrue
        $finding.evidence.delegatePermissionFound | Should -BeFalse
        $finding.status | Should -Be "Detected"
    }

    It -Name "counts single permission results independently of their Count property (<PermissionCount>)" -TestCases @(
        @{ PermissionCount = $null }
        @{ PermissionCount = 0 }
    ) {
        param($PermissionCount)
        $script:OwnerCalendarPerms = @(
            [PSCustomObject]@{ User = $script:ReceiverMB.DisplayName; AccessRights = @("Editor"); Count = $PermissionCount }
        )
        $script:OwnerMailboxPerms = @(
            [PSCustomObject]@{ User = "old.receiver@contoso.com"; AccessRights = @("FullAccess"); Count = $PermissionCount }
        )
        $script:OwnerCalendarPermsAvailable = $true
        $script:OwnerMailboxPermsAvailable = $true
        Mock -CommandName Write-Host -MockWith {}

        Write-OwnerReceiverPermissionSummary -Receiver $Receiver

        Should -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -eq "Receiver [receiver@contoso.com] has [Editor] on the owner Calendar folder and [FullAccess] on the owner Mailbox."
        }
        Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -like "*does not have an individual permission entry*"
        }
    }
}

Describe "Check-SharingStatus permission flag comparison" {
    It -Name "returns Differ=<Differ> for <Case>" -TestCases @(
        @{ Case = "identical flags"; First = @("Delegate"); Second = @("Delegate"); Differ = $false }
        @{ Case = "Editor as the only difference"; First = @("Delegate"); Second = @("Editor", "Delegate"); Differ = $false }
        @{ Case = "Editor as the only difference in the other direction"; First = @("Editor", "Delegate"); Second = @("Delegate"); Differ = $false }
        @{ Case = "Editor with different casing as the only difference"; First = @("Delegate"); Second = @("editor", "Delegate"); Differ = $false }
        @{ Case = "a flag other than Editor differing"; First = @("Delegate"); Second = @("Editor", "Reviewer"); Differ = $true }
        @{ Case = "a flag missing when Editor is also present"; First = @("Editor", "Delegate"); Second = @("Editor"); Differ = $true }
        @{ Case = "null flags"; First = $null; Second = @("Editor"); Differ = $false }
        @{ Case = "a single comma-separated flags value with Editor as the only difference"; First = @("Delegate"); Second = @("Editor, Delegate"); Differ = $false }
        @{ Case = "single comma-separated flags values that are identical"; First = @("Editor, Delegate"); Second = @("Editor, Delegate"); Differ = $false }
        @{ Case = "a single comma-separated flags value with a real difference"; First = @("Delegate"); Second = @("Editor, Reviewer"); Differ = $true }
    ) {
        param($Case, $First, $Second, $Differ)

        Test-SharingPermissionFlagsDiffer -FirstFlags $First -SecondFlags $Second | Should -Be $Differ
    }
}

Describe "Check-SharingStatus published calendar URLs" {
    It -Name "matches <Case> as Equal=<Equal>" -TestCases @(
        @{ Case = "identical URLs"; Other = "https://example.com/calendar/AbCd.ics?token=EfGh"; Equal = $true }
        @{ Case = "scheme and host casing"; Other = "HTTPS://EXAMPLE.COM/calendar/AbCd.ics?token=EfGh"; Equal = $true }
        @{ Case = "surrounding whitespace"; Other = " https://example.com/calendar/AbCd.ics?token=EfGh "; Equal = $true }
        @{ Case = "default port"; Other = "https://example.com:443/calendar/AbCd.ics?token=EfGh"; Equal = $true }
        @{ Case = "different path casing"; Other = "https://example.com/calendar/abcd.ics?token=EfGh"; Equal = $false }
        @{ Case = "different query casing"; Other = "https://example.com/calendar/AbCd.ics?token=efgh"; Equal = $false }
        @{ Case = "different host"; Other = "https://other.example.com/calendar/AbCd.ics?token=EfGh"; Equal = $false }
        @{ Case = "different scheme"; Other = "http://example.com/calendar/AbCd.ics?token=EfGh"; Equal = $false }
        @{ Case = "different port"; Other = "https://example.com:444/calendar/AbCd.ics?token=EfGh"; Equal = $false }
        @{ Case = "relative URL"; Other = "/calendar/AbCd.ics?token=EfGh"; Equal = $false }
        @{ Case = "malformed URL"; Other = "https://"; Equal = $false }
        @{ Case = "empty URL"; Other = ""; Equal = $false }
        @{ Case = "missing URL"; Other = $null; Equal = $false }
    ) {
        param($Case, $Other, $Equal)

        $ownerUrl = "https://example.com/calendar/AbCd.ics?token=EfGh"
        Test-PublishedCalendarUrlEqual -First $ownerUrl -Second $Other | Should -Be $Equal
        Test-PublishedCalendarUrlEqual -First $Other -Second $ownerUrl | Should -Be $Equal
    }
}

Describe "Check-SharingStatus published subscription history" {
    BeforeEach {
        Initialize-SharingTestState
        $script:OwnerPublished = $true
        $script:OwnerCalendarFolder = [PSCustomObject]@{ PublishEnabled = $true }
        $script:OwnerPublishedICalUrl = "https://example.com/calendar/AbCd.ics?token=EfGh"
        $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = $Receiver; SharingType = "publish" })
        foreach ($collectorName in @("OwnerCalendarFolder", "InternetCalendar", "ReceiverFolderStatistics")) {
            $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "Success"; error = $null }
        }
        Mock -CommandName Write-Host -MockWith {}
    }

    It -Name "uses an existing subscription folder with <Case>" -TestCases @(
        @{ Case = "oldest entry first"; Reverse = $false; OldTimestamp = "9/1/2026 12:00:00"; NewTimestamp = "10/22/2026 12:00:00"; BothLive = $false }
        @{ Case = "newest entry first"; Reverse = $true; OldTimestamp = "9/1/2026 12:00:00"; NewTimestamp = "10/22/2026 12:00:00"; BothLive = $false }
        @{ Case = "undated history"; Reverse = $false; OldTimestamp = $null; NewTimestamp = $null; BothLive = $false }
        @{ Case = "invalid timestamps"; Reverse = $false; OldTimestamp = "not-a-date"; NewTimestamp = "10/22/2026 12:00:00"; BothLive = $false }
        @{ Case = "a newer entry for a deleted folder"; Reverse = $false; OldTimestamp = "10/23/2026 12:00:00"; NewTimestamp = "10/22/2026 12:00:00"; BothLive = $false }
        @{ Case = "multiple existing folders"; Reverse = $false; OldTimestamp = "9/1/2026 12:00:00"; NewTimestamp = "10/22/2026 12:00:00"; BothLive = $true }
    ) {
        param($Case, $Reverse, $OldTimestamp, $NewTimestamp, $BothLive)

        $oldEntry = [PSCustomObject]@{
            Timestamp     = $OldTimestamp
            PublishingUrl = $script:OwnerPublishedICalUrl
            LocalFolderId = "old-id"
            Folder        = "Old copy"
        }
        $newEntry = [PSCustomObject]@{
            Timestamp     = $NewTimestamp
            PublishingUrl = $script:OwnerPublishedICalUrl
            LocalFolderId = "current-id"
            Folder        = "Current copy"
        }
        $script:ReceiverInternetCalendarEntries = if ($Reverse) { @($newEntry, $oldEntry) } else { @($oldEntry, $newEntry) }
        $script:ReceiverFolderStatistics = @(
            [PSCustomObject]@{ FolderId = "current-id"; Name = "Current copy"; FolderPath = "/Current copy" }
            if ($BothLive) {
                [PSCustomObject]@{ FolderId = "old-id"; Name = "Old copy"; FolderPath = "/Old copy" }
            }
        )

        Test-PublishedCalendarRelationship
        Complete-SharingFindings

        $script:ReceiverPublishedCalendarEntry.LocalFolderId | Should -Be "current-id"
        $script:ReceiverPublishedCalendarFolder.FolderId | Should -Be "current-id"
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR422").status | Should -Be "NotDetected"
    }

    It "reports a missing folder only when none of the matching subscriptions has a folder" {
        $script:ReceiverInternetCalendarEntries = @(
            [PSCustomObject]@{ PublishingUrl = $script:OwnerPublishedICalUrl; LocalFolderId = "old-id" }
            [PSCustomObject]@{ PublishingUrl = $script:OwnerPublishedICalUrl; LocalFolderId = "current-id" }
        )
        $script:ReceiverFolderStatistics = @(
            [PSCustomObject]@{ FolderId = "unrelated-id"; Name = "Other calendar" }
        )

        Test-PublishedCalendarRelationship

        $script:ReceiverPublishedCalendarFolder | Should -BeNullOrEmpty
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR422").status | Should -Be "Detected"
    }

    It -Name "rejects a subscription with different <Component> case after Collect=<Collect>" -TestCases @(
        @{ Component = "path"; Url = "https://example.com/calendar/abcd.ics?token=EfGh"; Collect = $false }
        @{ Component = "query"; Url = "https://example.com/calendar/AbCd.ics?token=efgh"; Collect = $false }
        @{ Component = "path"; Url = "https://example.com/calendar/abcd.ics?token=EfGh"; Collect = $true }
        @{ Component = "query"; Url = "https://example.com/calendar/AbCd.ics?token=efgh"; Collect = $true }
    ) {
        param($Component, $Url, $Collect)

        $script:ReceiverInternetCalendarEntries = @([PSCustomObject]@{ PublishingUrl = $Url; LocalFolderId = "unrelated-id" })
        if ($Collect) {
            $script:ReceiverInternetCalendarEntries = @()
            $script:CollectorStatuses["InternetCalendar"].status = "NotRun"
            Mock -CommandName ProcessInternetCalendarLogs -MockWith {
                $script:CollectorStatuses["InternetCalendar"].status = "Success"
                $script:ReceiverInternetCalendarEntries = @([PSCustomObject]@{ PublishingUrl = $Url; LocalFolderId = "unrelated-id" })
            }
        }

        Test-PublishedCalendarRelationship
        Complete-SharingFindings

        $script:ReceiverPublishedCalendarEntry | Should -BeNullOrEmpty
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR421").status | Should -Be "Detected"
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR422").status | Should -Be "NotApplicable"
    }

    It "does not establish publishing from a URL with different path case" {
        $script:OwnerInviteData = @()
        $script:ReceiverInternetCalendarEntries = @(
            [PSCustomObject]@{ PublishingUrl = "https://example.com/calendar/abcd.ics?token=EfGh" }
        )

        Test-PublishedCalendarRelationship

        $script:PublishedSharing | Should -BeFalse
        $script:SharingFindings.Count | Should -Be 0
    }
}

Describe "Check-SharingStatus explicit receiver delegation" {
    BeforeEach {
        Initialize-SharingTestState
        $script:OwnerCalendarPermsAvailable = $true
        $script:CollectorStatuses["ActiveSharing"] = [PSCustomObject]@{ status = "Success"; error = $null }
        $script:CollectorStatuses["ReceiverLocalCalendarFolder"] = [PSCustomObject]@{ status = "Success"; error = $null }
        $script:OwnerActiveReceiver = [PSCustomObject]@{ SharingPermissionFlags = @("Delegate") }
        Mock -CommandName Write-Host -MockWith {}
    }

    It -Name "rejects <Case> as a substitute for individual delegate permissions" -TestCases @(
        @{ Case = "a group"; PermissionUser = "delegates@contoso.com" }
        @{ Case = "Default"; PermissionUser = "Default" }
        @{ Case = "Anonymous"; PermissionUser = "Anonymous" }
        @{ Case = "another delegate"; PermissionUser = "other@contoso.com" }
    ) {
        param($Case, $PermissionUser)
        $script:OwnerCalendarPerms = @(
            [PSCustomObject]@{ User = $PermissionUser; AccessRights = @("Editor"); SharingPermissionFlags = @("Delegate") }
        )
        $script:OwnerMailboxPerms = @(
            [PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("FullAccess") }
        )

        Test-ReceiverDelegatePermissions
        Complete-SharingFindings

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325"
        $finding.status | Should -Be "Detected"
        $finding.severity | Should -Be "Error"
        $finding.evidence.individualPermissionFound | Should -BeFalse
        $finding.evidence.receiver | Should -Be "Receiver"
        $finding.recommendedNextStep | Should -Match "individual.*Editor.*Delegate"
        Should -Invoke -CommandName Write-Host -ParameterFilter {
            ($ForegroundColor -eq "Red") -and ($Object -like "*Group or Default*")
        }
    }

    It -Name "rejects explicit receiver rights <Rights> with flags <Flags>" -TestCases @(
        @{ Rights = @("Reviewer"); Flags = @("Delegate") }
        @{ Rights = @("Owner"); Flags = @("Delegate") }
        @{ Rights = @("Editor"); Flags = @("None") }
        @{ Rights = @("Editor"); Flags = @() }
        @{ Rights = @(); Flags = @("Delegate") }
    ) {
        param($Rights, $Flags)
        $script:OwnerCalendarPerms = @(
            [PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = $Rights; SharingPermissionFlags = $Flags }
        )

        Test-ReceiverDelegatePermissions

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325"
        $finding.status | Should -Be "Detected"
        $finding.evidence.individualPermissionFound | Should -BeTrue
        $finding.evidence.delegatePermissionFound | Should -BeFalse
    }

    It -Name "accepts an explicit receiver entry through <Shape>" -TestCases @(
        @{ Shape = "SMTP address"; PermissionUser = " RECEIVER@Contoso.com "; Flags = @("Delegate") }
        @{ Shape = "AD recipient"; PermissionUser = [PSCustomObject]@{ ADRecipient = [PSCustomObject]@{ PrimarySmtpAddress = "receiver@contoso.com" } }; Flags = @("Delegate", "CanViewPrivateItems") }
        @{ Shape = "comma-separated enum flags"; PermissionUser = "receiver@contoso.com"; Flags = @("Delegate, CanViewPrivateItems") }
    ) {
        param($Shape, $PermissionUser, $Flags)
        $script:OwnerCalendarPerms = @(
            [PSCustomObject]@{ User = $PermissionUser; AccessRights = @("Editor"); SharingPermissionFlags = $Flags },
            [PSCustomObject]@{ User = "delegates@contoso.com"; AccessRights = @("Editor"); SharingPermissionFlags = @("Delegate") }
        )
        $script:OwnerActiveReceiver = $null
        $script:CollectorStatuses["ActiveSharing"].status = "Unavailable"

        Test-ReceiverDelegatePermissions

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325"
        $finding.status | Should -Be "NotDetected"
        $finding.evidence.delegatePermissionFound | Should -BeTrue
        Should -Not -Invoke -CommandName Write-Host
    }

    It -Name "recognizes delegate evidence from <Source> without requiring a matched local folder" -TestCases @(
        @{ Source = "owner permissions" }
        @{ Source = "active sharing" }
        @{ Source = "receiver folder" }
    ) {
        param($Source)
        $script:OwnerActiveReceiver = $null
        $script:CollectorStatuses["ActiveSharing"].status = "Unavailable"
        $script:CollectorStatuses["ReceiverLocalCalendarFolder"].status = "NotEvaluated"
        switch ($Source) {
            "owner permissions" {
                $script:OwnerCalendarPerms = @(
                    [PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("Reviewer"); SharingPermissionFlags = @("Delegate") }
                )
            }
            "active sharing" {
                $script:OwnerActiveReceiver = [PSCustomObject]@{ SharingPermissionFlags = @("Delegate, CanViewPrivateItems") }
                $script:CollectorStatuses["ActiveSharing"].status = "Success"
            }
            "receiver folder" {
                $script:ReceiverLocalCalendarFolder = [PSCustomObject]@{ SharingPermissionFlags = @("Delegate") }
                $script:CollectorStatuses["ReceiverLocalCalendarFolder"].status = "Success"
            }
        }

        Test-ReceiverDelegatePermissions

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status | Should -Be "Detected"
    }

    It "does not combine rights and flags from separate permission entries" {
        $script:OwnerCalendarPerms = @(
            [PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("Editor"); SharingPermissionFlags = @("None") },
            [PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("Reviewer"); SharingPermissionFlags = @("Delegate") }
        )

        Test-ReceiverDelegatePermissions

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status | Should -Be "Detected"
    }

    It "reports unavailable calendar permissions as incomplete rather than a pass or a confirmed failure" {
        $script:OwnerCalendarPermsAvailable = $false

        Test-ReceiverDelegatePermissions

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325"
        $finding.status | Should -Be "NotEvaluated"
        $finding.title | Should -Be "Receiver delegation check could not be completed"
        $finding.recommendedNextStep | Should -BeLike "Confirm whether the receiver is intended to be a delegate.*"
        $finding.recommendedNextStep | Should -Not -BeLike "Grant the receiver*"
    }

    It "does not infer delegation from another delegate or group" {
        $script:OwnerActiveReceiver = $null
        $script:OwnerCalendarPerms = @(
            [PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("Reviewer"); SharingPermissionFlags = @("None") },
            [PSCustomObject]@{ User = "delegates@contoso.com"; AccessRights = @("Editor"); SharingPermissionFlags = @("Delegate") }
        )

        Test-ReceiverDelegatePermissions

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status | Should -Be "NotApplicable"
    }

    It -Name "reports missing <Collector> evidence as incomplete when delegation is unknown" -TestCases @(
        @{ Collector = "ActiveSharing" }
        @{ Collector = "ReceiverLocalCalendarFolder" }
    ) {
        param($Collector)
        $script:OwnerActiveReceiver = $null
        $script:CollectorStatuses[$Collector].status = "Unavailable"

        Test-ReceiverDelegatePermissions

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325"
        $finding.status | Should -Be "NotEvaluated"
        $finding.title | Should -Be "Receiver delegation check could not be completed"
        $finding.recommendedNextStep | Should -BeLike "Confirm whether the receiver is intended to be a delegate.*"
        $reportedFinding = (Get-SharingJsonReportObject).findings | Where-Object -Property ruleId -EQ "SHR325"
        $reportedFinding.result | Should -Be "Inconclusive"
        $reportedFinding.title | Should -Be $finding.title
        $reportedFinding.recommendedNextStep | Should -Be $finding.recommendedNextStep
    }

    It "checks explicit calendar delegation for legacy MAPI relationships" {
        $script:LegacyMapiSharing = $true

        Test-ReceiverDelegatePermissions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status | Should -Be "Detected"
    }

    It "does not require delegation for a published subscription" {
        $script:PublishedSharing = $true

        Test-ReceiverDelegatePermissions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status | Should -Be "NotApplicable"
    }

    It "does not report a pass when the delegate check was not performed" {
        Complete-SharingFindings

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325"
        $finding.status | Should -Be "NotEvaluated"
        $finding.title | Should -Be "Receiver delegation check could not be completed"
        $finding.recommendedNextStep | Should -BeLike "Confirm whether the receiver is intended to be a delegate.*"
    }
}

Describe "Check-SharingStatus log exceptions and age filter" {
    BeforeEach {
        Initialize-SharingTestState
        $script:SharingLogScanPerformed = $false
        Mock Write-Host {}
        Mock Write-Warning {}
        $script:RecentStamp = (Get-Date).ToUniversalTime().AddDays(-3).ToString("MM/dd/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
    }

    It "detects the named property quota exception and reports the other exceptions separately" {
        $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"] = [ordered]@{
            status = "Collected"
            data   = @(
                "$script:RecentStamp, Mailbox: 'R', Entry Sync Details for folder A are [SRES, True];[EX, QuotaExceededException_Cannot get ID from name._MapiExceptionNamedPropsQuotaExceeded_MapiExceptionNamedPropsQuotaExceeded: GetIdsFromNames operation has failed (hr=0x80040900, ec=-2147219200)];[ERR, ]",
                "$script:RecentStamp, Mailbox: 'R', Entry Sync Details for folder B are [SRES, True];[EX, ];[ERR, ]"
            )
        }
        $script:ReceiverAcceptLogRaw = @(
            "$script:RecentStamp, Mailbox: 'R', Entry Microsoft.Exchange.Data.Storage.WrongObjectTypeException: The object was bound to a wrong object type.",
            "$script:RecentStamp, Mailbox: 'R', Entry CreateInternalSharedCalendarGroupEntry: ok"
        ) -join "`r`n"

        Test-SharingLogExceptions
        Complete-SharingFindings

        $quota = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR408"
        $quota.status | Should -Be "Detected"
        $quota.severity | Should -Be "Error"
        $quota.evidence.quotaExceptionCount | Should -Be 1
        $quota.evidence.affectedLogs | Should -Contain "Receiver SharingSyncAssistant"
        $quota.evidence.latestEntryUtc | Should -Not -BeNullOrEmpty
        $exceptions = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR409"
        $exceptions.status | Should -Be "Detected"
        $exceptions.evidence.exceptionCount | Should -Be 1
        $exceptions.evidence.exceptionTypes | Should -Contain "WrongObjectTypeException"
        $exceptions.evidence.affectedLogs | Should -Contain "Receiver AcceptCalendarSharingInvite"
    }

    It "does not flag benign log content" {
        $script:SharingDiagnosticLogs["receiver_SharingLog"] = [ordered]@{
            status = "Collected"
            data   = @(
                "$script:RecentStamp, Mailbox: 'R', Entry X : Synchronized 1 out of 1 items during this batch. Here count of numberOfFailures: 0 and skippedFailuresCount: 0..",
                "$script:RecentStamp, Mailbox: 'R', Entry Sync Details for folder A are [SRES, True];[EX, ];[ERR, ]"
            )
        }
        $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"] = [ordered]@{
            status = "Collected"
            data   = @("$script:RecentStamp, Mailbox: 'R', Entry Failed to read user configuration time zone. Use default session time zone")
        }

        Test-SharingLogExceptions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR408").status | Should -Be "NotDetected"
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR409").status | Should -Be "NotDetected"
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR414").status | Should -Be "NotDetected"
    }

    It "flags non-zero batch failures" {
        $script:SharingDiagnosticLogs["receiver_SharingLog"] = [ordered]@{
            status = "Collected"
            data   = @("$script:RecentStamp, Mailbox: 'R', Entry X : Here count of numberOfFailures: 3 and skippedFailuresCount: 0..")
        }

        Test-SharingLogExceptions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR409").status | Should -Be "Detected"
    }

    It "marks the exception rules NotEvaluated when the logs were not scanned" {
        Complete-SharingFindings

        foreach ($ruleId in @("SHR408", "SHR409", "SHR414")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotEvaluated"
        }
    }

    It -Name "does not pass exception checks when all logs are <Status>" -TestCases @(
        @{ Status = "Missing" }
        @{ Status = "NoData" }
        @{ Status = "Failed" }
        @{ Status = "NotCollected" }
    ) {
        param($Status)
        $script:SharingLogScanPerformed = $true
        if ($Status -ne "Missing") {
            foreach ($logKey in @("receiver_SharingSyncAssistantLog", "receiver_SharingLog")) {
                $script:SharingDiagnosticLogs[$logKey] = @{ status = $Status; data = $null }
            }
        }

        Test-SharingLogExceptions
        Complete-SharingFindings

        $script:SharingLogScanPerformed | Should -BeFalse
        foreach ($ruleId in @("SHR408", "SHR409", "SHR414")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotEvaluated"
        }
        Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -like "No exceptions were found*"
        }
    }

    It -Name "completes an available exception scan after all <Source> entries were filtered by age" -TestCases @(
        @{ Source = "owner invite" }
        @{ Source = "receiver sharing" }
    ) {
        param($Source)
        if ($Source -eq "owner invite") {
            $script:OwnerInviteLogRaw = "01/01/2020 12:00:00, InvalidOperationException"
        } else {
            $script:SharingDiagnosticLogs["receiver_SharingLog"] = @{ status = "Collected"; data = @() }
        }

        Test-SharingLogExceptions
        Complete-SharingFindings

        $script:SharingLogScanPerformed | Should -BeTrue
        foreach ($ruleId in @("SHR408", "SHR409", "SHR414")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotDetected"
        }
    }

    It -Name "points tenant administrators to public XTAP guidance for failures in <Source>" -TestCases @(
        @{ Source = "Owner invite" }
        @{ Source = "Receiver accept" }
        @{ Source = "Receiver sharing" }
        @{ Source = "Receiver sync" }
    ) {
        param($Source)
        $lines = @(
            "$script:RecentStamp, Mailbox: test, Entry [XTAP] Starting XTAP policy evaluation"
            '[XTAP][UR] Flow failure (strictMode=False): DsApiForbiddenException: Missing RequiredPermission'
            '[XTAP] XTAPPolicyFound=False'
        )
        switch ($Source) {
            "Owner invite" { $script:OwnerInviteLogRaw = $lines -join "`r`n" }
            "Receiver accept" { $script:ReceiverAcceptLogRaw = $lines -join "`r`n" }
            "Receiver sharing" { $script:SharingDiagnosticLogs["receiver_SharingLog"] = @{ data = $lines } }
            "Receiver sync" { $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"] = @{ data = $lines } }
        }

        Test-SharingLogExceptions
        Complete-SharingFindings

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR414"
        $finding.status | Should -Be "Detected"
        $finding.severity | Should -Be "Warning"
        $finding.evidence.xtapFailureCount | Should -Be 1
        $finding.evidence.latestEntryUtc | Should -Not -BeNullOrEmpty
        $finding.recommendedNextStep | Should -BeLike "Tenant administrator:*https://learn.microsoft.com/en-us/exchange/sharing/migrate-to-m365-xtap*"
        $finding.recommendedNextStep | Should -BeLike "*failures for other recipients*"
        $reportedFinding = (Get-SharingJsonReportObject).findings | Where-Object -Property ruleId -EQ "SHR414"
        $reportedFinding.recommendedNextStep | Should -Be $finding.recommendedNextStep
    }

    It -Name "does not interpret benign XTAP trace <Trace> as a failure" -TestCases @(
        @{ Trace = "[XTAP] XTAPPolicyFound=False" }
        @{ Trace = "[XTAP] XTAPPolicyFound=True" }
        @{ Trace = "[XTAP] Starting XTAP policy evaluation" }
        @{ Trace = "[XTAP-Anon] Anonymous capability resolved: outcome=DenyExcluded, detailLevel=none" }
        @{ Trace = "[XTAP] numberOfFailures: 0" }
    ) {
        param($Trace)
        $script:OwnerInviteLogRaw = "$script:RecentStamp, Mailbox: test, Entry $Trace"

        Test-SharingLogExceptions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR414").status | Should -Be "NotDetected"
    }

    It "reports an explicit XTAP failure even without a named exception" {
        $script:OwnerInviteLogRaw = "$script:RecentStamp, Mailbox: test, Entry [XTAP] Policy evaluation failed"

        Test-SharingLogExceptions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR414").status | Should -Be "Detected"
        Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -like "No exceptions were found*"
        }
    }

    It "does not attribute an unrelated forbidden exception to XTAP" {
        $script:OwnerInviteLogRaw = "$script:RecentStamp, Mailbox: test, Entry DsApiForbiddenException"

        Test-SharingLogExceptions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR409").status | Should -Be "Detected"
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR414").status | Should -Be "NotDetected"
    }

    It "does not report XTAP failures older than one year" {
        $script:OwnerInviteLogRaw = @(
            "$script:RecentStamp, Mailbox: test, Entry [XTAP] Starting XTAP policy evaluation"
            "01/01/2020 12:00:00, Mailbox: test, Entry [XTAP][UR] Flow failure: DsApiForbiddenException"
        ) -join "`r`n"

        Test-SharingLogExceptions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR414").status | Should -Be "NotDetected"
    }

    It "omits entries older than one year and keeps continuation lines with their entry" {
        $reference = [DateTime]::new(2026, 10, 20, 0, 0, 0, [DateTimeKind]::Utc)
        $lines = @(
            "10/01/2026 10:00:00, recent entry",
            "   at Recent.StackFrame()",
            "10/21/2025 10:00:00, just inside the year",
            "10/19/2024 10:00:00, old entry",
            "   at Old.StackFrame()",
            "05/15/2022 10:00:00, very old entry"
        )

        $result = Select-CalendarDiagnosticLogLineWithinDays -Line $lines -ReferenceTimeUtc $reference -MaximumAgeDays 365

        $result.OmittedEntries | Should -Be 2
        $result.Line | Should -Be @(
            "10/01/2026 10:00:00, recent entry",
            "   at Recent.StackFrame()",
            "10/21/2025 10:00:00, just inside the year")
    }

    It "omits old entries when collecting diagnostic logs and records the count" {
        $script:OwnerMB = [PSCustomObject]@{ DisplayName = "Owner Display" }
        $script:ReceiverMB = [PSCustomObject]@{ DisplayName = "Receiver Display" }
        $oldStamp = (Get-Date).ToUniversalTime().AddDays(-800).ToString("MM/dd/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        Mock Export-MailboxDiagnosticLogs {
            [PSCustomObject]@{ MailboxLog = @("$script:RecentStamp, recent $ComponentName", "", "$script:OldStamp, old $ComponentName") -join "`r`n" }
        }
        $script:OldStamp = $oldStamp

        Get-SharingDiagnosticLogs

        $logEntry = $script:SharingDiagnosticLogs["receiver_SharingLog"]
        $logEntry.data.Count | Should -Be 1
        $logEntry.data[0] | Should -BeLike "*recent Sharing"
        $logEntry.omittedOlderThanOneYear | Should -Be 1
    }

    It "omits parsed entries older than one year from the JSON report" {
        $IncludeSensitiveData = $true
        $script:OwnerInviteData = @(
            [PSCustomObject]@{ Timestamp = $script:RecentStamp; Recipient = "receiver@contoso.com" },
            [PSCustomObject]@{ Timestamp = "01/02/2020 10:00:00"; Recipient = "old@contoso.com" }
        )
        $script:OwnerInviteLogRaw = @("$script:RecentStamp, recent invite", "", "01/02/2020 10:00:00, old invite") -join "`r`n"
        Complete-SharingFindings

        $rawData = (Get-SharingJsonReportObject).rawData

        $rawData.owner_InviteLog.data.Count | Should -Be 1
        $rawData.owner_InviteLog.omittedOlderThanOneYear | Should -Be 1
        $rawData.owner_InviteLogFull.data.Count | Should -Be 1
        $rawData.owner_InviteLogFull.omittedOlderThanOneYear | Should -Be 1
    }
}

Describe "Check-SharingStatus event chronology" {
    It "orders mixed regional timestamps without selecting a future interpretation" {
        $reference = [DateTime]::new(2026, 10, 23, 18, 0, 0, [DateTimeKind]::Utc)
        $entries = @(
            [PSCustomObject]@{ Timestamp = "12/10/2026 10:21:03" }
            [PSCustomObject]@{ Timestamp = "15/10/2026 15:44:29" }
            [PSCustomObject]@{ Timestamp = "10/21/2026 7:18:03 AM" }
        )

        $dated = @(Get-DatedSharingLogEntries -Entry $entries -ReferenceTimeUtc $reference)

        $dated[0].Entry.Timestamp | Should -Be "10/21/2026 7:18:03 AM"
        $dated[0].Date | Should -Be ([DateTime]::new(2026, 10, 21, 7, 18, 3, [DateTimeKind]::Utc))
        $dated[2].Date.Month | Should -Be 10
    }

    It "retains ISO timestamp support and normalizes it to UTC" {
        $entry = [PSCustomObject]@{ Timestamp = "2026-10-21T07:18:03Z" }
        $reference = [DateTime]::new(2026, 10, 23, 0, 0, 0, [DateTimeKind]::Utc)

        $dated = @(Get-DatedSharingLogEntries -Entry @($entry) -ReferenceTimeUtc $reference)

        $dated[0].Date | Should -Be ([DateTime]::new(2026, 10, 21, 7, 18, 3, [DateTimeKind]::Utc))
        $dated[0].Date.Kind | Should -Be ([DateTimeKind]::Utc)
    }

    It "does not accept a future ISO timestamp after converting time zones" {
        $entry = [PSCustomObject]@{ Timestamp = "2026-10-23T02:00:00+00:00" }
        $reference = [DateTime]::new(2026, 10, 23, 0, 0, 0, [DateTimeKind]::Utc)

        $dated = @(Get-DatedSharingLogEntries -Entry @($entry) -ReferenceTimeUtc $reference)

        $dated.Count | Should -Be 1
        $dated[0].Date | Should -BeNullOrEmpty
    }
}

Describe "Check-SharingStatus selected-calendar relationship assessment" {
    BeforeEach {
        Initialize-SharingTestState
        $script:OwnerCalendarSubfolderSelected = $true
        $script:NormalizedOwnerCalendarFolderPath = "\Calendar\Project Calendar"
        $script:RequestedOwnerCalendarLeafName = "Project Calendar"
        $script:OwnerMB = [PSCustomObject]@{
            ExchangeGuid   = "11111111-1111-1111-1111-111111111111"
            EmailAddresses = @("SMTP:owner@contoso.com", "smtp:owner-alias@contoso.com")
        }
        $script:ReceiverMB = [PSCustomObject]@{
            EmailAddresses = @("SMTP:receiver@contoso.com", "smtp:receiver-alias@contoso.com")
        }
        $script:OwnerCalendarPermsAvailable = $true
        $script:OwnerInviteCheckAvailable = $true
        $script:OwnerInviteData = @([PSCustomObject]@{
                Timestamp   = "10/22/2026 12:00:00"
                Recipient   = "receiver-alias@contoso.com"
                SharingType = "internal"
            })
        foreach ($collector in @("ActiveSharing", "CalendarEntries", "ReceiverFolderStatistics", "ReceiverAcceptLog")) {
            $script:CollectorStatuses[$collector] = [PSCustomObject]@{ status = "Success"; error = $null }
        }
        $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"] = [ordered]@{
            status = "Collected"
            data   = @("10/22/2026 12:00:00, unrelated log entry")
        }
        Mock -CommandName Write-Host -MockWith {}
    }

    It "does not confirm sub-calendar sharing from a mailbox invitation alone" {
        $assessment = Get-SharingRelationshipAssessment

        $assessment.status | Should -Be "NotConfirmed"
        $assessment.message | Should -Match "mailbox-level invitation exists.*calendar folder is unknown"
        $assessment.message | Should -Match "not proof that the calendar was never shared"
        $assessment.evidence.mailboxInviteCount | Should -Be 1
        $assessment.evidence.latestMailboxInviteTimestamp | Should -Be "10/22/2026 12:00:00"
        $assessment.evidence.mailboxInvitesIdentifyFolder | Should -BeFalse
        foreach ($key in @("individualPermissionFound", "activeRelationshipFound", "calendarEntryFound",
                "localFolderFound", "acceptanceFound", "synchronizationRequestFound")) {
            $assessment.evidence[$key] | Should -BeFalse
        }
        $assessment.unavailableEvidence.Count | Should -Be 0
    }

    It "reports unavailable evidence as null rather than a negative match" {
        $script:OwnerCalendarPermsAvailable = $false
        $script:CollectorStatuses["ReceiverFolderStatistics"].status = "Failed"
        $script:CollectorStatuses["ReceiverAcceptLog"].status = "Failed"
        $script:OwnerInviteCheckAvailable = $false

        $assessment = Get-SharingRelationshipAssessment

        $assessment.status | Should -Be "NotConfirmed"
        $assessment.evidence.mailboxInviteCount | Should -BeNullOrEmpty
        $assessment.evidence.latestMailboxInviteTimestamp | Should -BeNullOrEmpty
        $assessment.evidence.individualPermissionFound | Should -BeNullOrEmpty
        $assessment.evidence.localFolderFound | Should -BeNullOrEmpty
        $assessment.evidence.acceptanceFound | Should -BeNullOrEmpty
        $assessment.unavailableEvidence | Should -Contain "localFolderFound"
        $assessment.message | Should -Match "Some evidence sources were unavailable"
    }

    It "recognizes folder-specific <Source> evidence without claiming synchronization health" -TestCases @(
        @{ Source = "permission" }
        @{ Source = "active relationship" }
        @{ Source = "calendar entry" }
        @{ Source = "acceptance" }
        @{ Source = "synchronization request" }
    ) {
        param($Source)
        switch ($Source) {
            "permission" {
                $script:OwnerCalendarPerms = @([PSCustomObject]@{
                        User = "receiver-alias@contoso.com"; AccessRights = @("Reviewer")
                    })
            }
            "active relationship" { $script:OwnerActiveReceiver = [PSCustomObject]@{ EmailAddress = $Receiver } }
            "calendar entry" {
                $script:ReceiverCalendarEntries = @([PSCustomObject]@{
                        OwnerEmailAddress = "owner-alias@contoso.com"; CalendarName = "Project Calendar"
                    })
            }
            "acceptance" {
                $script:ReceiverAcceptLogEntries = @([PSCustomObject]@{
                        SharedCalendarOwner = "owner-alias@contoso.com"; FolderName = "Project Calendar"
                    })
            }
            "synchronization request" {
                $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"].data = @(
                    "10/22/2026 12:00:00, Entry RequestId: 'request', Sync Details for folder Project Calendar are [RMGUID, 11111111-1111-1111-1111-111111111111]"
                )
            }
        }

        $assessment = Get-SharingRelationshipAssessment

        $assessment.status | Should -Be "EvidenceFound"
        $assessment.message | Should -Match "does not establish synchronization health"
    }

    It "does not treat unrelated records, None permissions, or a folder name alone as proof" {
        $script:OwnerCalendarPerms = @([PSCustomObject]@{ User = $Receiver; AccessRights = @("None") })
        $script:ReceiverMatchedCalendar = [PSCustomObject]@{ Name = "Project Calendar" }
        $script:ReceiverCalendarEntries = @([PSCustomObject]@{
                OwnerEmailAddress = $Owner; CalendarName = "Other Calendar"
            })
        $script:ReceiverAcceptLogEntries = @([PSCustomObject]@{
                SharedCalendarOwner = "other@contoso.com"; FolderName = "Project Calendar"
            })
        $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"].data = @(
            "10/22/2026 12:00:00, Entry RequestId: 'request', Sync Details for folder Project Calendar are [RMGUID, 22222222-2222-2222-2222-222222222222]"
        )

        $assessment = Get-SharingRelationshipAssessment

        $assessment.status | Should -Be "NotConfirmed"
        $assessment.evidence.localFolderFound | Should -BeTrue
        $assessment.evidence.synchronizationRequestFound | Should -BeFalse
    }

    It "preserves missing-folder dependencies without masking collection failures or redaction" -TestCases @(
        @{ Case = "absent"; Expected = "NotApplicable" }
        @{ Case = "collection failed"; Expected = "NotEvaluated" }
        @{ Case = "folder details failed"; Expected = "NotEvaluated" }
        @{ Case = "redacted"; Expected = "NotEvaluated" }
    ) {
        param($Case, $Expected)
        if ($Case -eq "collection failed") {
            $script:CollectorStatuses["ReceiverFolderStatistics"].status = "Failed"
        } elseif ($Case -eq "folder details failed") {
            $script:CollectorStatuses["ReceiverLocalCalendarFolder"].status = "Failed"
        } elseif ($Case -eq "redacted") {
            Add-SharingFinding -RuleId "SHR213" -Status NotEvaluated -Evidence @{ reason = "Folder names are redacted." }
        } else {
            Add-SharingFinding -RuleId "SHR213" -Status Detected
        }
        Add-SharingFinding -RuleId "SHR240" -Status NotEvaluated
        Add-SharingFinding -RuleId "SHR322" -Status NotEvaluated
        Add-SharingFinding -RuleId "SHR323" -Status NotEvaluated
        Test-ReceiverDelegatePermissions

        Complete-SharingFindings

        foreach ($ruleId in @("SHR240", "SHR322", "SHR323", "SHR325")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be $Expected
        }
        if ($Case -eq "absent") {
            $script:CollectorStatuses["ReceiverLocalCalendarFolder"].status | Should -Be "NotApplicable"
            foreach ($ruleId in @("SHR404", "SHR405", "SHR406", "SHR407")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotApplicable"
            }
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR213").status | Should -Be "Detected"
        }
    }

    It "still validates explicit delegation when the receiver folder is absent" {
        $script:OwnerCalendarPerms = @([PSCustomObject]@{
                User = $Receiver; AccessRights = @("Reviewer"); SharingPermissionFlags = @("Delegate")
            })

        Test-ReceiverDelegatePermissions
        Complete-SharingFindings

        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status | Should -Be "Detected"
    }

    It "does not mistake collected logs for evaluated freshness when the model is unknown" {
        $script:CollectorStatuses["ReceiverFolderStatistics"].status = "Failed"
        foreach ($collector in @("ReceiverSharingSyncAssistantLog", "ReceiverSharingLog")) {
            $script:CollectorStatuses[$collector] = [PSCustomObject]@{ status = "Success"; error = $null }
        }

        Complete-SharingFindings

        foreach ($ruleId in @("SHR404", "SHR405", "SHR406", "SHR407")) {
            $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId
            $finding.status | Should -Be "NotEvaluated"
            $finding.evidence.reason | Should -Match "logs were collected.*freshness was not evaluated"
            $finding.recommendedNextStep | Should -Match "^Confirm the calendar-sharing relationship"
        }
    }

    It "writes the same assessment to JSON and console without adding findings or exposing unrelated identities" -TestCases @(
        @{ Sensitive = $true }
        @{ Sensitive = $false }
    ) {
        param($Sensitive)
        $IncludeSensitiveData = $Sensitive
        $script:OwnerInviteData += [PSCustomObject]@{ Recipient = "unrelated-secret@contoso.com"; Timestamp = "10/21/2026 12:00:00" }

        Write-SharingSummary -Owner $Owner -Receiver $Receiver | Out-Null
        $report = Get-SharingJsonReportObject
        $json = $report | ConvertTo-Json -Depth 10 | ConvertFrom-Json

        $json.summary.relationshipAssessment.status | Should -Be "NotConfirmed"
        $json.summary.relationshipAssessment.evidence.mailboxInviteCount | Should -Be 1
        $json.summary.relationshipAssessment.evidence.localFolderFound | Should -BeFalse
        $json.findings.Count | Should -Be $Script:expectedRuleIds.Count
        Should -Invoke -CommandName Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq $report.summary.relationshipAssessment.message
        }
        Should -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -eq "Selected-calendar sharing assessment: Owner [owner@contoso.com], receiver [receiver@contoso.com], calendar [\Calendar\Project Calendar]."
        }
        ($json.summary.relationshipAssessment | ConvertTo-Json -Depth 5) | Should -Not -Match "unrelated-secret"
    }

    It "does not add a sub-calendar assessment to default-calendar or fatal prerequisite runs" {
        $script:OwnerCalendarSubfolderSelected = $false
        Get-SharingRelationshipAssessment | Should -BeNullOrEmpty
        $script:OwnerCalendarSubfolderSelected = $true
        $script:FatalPrerequisiteFailure = [PSCustomObject]@{ ruleId = "SHR100" }
        Get-SharingRelationshipAssessment | Should -BeNullOrEmpty
    }
}

Describe "Check-SharingStatus receiver log freshness" {
    BeforeEach {
        Initialize-SharingTestState
        $script:ModernSharing = $true
        $script:SharingDiagnosticLogs = [ordered]@{}
        $script:ReceiverMB = [PSCustomObject]@{ DisplayName = "Receiver Display" }
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It "finds the latest timestamp in <Case> logs" -TestCases @(
        @{ Case = "month-first"; Lines = @("05/15/2026 23:30:05, Mailbox: x", "05/15/2026 19:55:28, Mailbox: x", "", "not a log line"); Expected = [DateTime]::new(2026, 5, 15, 23, 30, 5) }
        @{ Case = "day-first"; Lines = @("15/10/2026 13:44:31, Mailbox: x", "14/10/2026 07:28:54, Mailbox: x"); Expected = [DateTime]::new(2026, 10, 15, 13, 44, 31) }
        @{ Case = "12-hour month-first"; Lines = @("5/27/2025 8:14:06 PM, Mailbox: x", "4/27/2025 7:08:15 AM, Mailbox: x"); Expected = [DateTime]::new(2025, 5, 27, 20, 14, 6) }
        @{ Case = "ambiguous (month-first assumed)"; Lines = @("05/04/2026 01:45:18, Mailbox: x", "05/03/2026 14:57:30, Mailbox: x"); Expected = [DateTime]::new(2026, 5, 4, 1, 45, 18) }
        @{ Case = "unordered"; Lines = @("05/03/2026 14:57:30, x", "05/04/2026 01:45:18, x", "05/02/2026 01:45:18, x"); Expected = [DateTime]::new(2026, 5, 4, 1, 45, 18) }
    ) {
        param($Case, $Lines, $Expected)

        $latest = Get-CalendarDiagnosticLogLatestTimestamp -Line $Lines -ReferenceTimeUtc ([DateTime]::new(2026, 10, 20, 0, 0, 0, [DateTimeKind]::Utc))

        $latest | Should -Be $Expected
        $latest.Kind | Should -Be ([System.DateTimeKind]::Utc)
    }

    It "returns null when no timestamps exist or all are in the future" {
        $reference = [DateTime]::new(2026, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)

        Get-CalendarDiagnosticLogLatestTimestamp -Line @("no timestamp here", "") -ReferenceTimeUtc $reference | Should -BeNullOrEmpty
        Get-CalendarDiagnosticLogLatestTimestamp -Line @("12/12/2030 10:00:00, x") -ReferenceTimeUtc $reference | Should -BeNullOrEmpty
    }

    It "reports <ExpectedRule> for a latest <Component> entry that is <AgeDays> days old" -TestCases @(
        @{ Component = "SharingSyncAssistant"; AgeDays = 8; ExpectedRule = "SHR405"; SupersededRule = "SHR404"; OtherRule = "SHR407" }
        @{ Component = "SharingSyncAssistant"; AgeDays = 2; ExpectedRule = "SHR404"; SupersededRule = $null; OtherRule = "SHR406" }
        @{ Component = "Sharing"; AgeDays = 8; ExpectedRule = "SHR407"; SupersededRule = "SHR406"; OtherRule = "SHR405" }
        @{ Component = "Sharing"; AgeDays = 2; ExpectedRule = "SHR406"; SupersededRule = $null; OtherRule = "SHR404" }
    ) {
        param($Component, $AgeDays, $ExpectedRule, $SupersededRule, $OtherRule)

        $script:FreshnessTestComponent = $Component
        $script:FreshnessTestAgeDays = $AgeDays
        Mock Export-MailboxDiagnosticLogs {
            $timestamp = (Get-Date).ToUniversalTime().AddDays(-$script:FreshnessTestAgeDays)
            $logText = if ($ComponentName -eq $script:FreshnessTestComponent) {
                @(
                    "$($timestamp.ToString('MM/dd/yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)), Mailbox: 'Receiver', Entry latest",
                    "$($timestamp.AddDays(-1).ToString('MM/dd/yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)), Mailbox: 'Receiver', Entry older"
                ) -join "`r`n"
            } else {
                "$((Get-Date).ToUniversalTime().ToString('MM/dd/yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)), Mailbox: 'Receiver', Entry current"
            }
            [PSCustomObject]@{ MailboxLog = $logText }
        }

        Test-ReceiverSharingLogFreshness
        Complete-SharingFindings

        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ $ExpectedRule
        $finding.status | Should -Be "Detected"
        $finding.evidence.ageHours | Should -BeGreaterThan 23
        $finding.evidence.latestEntryUtc | Should -Not -BeNullOrEmpty
        if ($null -ne $SupersededRule) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $SupersededRule).status | Should -Be "NotApplicable"
        }
        ($script:SharingFindings | Where-Object -Property ruleId -EQ $OtherRule).status | Should -Be "NotDetected"
    }

    It "does not report stale logs that were written recently" {
        Mock Export-MailboxDiagnosticLogs {
            $stamp = (Get-Date).ToUniversalTime().AddHours(-2).ToString("MM/dd/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            [PSCustomObject]@{ MailboxLog = "$stamp, Mailbox: 'Receiver', Entry current" }
        }

        Test-ReceiverSharingLogFreshness
        Complete-SharingFindings

        foreach ($ruleId in @("SHR404", "SHR405", "SHR406", "SHR407")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotDetected"
        }
        $script:SharingDiagnosticLogs["receiver_SharingLog"].status | Should -Be "Collected"
    }

    It "marks the rules NotEvaluated when the log is empty, unparsable, or unavailable" {
        Mock Export-MailboxDiagnosticLogs {
            switch ($ComponentName) {
                "SharingSyncAssistant" { [PSCustomObject]@{ MailboxLog = $null } }
                default { throw "Access denied" }
            }
        }

        Test-ReceiverSharingLogFreshness
        Complete-SharingFindings

        $script:CollectorStatuses["ReceiverSharingSyncAssistantLog"].status | Should -Be "NoData"
        $script:CollectorStatuses["ReceiverSharingLog"].status | Should -Be "Failed"
        foreach ($ruleId in @("SHR404", "SHR405", "SHR406", "SHR407")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotEvaluated"
        }
        $script:SharingDiagnosticLogs["receiver_SharingLog"].status | Should -Be "Failed"
    }

    It "marks the rules NotEvaluated when the log has no parseable timestamps" {
        Mock Export-MailboxDiagnosticLogs { [PSCustomObject]@{ MailboxLog = "garbage without a timestamp" } }

        Test-ReceiverSharingLogFreshness
        Complete-SharingFindings

        foreach ($ruleId in @("SHR404", "SHR405", "SHR406", "SHR407")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotEvaluated"
        }
    }

    It "marks the rules NotApplicable when the relationship is not Modern Sharing" {
        $script:ModernSharing = $false
        $script:LegacyMapiSharing = $true
        Complete-SharingFindings

        foreach ($ruleId in @("SHR404", "SHR405", "SHR406", "SHR407")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotApplicable"
        }
        $script:LegacyMapiSharing = $false
    }

    It "reuses the freshness-check logs for the JSON report and removes blank separator lines" {
        $IncludeSensitiveData = $true
        $script:OwnerMB = [PSCustomObject]@{ DisplayName = "Owner Display" }
        Mock Export-MailboxDiagnosticLogs {
            $stamp = (Get-Date).ToUniversalTime().AddHours(-1).ToString("MM/dd/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            [PSCustomObject]@{ MailboxLog = @("$stamp, line one $ComponentName", "", "$stamp, line two", "") -join "`r`n" }
        }

        Test-ReceiverSharingLogFreshness
        Get-SharingDiagnosticLogs

        # The receiver logs were collected once by the freshness check and are not collected again.
        Should -Invoke Export-MailboxDiagnosticLogs -Times 2 -Exactly
        $script:SharingDiagnosticLogs.Keys | Should -Contain "receiver_SharingLog"
        $script:SharingDiagnosticLogs["receiver_SharingLog"].data.Count | Should -Be 2
        $script:SharingDiagnosticLogs["receiver_SharingLog"].data | Should -Not -Contain ""
        $script:SharingDiagnosticLogs.Keys | Should -Not -Contain "owner_SharingLog"
    }
}

Describe "Check-SharingStatus JSON report" {
    BeforeEach {
        Initialize-SharingTestState
        $script:OwnerCalendarFolderPathSpecified = $false
        $script:ModernSharing = $true
        $script:SharingType = "Modern Sharing"
        $script:FatalPrerequisiteFailure = $null
        $script:OwnerMB = $null
        $script:OwnerInviteData = @()
        $script:OwnerCalendarPerms = @()
        $script:OwnerActiveSharees = @()
        $script:ReceiverAcceptLogEntries = @()
        $script:ReceiverCalendarEntries = @()
        $script:OwnerInviteLogRaw = $null
        $script:ReceiverAcceptLogRaw = $null
        $script:SharingDiagnosticLogs = [ordered]@{}
    }

    It "collects the full SharingSyncAssistant and Sharing logs for the receiver only" {
        $script:OwnerMB = [PSCustomObject]@{ DisplayName = "Owner Display" }
        $script:ReceiverMB = [PSCustomObject]@{ DisplayName = "Receiver Display" }
        Mock Export-MailboxDiagnosticLogs {
            [PSCustomObject]@{ MailboxLog = @("line one for $Identity $ComponentName", "line two") -join "`r`n" }
        }
        Mock Write-Host {}

        Get-SharingDiagnosticLogs

        $script:SharingDiagnosticLogs.Keys | Should -Be @("receiver_SharingSyncAssistantLog", "receiver_SharingLog")
        $receiverSync = $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"]
        $receiverSync.status | Should -Be "Collected"
        $receiverSync.source | Should -Be "Export-MailboxDiagnosticLogs -Identity receiver@contoso.com -ComponentName SharingSyncAssistant"
        $receiverSync.data | Should -Be @("line one for receiver@contoso.com SharingSyncAssistant", "line two")
        $script:SharingDiagnosticLogs["receiver_SharingLog"].source |
            Should -Be "Export-MailboxDiagnosticLogs -Identity receiver@contoso.com -ComponentName Sharing"
        $script:CollectorStatuses["ReceiverSharingSyncAssistantLog"].status | Should -Be "Success"
        $script:CollectorStatuses["ReceiverSharingLog"].status | Should -Be "Success"
        Should -Invoke Export-MailboxDiagnosticLogs -Times 2 -Exactly
        Should -Not -Invoke Export-MailboxDiagnosticLogs -ParameterFilter { $Identity -eq "owner@contoso.com" }
    }

    It "records empty, failed, and uncollected diagnostic logs without stopping" {
        $script:ReceiverMB = [PSCustomObject]@{ DisplayName = "Receiver Display" }
        Mock Export-MailboxDiagnosticLogs {
            if ($ComponentName -eq "Sharing") { throw "Access denied" }
            [PSCustomObject]@{ MailboxLog = $null }
        }
        Mock Write-Host {}
        Mock Write-Warning {}

        Get-SharingDiagnosticLogs

        $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"].status | Should -Be "NoData"
        $script:SharingDiagnosticLogs["receiver_SharingLog"].status | Should -Be "Failed"
        $script:SharingDiagnosticLogs["receiver_SharingLog"].error | Should -Be "Access denied"
        $script:SharingDiagnosticLogs["receiver_SharingLog"].data | Should -BeNullOrEmpty
        $script:CollectorStatuses["ReceiverSharingSyncAssistantLog"].status | Should -Be "NoData"
        $script:CollectorStatuses["ReceiverSharingLog"].status | Should -Be "Failed"
        $script:CollectionErrors.Count | Should -Be 1
        $script:CollectionErrors[0].collector | Should -Be "ReceiverSharingLog"

        $script:SharingDiagnosticLogs = [ordered]@{}
        $script:ReceiverMB = $null
        Get-SharingDiagnosticLogs
        $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"].status | Should -Be "NotCollected"
    }

    It "includes the full invite, accept, sync assistant, and sharing logs in Full mode raw data" {
        $IncludeSensitiveData = $true
        $script:OwnerInviteLogRaw = @("invite line 1", "", "invite line 2", "") -join "`r`n"
        $script:ReceiverAcceptLogRaw = "accept line 1"
        $script:SharingDiagnosticLogs["receiver_SharingLog"] = [ordered]@{
            source = "Export-MailboxDiagnosticLogs -Identity receiver@contoso.com -ComponentName Sharing"
            status = "Collected"
            error  = $null
            data   = @("sharing line")
        }
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.rawData.owner_InviteLogFull.source | Should -BeLike "*-ComponentName CalendarSharingInvite (full log)"
        $report.rawData.owner_InviteLogFull.data | Should -Be @("invite line 1", "invite line 2")
        $report.rawData.receiver_AcceptLogFull.source | Should -BeLike "*-ComponentName AcceptCalendarSharingInvite (full log)"
        $report.rawData.receiver_AcceptLogFull.data | Should -Be @("accept line 1")
        $report.rawData.receiver_SharingLog.status | Should -Be "Collected"
        $report.rawData.receiver_SharingLog.data | Should -Be @("sharing line")
        $report.rawData.Contains("owner_SharingLog") | Should -BeFalse
        $report.rawData.Contains("owner_SharingSyncAssistantLog") | Should -BeFalse
    }

    It "includes invitation folder-scope notes with Subfolder=<Subfolder> and HasEntries=<HasEntries>" -TestCases @(
        @{ Subfolder = $false; HasEntries = $true }
        @{ Subfolder = $true; HasEntries = $true }
        @{ Subfolder = $false; HasEntries = $false }
        @{ Subfolder = $true; HasEntries = $false }
    ) {
        param($Subfolder, $HasEntries)
        $IncludeSensitiveData = $true
        $script:OwnerCalendarSubfolderSelected = $Subfolder
        $script:NormalizedOwnerCalendarFolderPath = "\Calendar\Project Calendar"
        $expectedNote = "CalendarSharingInvite invitation entries are mailbox-wide and do not identify the shared folder. These entries cannot distinguish sharing of the main Calendar from a sub-calendar."
        if ($Subfolder) {
            $expectedNote += " They cannot confirm that the selected calendar [\Calendar\Project Calendar] was shared."
        }
        if ($HasEntries) {
            $stamp = (Get-Date).ToUniversalTime().ToString("MM/dd/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            $script:OwnerInviteData = @([PSCustomObject]@{ Timestamp = $stamp; Recipient = "receiver@contoso.com" })
            $script:OwnerInviteLogRaw = "$stamp, invitation entry"
        }
        $jsonPath = Join-Path -Path $TestDrive -ChildPath "Invite-Scope.json"

        Write-SharingJsonReport -Path $jsonPath

        $written = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        foreach ($sectionName in @("owner_InviteLog", "owner_InviteLogFull")) {
            $section = $written.rawData.$sectionName
            $section.note | Should -Be $expectedNote
            $section.source | Should -Match "CalendarSharingInvite"
            @($section.data).Where({ $null -ne $_ }).Count | Should -Be ([int]$HasEntries)
            $section.omittedOlderThanOneYear | Should -Be 0
        }
        $written.rawData.owner_InviteLog.data.Count | Should -Be ([int]$HasEntries)
        $written.rawData.receiver_AcceptLog.PSObject.Properties.Name | Should -Not -Contain "note"
    }

    It -Name "preserves full-log JSON arrays for <Shape> log data" -TestCases @(
        @{ Shape = "single-line"; Count = 1; Omitted = 0 }
        @{ Shape = "multiple-line"; Count = 2; Omitted = 0 }
        @{ Shape = "age-filtered"; Count = 0; Omitted = 1 }
        @{ Shape = "unavailable"; Count = 0; Omitted = 0 }
    ) {
        param($Shape, $Count, $Omitted)
        $IncludeSensitiveData = $true
        $stamp = (Get-Date).ToUniversalTime().ToString("MM/dd/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        $logText = switch ($Shape) {
            "single-line" { "$stamp, current entry" }
            "multiple-line" { "$stamp, first entry`r`n$stamp, second entry" }
            "age-filtered" { "01/01/2020 12:00:00, old entry" }
            "unavailable" { $null }
        }
        $script:OwnerInviteLogRaw = $logText
        $script:ReceiverAcceptLogRaw = $logText
        Complete-SharingFindings
        $jsonPath = Join-Path -Path $TestDrive -ChildPath "Full-Logs.json"

        Write-SharingJsonReport -Path $jsonPath

        $written = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        foreach ($sectionName in @("owner_InviteLogFull", "receiver_AcceptLogFull")) {
            $section = $written.rawData.$sectionName
            if ($Shape -eq "unavailable") {
                $section.data | Should -BeNullOrEmpty
                ($null -eq $section.data) | Should -BeTrue
            } else {
                ($section.data -is [array]) | Should -BeTrue
                $section.data.Count | Should -Be $Count
            }
            $section.omittedOlderThanOneYear | Should -Be $Omitted
        }
    }

    It "builds the report with metadata, collectors, all rules, and error lists" {
        Add-SharingFinding -RuleId "SHR301" -Status Detected -Area "Invite" -Evidence @{
            owner    = "owner@contoso.com"
            receiver = "receiver@contoso.com"
        }
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.metadata.schemaVersion | Should -Be "1.0-preview"
        $report.metadata.owner | Should -Be "owner@contoso.com"
        $report.metadata.receiver | Should -Be "receiver@contoso.com"
        $report.metadata.privacyMode | Should -Be "Sanitized"
        $report.metadata.ownerCalendarFolderPath | Should -Be "(main) calendar"
        $report.sharing.modernSharing | Should -BeTrue
        $report.sharing.fatalPrerequisiteFailure | Should -BeNullOrEmpty
        @($report.findings).Count | Should -Be $Script:expectedRuleIds.Count
        $report.collectors.Keys | Should -Contain "OwnerMailbox"
        @($report.collectionErrors).Count | Should -Be 0
        @($report.evaluationErrors).Count | Should -Be 0
    }

    It "reports Full privacy mode and the selected folder path when requested" {
        $IncludeSensitiveData = $true
        $script:OwnerCalendarFolderPathSpecified = $true
        $script:NormalizedOwnerCalendarFolderPath = "Calendar\Project Calendar"
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.metadata.privacyMode | Should -Be "Full"
        $report.metadata.ownerCalendarFolderPath | Should -Be "Calendar\Project Calendar"
    }

    It "reports a fatal prerequisite failure without claiming completeness" {
        Register-SharingFatalPrerequisiteFailure -RuleId "SHR100" -Reason "Owner mailbox lookup failed."
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.metadata.collectionStatus | Should -Be "FatalPrerequisiteFailure"
        $report.sharing.fatalPrerequisiteFailure.ruleId | Should -Be "SHR100"
    }

    It "writes a parseable JSON file with sanitized evidence" {
        Add-SharingFinding -RuleId "SHR301" -Status Detected -Area "Invite" -Evidence @{
            owner    = "owner@contoso.com"
            receiver = "receiver@contoso.com"
        }
        Complete-SharingFindings
        $jsonPath = Join-Path -Path $TestDrive -ChildPath "Sharing-Report.json"

        Write-SharingJsonReport -Path $jsonPath

        $written = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        $written.metadata.schemaVersion | Should -Be "1.0-preview"
        @($written.findings).Count | Should -Be $Script:expectedRuleIds.Count
        $invite = $written.findings | Where-Object -Property ruleId -EQ "SHR301"
        $invite.status | Should -Be "Detected"
        $invite.result | Should -Be "Fail"
        $expectedResults = @{ Detected = "Fail"; NotDetected = "Pass"; NotEvaluated = "Inconclusive"; NotApplicable = "Skipped" }
        foreach ($finding in @($written.findings | Where-Object -Property ruleId -NE "SHR301")) {
            $finding.result | Should -Be $expectedResults[$finding.status]
        }
        $invite.evidence.owner | Should -Be "Owner"
    }

    It "reports raw evidence counts only in sanitized mode" {
        $script:OwnerInviteData = @([PSCustomObject]@{ Timestamp = "10/15/2026 1:00:00 PM"; Recipient = "receiver@contoso.com" })
        $script:OwnerCalendarPerms = @([PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("Reviewer"); SharingPermissionFlags = @("Delegate") })
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.rawData.included | Should -BeFalse
        $report.rawData.counts.owner_InviteLogEntries | Should -Be 1
        $report.rawData.counts.owner_CalendarPermissions | Should -Be 1
        $report.rawData.Contains("owner_InviteLog") | Should -BeFalse
        ($report | ConvertTo-Json -Depth 8) | Should -Not -Match "receiver@contoso.com\W+Reviewer"
    }

    It "includes raw evidence in Full mode" {
        $IncludeSensitiveData = $true
        $script:OwnerMB = [PSCustomObject]@{
            DisplayName          = "Owner Display"
            PrimarySmtpAddress   = "owner@contoso.com"
            RecipientTypeDetails = "UserMailbox"
            WhenCreatedUTC       = [DateTime]::new(2020, 1, 2, 3, 4, 5, [DateTimeKind]::Utc)
            ExtraProperty        = "not included"
        }
        $script:OwnerInviteData = @([PSCustomObject]@{ Timestamp = "15/10/2026 13:00:00"; Recipient = "receiver@contoso.com"; SharingType = "Calendar" })
        $script:OwnerCalendarPerms = @([PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("Reviewer"); SharingPermissionFlags = @("Delegate") })
        $script:OwnerActiveSharees = @([PSCustomObject]@{ EmailAddress = "receiver@contoso.com"; SharingPermissionFlags = "Editor, Delegate"; ActiveShareeFlags = @("None") })
        $script:ReceiverAcceptLogEntries = @([PSCustomObject]@{ Timestamp = "15/10/2026 13:44:31"; SharedCalendarOwner = "owner@contoso.com"; FolderName = "Owner Calendar" })
        $script:ReceiverCalendarEntries = @([PSCustomObject]@{ CalendarName = "Owner Calendar"; OwnerEmailAddress = "owner@contoso.com"; SharingModelType = "New"; IsOrphanedEntry = $false })
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject
        $json = $report | ConvertTo-Json -Depth 10 | ConvertFrom-Json

        $json.rawData.included | Should -BeTrue
        $json.rawData.owner_Mailbox.source | Should -Be "Get-Mailbox -Identity owner@contoso.com"
        $json.rawData.owner_Mailbox.data.PrimarySmtpAddress | Should -Be "owner@contoso.com"
        $report.rawData.owner_Mailbox.data.WhenCreatedUTC | Should -Match "^2020-01-02T03:04:05"
        $json.rawData.owner_Mailbox.data.PSObject.Properties.Name | Should -Not -Contain "ExtraProperty"
        $json.rawData.owner_InviteLog.source | Should -Be "Export-MailboxDiagnosticLogs -Identity owner@contoso.com -ComponentName CalendarSharingInvite (parsed entries)"
        $json.rawData.owner_InviteLog.data[0].Recipient | Should -Be "receiver@contoso.com"
        $json.rawData.owner_CalendarPermissions.source | Should -BeLike "Get-MailboxFolderPermission -Identity *"
        $json.rawData.owner_CalendarPermissions.data[0].userIdentity | Should -Be "receiver@contoso.com"
        $json.rawData.owner_CalendarPermissions.data[0].AccessRights | Should -Contain "Reviewer"
        $json.rawData.owner_ActiveSharees.source | Should -BeLike "Get-CalendarActiveSharingInformation -Identity *"
        $json.rawData.owner_ActiveSharees.data[0].SharingPermissionFlags | Should -Be @("Editor", "Delegate")
        $json.rawData.receiver_AcceptLog.source | Should -BeLike "Export-MailboxDiagnosticLogs -Identity receiver@contoso.com -ComponentName AcceptCalendarSharingInvite*"
        $json.rawData.receiver_AcceptLog.data[0].FolderName | Should -Be "Owner Calendar"
        $json.rawData.receiver_CalendarEntries.source | Should -Be "Get-CalendarEntries -Identity receiver@contoso.com"
        $json.rawData.receiver_CalendarEntries.data[0].SharingModelType | Should -Be "New"
        foreach ($sectionName in @($report.rawData.Keys | Where-Object { $_ -notin @("included", "counts") })) {
            $report.rawData[$sectionName].source | Should -Not -BeNullOrEmpty
        }
    }

    It "keeps raw data shapes stable and converts dates and flags" {
        $IncludeSensitiveData = $true
        $script:OwnerMB = [PSCustomObject]@{
            PrimarySmtpAddress  = "owner@contoso.com"
            GrantSendOnBehalfTo = @()
        }
        $script:ReceiverMB = [PSCustomObject]@{
            PrimarySmtpAddress  = "receiver@contoso.com"
            GrantSendOnBehalfTo = @("delegate-one")
        }
        $script:OwnerMailboxPerms = @([PSCustomObject]@{
                User         = "NT AUTHORITY\SELF"
                AccessRights = "FullAccess, ReadPermission"
                IsInherited  = $false
                Deny         = [switch]$false
            })
        $script:ReceiverLocalCalendarFolder = [PSCustomObject]@{
            CreationTime                = "10/15/2026 13:44:33"
            LastAttemptedSyncTime       = "10/20/2026 18:55:34"
            LastSuccessfulSyncTime      = "01/02/0001 00:00:00"
            SharedCalendarSyncStartDate = "not a date"
            ExtendedFolderFlags         = "ReadOnly, SharedIn"
            SharingPermissionFlags      = "None"
        }
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.rawData.owner_Mailbox.data.GrantSendOnBehalfTo.GetType().IsArray | Should -BeTrue
        @($report.rawData.owner_Mailbox.data.GrantSendOnBehalfTo).Count | Should -Be 0
        $report.rawData.receiver_Mailbox.data.GrantSendOnBehalfTo.GetType().IsArray | Should -BeTrue
        @($report.rawData.receiver_Mailbox.data.GrantSendOnBehalfTo).Count | Should -Be 1
        $report.rawData.owner_MailboxPermissions.data.GetType().IsArray | Should -BeTrue
        $report.rawData.owner_MailboxPermissions.data[0].Deny | Should -BeFalse
        $report.rawData.owner_MailboxPermissions.data[0].AccessRights | Should -Be @("FullAccess", "ReadPermission")
        $localFolder = $report.rawData.receiver_LocalCalendarFolder.data
        $localFolder.CreationTime | Should -Be "2026-10-15T13:44:33.0000000Z"
        $localFolder.LastAttemptedSyncTime | Should -Be "2026-10-20T18:55:34.0000000Z"
        $localFolder.LastSuccessfulSyncTime | Should -Be "Uninitialized"
        $localFolder.SharedCalendarSyncStartDate | Should -Be "not a date"
        $localFolder.ExtendedFolderFlags | Should -Be @("ReadOnly", "SharedIn")
        $localFolder.SharingPermissionFlags | Should -Be @("None")
        $report.rawData.receiver_SelectedAcceptLog.data | Should -BeNullOrEmpty
        $report.rawData.receiver_SelectedAcceptLog.source | Should -BeLike "Not filtered*"
    }

    It "explains why automatically completed findings were skipped" {
        $script:OwnerPublished = $false
        Complete-SharingFindings

        $skipped = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR420"
        $skipped.status | Should -Be "NotApplicable"
        $skipped.evidence.reason | Should -Be "The owner calendar is not published."
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR421").evidence.reason |
            Should -Be "The relationship is not a published calendar subscription."
    }

    It "writes readable apostrophes, ampersands, and angle brackets while keeping escaped backslashes intact" {
        $jsonPath = Join-Path -Path $TestDrive -ChildPath "Readable.json"
        $literalEscape = [string]::Concat("literal ", [char]92, "u0027 text")
        $data = [ordered]@{
            log     = "Mailbox: 'Julia Example', <tag> & more"
            literal = $literalEscape
        }

        Write-CalendarDiagnosticJsonFile -InputObject $data -Path $jsonPath -Depth 4

        $text = Get-Content -Path $jsonPath -Raw
        $text | Should -Match "Mailbox: 'Julia Example', <tag> & more"
        $text | Should -Not -Match "u0027.*u0027"
        $roundTrip = $text | ConvertFrom-Json
        $roundTrip.log | Should -Be $data.log
        $roundTrip.literal | Should -Be $literalEscape
    }

    It "adds a summary, categories, and plain-language finding text" {
        Add-SharingFinding -RuleId "SHR301" -Status Detected -Area "Invite" -Evidence @{
            owner    = "owner@contoso.com"
            receiver = "receiver@contoso.com"
        }
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.summary.overallResult | Should -Be "Fail"
        $report.summary.failedRules | Should -Contain "SHR301"
        $report.summary.failCount | Should -Be 1
        ($report.summary.failCount + $report.summary.infoCount + $report.summary.inconclusiveCount + $report.summary.passCount + $report.summary.skippedCount) |
            Should -Be $Script:expectedRuleIds.Count
        $report.sharing.sharingModel | Should -Be "Modern"
        $failed = $report.findings | Where-Object -Property ruleId -EQ "SHR301"
        $failed.category | Should -Be "Pair relationship"
        $failed.summary | Should -Be $failed.title
        $failed.recommendedNextStep | Should -Not -BeNullOrEmpty
        $passed = $report.findings | Where-Object -Property result -EQ "Pass" | Select-Object -First 1
        $passed.summary | Should -BeLike "Not detected: *"
        $passed.recommendedNextStep | Should -BeNullOrEmpty
        $passed.area | Should -BeNullOrEmpty
    }

    It "reports an Inconclusive overall result when only incomplete checks exist" {
        Add-SharingFinding -RuleId "SHR220" -Status NotEvaluated -Evidence @{ reason = "Test" }
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.summary.overallResult | Should -Be "Inconclusive"
        $report.summary.inconclusiveRules | Should -Contain "SHR220"
    }

    It -Name "reports <Result> with a retained <ErrorKind> error and rule status <FindingStatus>" -TestCases @(
        @{ ErrorKind = "evaluation"; FindingStatus = "NotDetected"; Result = "Inconclusive" }
        @{ ErrorKind = "collection"; FindingStatus = "NotDetected"; Result = "Inconclusive" }
        @{ ErrorKind = "evaluation"; FindingStatus = "Detected"; Result = "Fail" }
        @{ ErrorKind = "collection"; FindingStatus = "Detected"; Result = "Fail" }
    ) {
        param($ErrorKind, $FindingStatus, $Result)
        foreach ($rule in $script:SharingRuleCatalog) {
            $status = if ($rule.RuleId -eq "SHR301") { $FindingStatus } else { "NotDetected" }
            Add-SharingFinding -RuleId $rule.RuleId -Status $status
        }
        if ($ErrorKind -eq "evaluation") {
            Invoke-SharingEvaluation -Name "Unscoped diagnostics" -Action { throw "Evaluation failed" }
        } else {
            { Invoke-SharingCollector -Name "OwnerMailbox" -Action { throw "Collection failed" } } | Should -Throw
        }
        Complete-SharingFindings

        $report = Get-SharingJsonReportObject

        $report.metadata.collectionStatus | Should -Be "Partial"
        $report.summary.inconclusiveCount | Should -Be 0
        $report.summary.overallResult | Should -Be $Result
        (@($report.collectionErrors).Count + @($report.evaluationErrors).Count) | Should -Be 1
    }

    It "writes the report by default and only skips it with SkipJsonOutput" {
        $entryScript = Get-Content -Path "$Script:parentPath\Check-SharingStatus.ps1" -Raw
        $entryScript | Should -Match '(?m)^\s*\[switch\]\$SkipJsonOutput'
        $entryScript | Should -Match '(?m)^if \(-not \$SkipJsonOutput\) \{'
        $entryScript | Should -Match 'Write-SharingJsonReport -Path'
        $entryScript | Should -Match '(?s)Invoke-SharingEvaluation -Name "Sharing log collection" -Action \{\s*Get-SharingDiagnosticLogs'
    }
}

Describe "Check-SharingStatus structured diagnostics" {
    BeforeEach {
        Initialize-SharingTestState
    }

    Context "Structured finding contract and rule catalog" {
        It "uses the clarified receiver local-copy title for SHR213" {
            Add-SharingFinding -RuleId "SHR213" -Status Detected

            $script:SharingFindings[0].severity | Should -Be "Error"
            $script:SharingFindings[0].title | Should -Be "Receiver's local copy of owner calendar is missing"
        }

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
            $finding.title | Should -Be "Mailbox-level sharing invite to receiver is missing"
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

        It "retains healthy states and classifies non-published InternetCalendar rules as NotApplicable" {
            $script:ModernSharing = $true
            foreach ($collectorName in $Script:collectorNames) {
                $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "Success"; error = $null }
            }
            $script:ReceiverCalendarCandidates = @([PSCustomObject]@{ Name = "Owner Display" })
            $script:ReceiverMatchedCalendar = $script:ReceiverCalendarCandidates[0]
            $script:CalendarStatisticsComparisonPerformed = $true
            Complete-SharingFindings

            @($script:SharingFindings | Where-Object -Property status -EQ "NotDetected").Count |
                Should -Be ($Script:expectedRuleIds.Count - 6)
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status |
                Should -Be "NotEvaluated"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR233").status |
                Should -Be "NotDetected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR420").status |
                Should -Be "NotApplicable"
            foreach ($ruleId in @("SHR421", "SHR422", "SHR423", "SHR424")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status |
                    Should -Be "NotApplicable"
            }
            $script:CollectorStatuses["InternetCalendar"].status | Should -Be "Success"
        }

        It "does not evaluate InternetCalendar evidence when the owner calendar is not published" {
            $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "NoData"; error = $null }

            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR420").status |
                Should -Be "NotApplicable"
        }
    }

    Context "Collectors, failures, and bounded diagnostics" {
        It -Name "preserves the sharing error schema when using the shared normalizer" {
            $IncludeSensitiveData = $true
            $message = "first line" + [Environment]::NewLine + "second line"
            $exception = [System.InvalidOperationException]::new($message)

            $errorInfo = ConvertTo-SharingErrorInfo -ErrorRecord $exception

            $errorInfo.message | Should -Be "first line second line"
            $errorInfo.exceptionType | Should -Be "System.InvalidOperationException"
            @($errorInfo.PSObject.Properties.Name).Count | Should -Be 2
        }

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

        It "completes and writes a report after an unscoped evaluation failure" {
            Invoke-SharingEvaluation -Name "Owner diagnostics" -Action { throw "Malformed diagnostic evidence" }

            $script:EvaluationErrors.Count | Should -Be 1
            $script:EvaluationErrors[0].ruleIds.Count | Should -Be 0
            { Complete-SharingFindings } | Should -Not -Throw
            $jsonPath = Join-Path -Path $TestDrive -ChildPath "Evaluation-Failure.json"
            Write-SharingJsonReport -Path $jsonPath

            $written = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
            @($written.evaluationErrors).Count | Should -Be 1
            $written.evaluationErrors[0].evaluation | Should -Be "Owner diagnostics"
            $written.metadata.collectionStatus | Should -Be "Partial"
            $written.summary.overallResult | Should -Be "Inconclusive"
        }

        It -Name "ignores null rule IDs while retaining <Case> evaluation errors" -TestCases @(
            @{ Case = "unscoped"; RuleIds = @($null); RetainedCount = 1 }
            @{ Case = "applicable"; RuleIds = @($null, "SHR409"); RetainedCount = 1 }
            @{ Case = "inapplicable"; RuleIds = @($null, "SHR405"); RetainedCount = 0 }
        ) {
            param($RuleIds, $RetainedCount)
            $script:PublishedSharing = $true
            $script:EvaluationErrors.Add([PSCustomObject]@{
                    evaluation = "Diagnostics"
                    error      = "Evaluation failed"
                    ruleIds    = $RuleIds
                })

            { Complete-SharingFindings } | Should -Not -Throw

            $script:EvaluationErrors.Count | Should -Be $RetainedCount
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
                $command.Parameters.Keys | Should -Not -Contain "ModernSharingOnly"
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
        It "clarifies the invitation table scope with Subfolder=<Subfolder>" -TestCases @(
            @{ Subfolder = $false }
            @{ Subfolder = $true }
        ) {
            param($Subfolder)
            $script:OwnerCalendarSubfolderSelected = $Subfolder
            $script:NormalizedOwnerCalendarFolderPath = "\Calendar\Project Calendar"
            $expectedNote = "CalendarSharingInvite invitation entries are mailbox-wide and do not identify the shared folder. These entries cannot distinguish sharing of the main Calendar from a sub-calendar."
            if ($Subfolder) {
                $expectedNote += " They cannot confirm that the selected calendar [\Calendar\Project Calendar] was shared."
            }
            Mock -CommandName Export-MailboxDiagnosticLogs -MockWith {
                [PSCustomObject]@{
                    MailboxLog = "10/22/2026 12:00:00, Mailbox: owner, Entry MailboxOwner:owner@contoso.com,Recipient:receiver@contoso.com,RecipientType:UserMailbox,Handler=ms-exchange-internal,DetailLevel=Editor"
                }
            }
            Mock -CommandName Write-Host -MockWith {}

            $output = ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com" | Out-String -Width 200

            Should -Invoke -CommandName Write-Host -Times 1 -Exactly -ParameterFilter {
                ($ForegroundColor -eq "Yellow") -and ($Object -eq $expectedNote)
            }
            Should -Invoke -CommandName Write-Host -Times 1 -Exactly -ParameterFilter {
                $Object -eq "User [owner@contoso.com] has calendar-sharing invitation entries for the following recipients:"
            }
            $output | Should -Match "receiver@contoso.com.*internal.*Editor"
            $script:OwnerInviteData.Count | Should -Be 1
            $script:OwnerInviteCheckAvailable | Should -BeTrue
        }

        It "preserves mailbox punctuation and maps all invitation fields for <MailboxText>" -TestCases @(
            @{ MailboxText = "owner"; ExpectedMailbox = "owner" }
            @{ MailboxText = "'Owner Display'"; ExpectedMailbox = "Owner Display" }
            @{ MailboxText = "'Owner, Example A.'"; ExpectedMailbox = "Owner, Example A." }
            @{ MailboxText = "'O'Brien, Example, Team'"; ExpectedMailbox = "O'Brien, Example, Team" }
            @{ MailboxText = "'Owner, `"Example`"'"; ExpectedMailbox = 'Owner, "Example"' }
            @{ MailboxText = "'Recipient: Team, ms-exchange-Group'"; ExpectedMailbox = "Recipient: Team, ms-exchange-Group" }
        ) {
            param($MailboxText, $ExpectedMailbox)

            $logLine = "10/22/2026 12:00:00 PM, Mailbox: $MailboxText, Entry MailboxOwner:owner@contoso.com,Recipient:receiver@contoso.com,RecipientType:UserMailbox,Handler=ms-exchange-internal,DetailLevel=Editor"
            Mock -CommandName Export-MailboxDiagnosticLogs -MockWith {
                [PSCustomObject]@{ MailboxLog = $logLine }
            }

            $output = ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com" | Out-String -Width 200

            $script:OwnerInviteData.Count | Should -Be 1
            $entry = $script:OwnerInviteData[0]
            @($entry.PSObject.Properties.Name) | Should -Be @(
                "Timestamp", "Mailbox", "MailboxOwner", "Recipient", "RecipientType", "SharingType", "DetailLevel"
            )
            $entry.Timestamp | Should -Be "10/22/2026 12:00:00 PM"
            $entry.Mailbox | Should -Be $ExpectedMailbox
            $entry.MailboxOwner | Should -Be "owner@contoso.com"
            $entry.Recipient | Should -Be "receiver@contoso.com"
            $entry.RecipientType | Should -Be "UserMailbox"
            $entry.SharingType | Should -Be "internal"
            $entry.DetailLevel | Should -Be "Editor"
            $script:OwnerInviteLogRaw | Should -Be $logLine
            $script:OwnerInviteCheckAvailable | Should -BeTrue
            $output | Should -Match "receiver@contoso.com.*internal.*Editor"
            (Get-PairSharingInvite).Recipient | Should -Be "receiver@contoso.com"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR301").status | Should -Be "NotDetected"
        }

        It "parses every invitation with <LineEndingName> line endings and ignores unrelated lines" -TestCases @(
            @{ LineEndingName = "CRLF"; LineEnding = "`r`n" }
            @{ LineEndingName = "LF"; LineEnding = "`n" }
        ) {
            param($LineEndingName, $LineEnding)

            $logText = @(
                "10/22/2026 12:00:00, Mailbox: 'Owner, Example', Entry MailboxOwner:owner@contoso.com,Recipient:receiver@contoso.com,RecipientType:UserMailbox,Handler=ms-exchange-internal,DetailLevel=Editor"
                "10/22/2026 11:00:00, Mailbox: 'Owner, Example', Entry unrelated diagnostic message"
                ""
                "10/21/2026 12:00:00, Mailbox: 'Owner, Example', Entry MailboxOwner:owner@contoso.com,Recipient:other@contoso.com,RecipientType:UserMailbox,Handler=ms-exchange-internal,DetailLevel=Reviewer"
                ""
            ) -join $LineEnding
            Mock -CommandName Export-MailboxDiagnosticLogs -MockWith {
                [PSCustomObject]@{ MailboxLog = $logText }
            }

            ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com" | Out-Null

            $script:OwnerInviteData.Count | Should -Be 2
            $script:OwnerInviteData[0].Recipient | Should -Be "receiver@contoso.com"
            $script:OwnerInviteData[1].Recipient | Should -Be "other@contoso.com"
            $script:OwnerInviteData[1].DetailLevel | Should -Be "Reviewer"
            $script:OwnerInviteLogRaw | Should -Be $logText
        }

        It "reports malformed invitations without retaining partial or stale parsed data" {
            $script:OwnerInviteCheckAvailable = $true
            $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = "stale@contoso.com" })
            $logText = @(
                "10/22/2026 12:00:00, Mailbox: 'Owner, Example', Entry MailboxOwner:owner@contoso.com,Recipient:other@contoso.com,RecipientType:UserMailbox,Handler=ms-exchange-internal,DetailLevel=Editor"
                "10/21/2026 12:00:00, Mailbox: 'Owner, Example', Entry MailboxOwner:owner@contoso.com,Recipient:receiver@contoso.com,RecipientType:UserMailbox,Handler=ms-exchange-internal"
            ) -join "`r`n"
            Mock -CommandName Export-MailboxDiagnosticLogs -MockWith {
                [PSCustomObject]@{ MailboxLog = $logText }
            }
            Mock -CommandName Write-Warning -MockWith {}

            ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com" | Out-Null

            $script:OwnerInviteCheckAvailable | Should -BeFalse
            $script:OwnerInviteData | Should -BeNullOrEmpty
            $script:OwnerInviteLogRaw | Should -Be $logText
            $script:EvaluationErrors.Count | Should -Be 1
            $script:EvaluationErrors[0].evaluation | Should -Be "Owner invite-log parsing"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR300").status |
                Should -Be "NotEvaluated"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR301").status |
                Should -Be "NotEvaluated"
            Should -Invoke -CommandName Write-Warning -Times 1 -Exactly -ParameterFilter {
                $Message -match "Owner invite-log parsing evaluation failed.*line \[2\]"
            }
        }

        It -Name "displays the newest invitation per recipient with Reverse=<Reverse> and IncludeOther=<IncludeOther>" -TestCases @(
            @{ Reverse = $false; IncludeOther = $false }
            @{ Reverse = $true; IncludeOther = $false }
            @{ Reverse = $false; IncludeOther = $true }
            @{ Reverse = $true; IncludeOther = $true }
        ) {
            param($Reverse, $IncludeOther)

            $logLines = @(
                "9/1/2026 12:00:00,Mailbox: owner,Entry MailboxOwner: owner,Recipient: receiver@contoso.com,RecipientType: External,Handler=ms-exchange-publish,DetailLevel=Full"
                "10/22/2026 12:00:00,Mailbox: owner,Entry MailboxOwner: owner,Recipient: receiver@contoso.com,RecipientType: External,Handler=ms-exchange-external,DetailLevel=Full"
                if ($IncludeOther) {
                    "9/15/2026 12:00:00,Mailbox: owner,Entry MailboxOwner: owner,Recipient: other@contoso.com,RecipientType: Internal,Handler=ms-exchange-Modern,DetailLevel=Full"
                }
            )
            if ($Reverse) { [array]::Reverse($logLines) }
            Mock -CommandName Export-MailboxDiagnosticLogs -MockWith {
                [PSCustomObject]@{ MailboxLog = $logLines -join "`r`n" }
            }

            $output = ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com" | Out-String -Width 200

            $output | Should -Match "10/22/2026.*receiver@contoso.com.*external"
            if ($IncludeOther) {
                $output | Should -Match "9/15/2026.*other@contoso.com.*Modern"
            }
            $output | Should -Not -Match "9/1/2026"
            $script:OwnerInviteData.Count | Should -Be (2 + [int]$IncludeOther)
            (Get-PairSharingInvite).SharingType | Should -Be "external"
        }

        It "retains undated and tied latest invitations instead of hiding ambiguous history" {
            Mock -CommandName Write-Warning -MockWith {}
            Mock -CommandName Export-MailboxDiagnosticLogs -MockWith {
                [PSCustomObject]@{
                    MailboxLog = @(
                        "not-a-date,Mailbox: owner,Entry MailboxOwner: owner,Recipient: receiver@contoso.com,RecipientType: External,Handler=ms-exchange-publish,DetailLevel=Full"
                        "10/22/2026 12:00:00,Mailbox: owner,Entry MailboxOwner: owner,Recipient: receiver@contoso.com,RecipientType: External,Handler=ms-exchange-external,DetailLevel=Full"
                        "10/22/2026 12:00:00,Mailbox: owner,Entry MailboxOwner: owner,Recipient: receiver@contoso.com,RecipientType: Internal,Handler=ms-exchange-Modern,DetailLevel=Full"
                    ) -join "`r`n"
                }
            }

            $output = ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com" | Out-String -Width 200

            $output | Should -Match "not-a-date.*publish"
            $output | Should -Match "10/22/2026.*external"
            $output | Should -Match "10/22/2026.*Modern"
            (Get-PairSharingInvite) | Should -BeNullOrEmpty
            Should -Invoke -CommandName Write-Warning -Times 1 -Exactly -ParameterFilter {
                $Message -like "*invitation timestamps could not be parsed*"
            }
        }

        It "records mailbox-scoped passing evidence when the expected receiver is present" {
            Mock Export-MailboxDiagnosticLogs {
                [PSCustomObject]@{
                    MailboxLog = "9/17/2026,Mailbox: owner,Entry MailboxOwner: owner,Recipient: receiver@contoso.com,RecipientType: Internal,Handler=ms-exchange-Modern,DetailLevel=Full"
                }
            }

            ProcessCalendarSharingInviteLogs -Identity "owner@contoso.com"

            $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR301"
            $finding.status | Should -Be "NotDetected"
            $finding.evidence.matchedInviteCount | Should -Be 1
            $finding.evidence.latestEntryUtc | Should -Be "2026-09-17T00:00:00.0000000Z"
            $finding.evidence.mailboxScoped | Should -BeTrue
            $finding.evidence.calendarFolderIdentified | Should -BeFalse
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
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status |
                Should -Be "Detected"
        }

        It -Name "accepts receiver delegate permissions through <PermissionUser> in the full diagnostic path" -TestCases @(
            @{ PermissionUser = "receiver@contoso.com" }
            @{ PermissionUser = "Receiver Display" }
            @{ PermissionUser = "old.receiver@contoso.com" }
        ) {
            param($PermissionUser)
            $Script:prerequisiteReceiverMailbox | Add-Member -NotePropertyMembers @{
                PrimarySmtpAddress = "receiver@contoso.com"
                EmailAddresses     = @("SMTP:receiver@contoso.com", "smtp:old.receiver@contoso.com")
            }
            $Script:activeSharees[0].EmailAddress = "old.receiver@contoso.com"
            Mock -CommandName Get-MailboxFolderPermission -MockWith {
                [PSCustomObject]@{
                    User                   = $PermissionUser
                    AccessRights           = @("Editor")
                    SharingPermissionFlags = @("Delegate")
                }
            }

            Invoke-SharingDiagnostics

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR325").status |
                Should -Be "NotDetected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR320").status |
                Should -Be "NotDetected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR311").status |
                Should -Be "NotDetected"
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] is using [Editor; SharingPermissionFlags: Delegate] on the owner Calendar folder."
            }
        }

        It "writes the permission summary only after receiver diagnostics have collected receiver information" {
            $script:permissionSummaryAfterReceiver = $false
            Mock -CommandName Write-OwnerReceiverPermissionSummary -MockWith {
                $script:permissionSummaryAfterReceiver = ($null -ne $script:ReceiverMB) -and
                ($script:CollectorStatuses["ReceiverFolderStatistics"].status -eq "Success")
            }

            Invoke-SharingDiagnostics

            $script:permissionSummaryAfterReceiver | Should -BeTrue
            Should -Invoke -CommandName Write-OwnerReceiverPermissionSummary -Times 1 -Exactly
        }

        It "correlates an explicitly selected default calendar with the shared receiver copy" -TestCases @(
            @{ CalendarRoot = "Calendar" }
            @{ CalendarRoot = "Kalender" }
        ) {
            param($CalendarRoot)
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:NormalizedOwnerCalendarFolderPath = "\$CalendarRoot"
            $script:RequestedOwnerCalendarLeafName = $CalendarRoot
            $Script:prerequisiteOwnerStats[0].Name = $CalendarRoot
            $Script:prerequisiteOwnerStats[0].FolderPath = "/$CalendarRoot"

            Invoke-SharingDiagnostics

            $script:OwnerCalendarSubfolderSelected | Should -BeFalse
            $script:ReceiverMatchedCalendar.Name | Should -Be "Owner Display"
            $script:LegacyMapiSharing | Should -BeFalse
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR231").status |
                Should -Be "NotDetected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR243").status |
                Should -Be "NotDetected"
            $script:CalendarStatisticsComparison.receiverCount | Should -Be 10
            (Get-SharingJsonReportObject).metadata.ownerCalendarFolderPath | Should -Be "\$CalendarRoot"
            Should -Invoke -CommandName Get-MailboxCalendarFolder -Times 1 -Exactly -ParameterFilter {
                $Identity -eq "receiver@contoso.com:\Calendar\Owner Display"
            }
            Should -Not -Invoke -CommandName Get-MailboxCalendarFolder -ParameterFilter {
                $Identity -eq "receiver@contoso.com:\Calendar"
            }
        }
    }

    Context "Duplicate-style calendar folder names" {
        It -Name "preserves a duplicate-style folder array with <Count> matches" -TestCases @(
            @{ Count = 0 }
            @{ Count = 1 }
            @{ Count = 2 }
        ) {
            param($Count)
            $folderStatistics = @(
                for ($index = 1; $index -le $Count; $index++) {
                    [PSCustomObject]@{ Name = "Calendar ($index)"; FolderPath = "/Calendar ($index)" }
                }
            )

            $matchingFolders = Get-DuplicateStyleCalendarFolders -FolderStatistics $folderStatistics

            ($matchingFolders -is [array]) | Should -BeTrue
            $matchingFolders.Count | Should -Be $Count
            if ($Count -gt 0) {
                $matchingFolders[0].Name | Should -Be "Calendar (1)"
            }
        }

        It "matches only terminal one- or two-digit numeric suffixes" {
            $folderStatistics = @(
                [PSCustomObject]@{ Name = "Calendar (1)"; FolderPath = "/Calendar (1)" },
                [PSCustomObject]@{ Name = "Calendar (12)"; FolderPath = "/Calendar (12)" },
                [PSCustomObject]@{ Name = "Calendar (123)"; FolderPath = "/Calendar (123)" },
                [PSCustomObject]@{ Name = "CUB01-3 McKinley (16-32) Public"; FolderPath = "/CUB01-3 McKinley (16-32) Public" },
                [PSCustomObject]@{ Name = "Calendar (1) Public"; FolderPath = "/Calendar (1) Public" }
            )

            $matchingFolders = Get-DuplicateStyleCalendarFolders -FolderStatistics $folderStatistics

            $matchingFolders.Name | Should -Be @("Calendar (1)", "Calendar (12)")
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

        It "reports that receiver access may use Default or a group when no individual entry exists" {
            Mock Get-MailboxFolderPermission {
                @(
                    [PSCustomObject]@{ User = "Default"; AccessRights = @("Reviewer"); SharingPermissionFlags = @() },
                    [PSCustomObject]@{ User = "Anonymous"; AccessRights = @("None"); SharingPermissionFlags = @() }
                )
            }
            Mock Get-MailboxPermission {
                @(
                    [PSCustomObject]@{ User = "NT AUTHORITY\SELF"; AccessRights = @("FullAccess"); SharingPermissionFlags = @() }
                )
            }
            Mock Write-Host {}

            GetOwnerInformation -Owner "owner@contoso.com"
            Write-OwnerReceiverPermissionSummary -Receiver "receiver@contoso.com"

            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] does not have an individual permission entry on the owner Calendar folder or Mailbox; access may come from Default or a group permission."
            }
        }

        It -Name "matches receiver permissions through the shared AD recipient identity" {
            Mock -CommandName Get-MailboxFolderPermission -MockWith {
                [PSCustomObject]@{
                    User                   = [PSCustomObject]@{
                        ADRecipient = [PSCustomObject]@{ PrimarySmtpAddress = " RECEIVER@Contoso.com " }
                    }
                    AccessRights           = @("Editor")
                    SharingPermissionFlags = @("Delegate")
                }
            }
            Mock -CommandName Get-MailboxPermission -MockWith { @() }
            Mock -CommandName Write-Host -MockWith {}

            GetOwnerInformation -Owner "owner@contoso.com"
            Write-OwnerReceiverPermissionSummary -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] is using [Editor; SharingPermissionFlags: Delegate] on the owner Calendar folder."
            }
        }

        It "summarizes receiver permissions found on both the calendar and mailbox" {
            Mock Get-MailboxFolderPermission {
                @(
                    [PSCustomObject]@{
                        User                   = "receiver@contoso.com"
                        AccessRights           = @("Editor")
                        SharingPermissionFlags = @("Delegate")
                    }
                )
            }
            Mock Get-MailboxPermission {
                @(
                    [PSCustomObject]@{
                        User                   = "receiver@contoso.com"
                        AccessRights           = @("FullAccess", "ReadPermission")
                        SharingPermissionFlags = @()
                    }
                )
            }
            Mock Write-Host {}

            GetOwnerInformation -Owner "owner@contoso.com"
            Write-OwnerReceiverPermissionSummary -Receiver "receiver@contoso.com"

            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] has [Editor; SharingPermissionFlags: Delegate] on the owner Calendar folder and [FullAccess, ReadPermission] on the owner Mailbox."
            }
        }

        It "summarizes a receiver permission found only on the calendar" {
            Mock Get-MailboxFolderPermission {
                @(
                    [PSCustomObject]@{
                        User                   = "receiver@contoso.com"
                        AccessRights           = @("Reviewer")
                        SharingPermissionFlags = @()
                    }
                )
            }
            Mock Get-MailboxPermission { @() }
            Mock Write-Host {}

            GetOwnerInformation -Owner "owner@contoso.com"
            Write-OwnerReceiverPermissionSummary -Receiver "receiver@contoso.com"

            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] is using [Reviewer] on the owner Calendar folder."
            }
        }

        It "summarizes a receiver permission found only on the mailbox" {
            Mock Get-MailboxFolderPermission { @() }
            Mock Get-MailboxPermission {
                @(
                    [PSCustomObject]@{
                        User                   = "receiver@contoso.com"
                        AccessRights           = @("FullAccess")
                        SharingPermissionFlags = @()
                    }
                )
            }
            Mock Write-Host {}

            GetOwnerInformation -Owner "owner@contoso.com"
            Write-OwnerReceiverPermissionSummary -Receiver "receiver@contoso.com"

            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "Receiver [receiver@contoso.com] has [FullAccess] on the owner Mailbox."
            }
        }

        It -Name "separates mailbox Deny entries from Allow entries (mixed=<Mixed>)" -TestCases @(
            @{ Mixed = $false }
            @{ Mixed = $true }
        ) {
            param($Mixed)
            Mock -CommandName Get-MailboxPermission -MockWith {
                $permissions = @(
                    [PSCustomObject]@{ User = "receiver@contoso.com"; AccessRights = @("FullAccess"); Deny = [switch]$true }
                )
                if ($Mixed) {
                    $permissions += [PSCustomObject]@{
                        User = "receiver@contoso.com"; AccessRights = @("FullAccess", "ReadPermission"); Deny = [switch]$false
                    }
                }
                return $permissions
            }
            Mock -CommandName Write-Host -MockWith {}

            GetOwnerInformation -Owner "owner@contoso.com"
            Write-OwnerReceiverPermissionSummary -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Yellow") -and
                ($Object -eq "Receiver [receiver@contoso.com] has Deny entries for [FullAccess] on the owner Mailbox.")
            }
            Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Green") -and ($Object -like "*FullAccess*")
            }
            if ($Mixed) {
                Should -Invoke -CommandName Write-Host -ParameterFilter {
                    ($ForegroundColor -eq "Yellow") -and
                    ($Object -eq "Receiver [receiver@contoso.com] has Allow entries for [FullAccess, ReadPermission] on the owner Mailbox; Deny entries are also present, so these are not effective-access results.")
                }
            } else {
                Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
                    $Object -like "*Allow entries*"
                }
            }
        }

        It "detects an owner calendar renamed Outbox" {
            Mock Get-MailboxFolderStatistics {
                @(
                    [PSCustomObject]@{
                        FolderType             = "Calendar"
                        Name                   = "Outbox"
                        FolderPath             = "/Outbox"
                        FolderSize             = "1 KB (1,024 bytes)"
                        FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                        VisibleItemsInFolder   = 10
                    }
                )
            }
            Mock Write-Host {}

            GetOwnerInformation -Owner "owner@contoso.com"
            Complete-SharingFindings

            $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR113"
            $finding.status | Should -Be "Detected"
            $finding.severity | Should -Be "Error"
            $finding.recommendedNextStep | Should -BeLike "*Escalate to Microsoft Support*"
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and ($Object -like "*renamed Outbox*escalate to Microsoft Support*")
            }
        }

        It "does not report an Outbox calendar for normally named owner calendars" {
            GetOwnerInformation -Owner "owner@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR113").status |
                Should -Be "NotDetected"
        }

        It "warns for duplicate-style owner calendar folder names" {
            Mock Get-MailboxFolderStatistics {
                @(
                    [PSCustomObject]@{
                        FolderType             = "Calendar"
                        Name                   = "Calendar"
                        FolderPath             = "/Calendar"
                        FolderSize             = "1 KB (1,024 bytes)"
                        FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                        VisibleItemsInFolder   = 10
                    },
                    [PSCustomObject]@{
                        FolderType             = "User Created"
                        Name                   = "Project (12)"
                        FolderPath             = "/Project (12)"
                        FolderSize             = "1 KB (1,024 bytes)"
                        FolderAndSubfolderSize = "1 KB (1,024 bytes)"
                        VisibleItemsInFolder   = 1
                    }
                )
            }

            GetOwnerInformation -Owner "owner@contoso.com"

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR112").status |
                Should -Be "Detected"
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
                    "Identity", "CreationTime", "PublishEnabled",
                    "PublishedCalendarUrl", "PublishedICalUrl", "ExtendedFolderFlags")) {
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

        It -Name "only classifies a correlated New entry as Modern with confirmed internal organizations (<Case>)" -TestCases @(
            @{ Case = "owner missing"; OwnerOrganization = $null; ReceiverOrganization = "OU1"; Modern = $false }
            @{ Case = "receiver missing"; OwnerOrganization = "OU1"; ReceiverOrganization = $null; Modern = $false }
            @{ Case = "both missing"; OwnerOrganization = $null; ReceiverOrganization = $null; Modern = $false }
            @{ Case = "internal confirmed"; OwnerOrganization = "OU1"; ReceiverOrganization = "OU1"; Modern = $true }
        ) {
            param($OwnerOrganization, $ReceiverOrganization, $Modern)
            $script:OwnerMB.OrganizationalUnitRoot = $OwnerOrganization
            $Script:receiverMailbox.OrganizationalUnitRoot = $ReceiverOrganization
            $Script:receiverStats[1].Name = "Renamed local calendar"
            $Script:receiverStats[1].FolderPath = "/Renamed local calendar"
            $Script:calendarEntries[0].CalendarName = "Renamed local calendar"
            Mock Write-Host {}

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $script:ReceiverMatchedCalendar.Name | Should -Be "Renamed local calendar"
            $script:ReceiverCalendarCandidates.Count | Should -Be 1
            $script:ModernSharing | Should -Be $Modern
            $report = Get-SharingJsonReportObject
            if ($Modern) {
                $report.sharing.sharingType | Should -Be "InternalSharing"
                $report.sharing.sharingModel | Should -Be "Modern"
                $report.sharing.relationshipKind | Should -Be "Internal: REST (New Model)"
            } else {
                $report.sharing.sharingType | Should -Be "Undetermined"
                $report.sharing.sharingModel | Should -Be "Undetermined"
                $report.sharing.relationshipKind | Should -Be "Undetermined"
            }
        }

        It "reports a missing external local folder without requiring an internal New entry" {
            $Script:receiverStats = @($Script:receiverStats[0])
            $Script:calendarEntries = @()
            $Script:receiverMailbox.OrganizationalUnitRoot = "OU2"

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $script:SharingFindings.ruleId | Should -Contain "SHR213"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR231").status |
                Should -Be "NotApplicable"
        }

        It "classifies internal sharing without a Modern copy as legacy MAPI" {
            $Script:receiverStats = @($Script:receiverStats[0])
            $Script:calendarEntries = @(
                [PSCustomObject]@{
                    CalendarGroupName = "People's calendars"
                    CalendarName      = "Owner Display"
                    OwnerEmailAddress = "owner@contoso.com"
                    SharingModelType  = "Old"
                    IsOrphanedEntry   = $false
                }
            )
            Add-SharingFinding -RuleId "SHR301" -Status Detected -Evidence @{
                matchingInviteFound = $false
            }
            Add-SharingFinding -RuleId "SHR311" -Status Detected -Evidence @{
                activeRelationshipFound = $false
            }
            Mock Write-Host {}
            Mock Compare-CalendarFolderStatistics {}

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $script:LegacyMapiSharing | Should -BeTrue
            $script:PIIAccess | Should -BeTrue
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR324").status |
                Should -Be "Detected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR324").recommendedNextStep |
                Should -Match "support\.microsoft\.com/en-us/outlook/calendar-sharing-in-microsoft-365"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR233").status |
                Should -Be "Detected"
            @($script:SharingFindings | Where-Object {
                    ($_.ruleId -in $script:ModernSharingRuleIds) -and
                    ($_.status -ne "NotApplicable")
                }).Count | Should -Be 0
            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "Warning: This internal relationship is using legacy MAPI calendar sharing."
            }
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -like "Do Not have PII information*"
            }
            Should -Not -Invoke Compare-CalendarFolderStatistics
        }

        It -Name "does not infer legacy sharing from missing Modern evidence (<Case>)" -TestCases @(
            @{ Case = "no sharing entries"; OtherOwner = $null }
            @{ Case = "unrelated Old entry"; OtherOwner = "other@contoso.com" }
        ) {
            param($Case, $OtherOwner)
            $Script:receiverStats = @($Script:receiverStats[0])
            $Script:calendarEntries = @()
            if ($OtherOwner) {
                $Script:calendarEntries = @(
                    [PSCustomObject]@{ OwnerEmailAddress = $OtherOwner; SharingModelType = "Old"; CalendarName = "Other Calendar" }
                )
            }
            Add-SharingFinding -RuleId "SHR301" -Status Detected -Evidence @{ matchingInviteFound = $false }

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $script:LegacyMapiSharing | Should -BeFalse
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR324").status | Should -Be "NotDetected"
            foreach ($ruleId in @("SHR301", "SHR231", "SHR213")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "Detected"
            }
        }

        It "validates a published subscription and its receiver local folder" {
            $script:OwnerPublished = $true
            $script:OwnerPublishedICalUrl = "https://outlook.office365.com/owa/calendar/owner/calendar.ics"
            $script:CollectorStatuses["OwnerCalendarFolder"] =
            [PSCustomObject]@{ status = "Success"; error = $null }
            $Script:receiverStats = @(
                $Script:receiverStats[0],
                [PSCustomObject]@{
                    FolderType           = "User Created"
                    Name                 = "Published Owner"
                    FolderPath           = "/Published Owner"
                    FolderId             = "published-folder-id"
                    FolderSize           = "1 KB"
                    VisibleItemsInFolder = 5
                }
            )
            $Script:calendarEntries = @()
            Mock ProcessInternetCalendarLogs {
                $script:CollectorStatuses["InternetCalendar"] =
                [PSCustomObject]@{ status = "Success"; error = $null }
                $script:ReceiverInternetCalendarEntries = @(
                    [PSCustomObject]@{
                        PublishingUrl    = $script:OwnerPublishedICalUrl
                        RemoteFolderName = "Calendar"
                        LocalFolderId    = "published-folder-id"
                        Folder           = "Published Owner"
                    }
                )
            }

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $script:PublishedSharing | Should -BeTrue
            $script:LegacyMapiSharing | Should -BeFalse
            $script:ModernSharing | Should -BeFalse
            $script:ReceiverPublishedCalendarFolder.Name | Should -Be "Published Owner"
            Should -Invoke ProcessInternetCalendarLogs -Times 1 -Exactly
            foreach ($ruleId in @("SHR421", "SHR422", "SHR423")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status |
                    Should -Be "NotDetected"
            }
            @($script:SharingFindings | Where-Object {
                    ($_.ruleId -in $script:ModernSharingRuleIds) -and
                    ($_.status -ne "NotApplicable")
                }).Count | Should -Be 0
        }

        It "warns when the receiver has no subscription to the published owner calendar" {
            $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = "receiver@contoso.com"; SharingType = "publish" })
            $script:OwnerPublished = $true
            $script:OwnerPublishedICalUrl = "https://outlook.office365.com/owa/calendar/owner/calendar.ics"
            $script:CollectorStatuses["OwnerCalendarFolder"] =
            [PSCustomObject]@{ status = "Success"; error = $null }
            $Script:receiverStats = @($Script:receiverStats[0])
            $Script:calendarEntries = @()
            Mock ProcessInternetCalendarLogs {
                $script:CollectorStatuses["InternetCalendar"] =
                [PSCustomObject]@{ status = "NoData"; error = $null }
                $script:ReceiverInternetCalendarEntries = @()
            }

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $script:PublishedSharing | Should -BeTrue
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR421").status |
                Should -Be "Detected"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR213").status |
                Should -Be "NotApplicable"
        }

        It -Name "keeps a missing published folder inconclusive when <Unavailable> evidence is unavailable" -TestCases @(
            @{ Unavailable = "subscription" }
            @{ Unavailable = "folder statistics" }
        ) {
            param($Unavailable)
            $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = "receiver@contoso.com"; SharingType = "publish" })
            $script:OwnerPublished = $true
            $script:OwnerPublishedICalUrl = "https://outlook.office365.com/owa/calendar/owner/calendar.ics"
            $Script:calendarEntries = @()
            $Script:receiverStats = @($Script:receiverStats[0])
            Mock -CommandName ProcessInternetCalendarLogs -MockWith {
                if ($Unavailable -eq "subscription") {
                    $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "Failed"; error = "Access denied" }
                    $script:ReceiverInternetCalendarEntries = @()
                } else {
                    $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "Success"; error = $null }
                    $script:ReceiverInternetCalendarEntries = @(
                        [PSCustomObject]@{ PublishingUrl = $script:OwnerPublishedICalUrl; Folder = "Published Owner" }
                    )
                }
            }
            if ($Unavailable -eq "folder statistics") {
                Mock -CommandName Get-MailboxFolderStatistics -MockWith { throw "Access denied" }
            }

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $script:PublishedSharing | Should -BeTrue
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR422").status | Should -Be "NotEvaluated"
            if ($Unavailable -eq "subscription") {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR421").status | Should -Be "NotEvaluated"
            }
        }

        It "detects a missing published folder only with a matching subscription and available statistics" {
            $script:OwnerPublished = $true
            $script:OwnerPublishedICalUrl = "https://outlook.office365.com/owa/calendar/owner/calendar.ics"
            $Script:calendarEntries = @()
            $Script:receiverStats = @($Script:receiverStats[0])
            Mock -CommandName ProcessInternetCalendarLogs -MockWith {
                $script:CollectorStatuses["InternetCalendar"] = [PSCustomObject]@{ status = "Success"; error = $null }
                $script:ReceiverInternetCalendarEntries = @(
                    [PSCustomObject]@{ PublishingUrl = $script:OwnerPublishedICalUrl; Folder = "Published Owner" }
                )
            }

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR422").status | Should -Be "Detected"
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
            Mock Write-Host {}
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
            $oldEntryFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR233"
            $oldEntryFinding.status | Should -Be "Detected"
            @($oldEntryFinding.evidence.Keys | Sort-Object) |
                Should -Be @("oldModelEntryCount", "owner", "receiver")
            $oldEntryFinding.evidence.oldModelEntryCount | Should -Be 1
            $script:ConsoleFindingEvidence["SHR233"] |
                Should -Be "Get-CalendarEntries returned [1] Old entry(s) for [owner@contoso.com]."
            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "Old Model Calendar Sharing Entries:"
            }
        }

        It "does not collect InternetCalendar or display an empty Old entries table for a non-published owner" {
            Mock Write-Host {}

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            Should -Not -Invoke ProcessInternetCalendarLogs
            Should -Not -Invoke Write-Host -ParameterFilter {
                $Object -eq "Old Model Calendar Sharing Entries:"
            }
            $script:CollectorStatuses["InternetCalendar"].status | Should -Be "NotApplicable"
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR420").status |
                Should -Be "NotApplicable"
        }

        It "detects a receiver calendar renamed Outbox" {
            $Script:receiverStats += [PSCustomObject]@{
                FolderType           = "User Created"
                Name                 = "outbox"
                FolderPath           = "/outbox"
                FolderSize           = "1 KB"
                VisibleItemsInFolder = 0
            }
            Mock Write-Host {}

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR215").status |
                Should -Be "Detected"
            Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter {
                $Object -like "*Receiver calendar*renamed Outbox*"
            }
        }

        It "does not report an Outbox calendar for normally named receiver calendars" {
            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR215").status |
                Should -Be "NotDetected"
        }

        It "reports a numeric suffix on the uniquely matched folder" {
            $Script:receiverStats[1].Name = "Owner Display (1)"
            $Script:receiverStats[1].FolderPath = "/Calendar/Owner Display (1)"
            $Script:calendarEntries[0].CalendarName = "Owner Display (1)"

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Contain "SHR214"
        }

        It "does not warn for ranges, middle suffixes, or three-digit suffixes" {
            $Script:receiverStats = @(
                $Script:receiverStats[0],
                [PSCustomObject]@{
                    FolderType           = "User Created"
                    Name                 = "CUB01-3 McKinley (16-32) Public"
                    FolderPath           = "/CUB01-3 McKinley (16-32) Public"
                    FolderSize           = "1 KB"
                    VisibleItemsInFolder = 5
                },
                [PSCustomObject]@{
                    FolderType           = "User Created"
                    Name                 = "Archive (123)"
                    FolderPath           = "/Archive (123)"
                    FolderSize           = "1 KB"
                    VisibleItemsInFolder = 5
                }
            )
            $Script:calendarEntries = @()
            $Script:receiverMailbox.OrganizationalUnitRoot = "OU2"

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Not -Contain "SHR214"
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
            $script:OwnerCalendarSubfolderSelected = $true
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
            $script:OwnerCalendarSubfolderSelected = $true
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
            $script:OwnerCalendarSubfolderSelected = $true
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

            $script:OwnerCalendarFolderPathSpecified = $true
            $script:OwnerCalendarSubfolderSelected = $true
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

        It "detects the production item-count asymmetry with structured evidence" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 52
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 1061
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics

            $countFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR432"
            $countFinding.status | Should -Be "Detected"
            $countFinding.evidence.ownerCount | Should -Be 52
            $countFinding.evidence.receiverCount | Should -Be 1061
            $countFinding.evidence.delta | Should -Be 1009
            $countFinding.evidence.ratio | Should -Be 20.4
            $script:CalendarStatisticsComparison.PSObject.Properties.Name |
                Should -Be @("ownerCount", "receiverCount", "countDelta", "countRatio")
        }

        It "does not detect when the receiver count is below twice the owner count" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 200
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 399
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotDetected"
        }

        It "does not detect when the receiver count delta is below the absolute guard" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 1
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 100
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotDetected"
        }

        It "detects the exact absolute threshold safely when the owner count is zero" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 0
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 100
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "Detected"
            $script:CalendarStatisticsComparison.countRatio | Should -BeNullOrEmpty
        }

        It "keeps an owner-larger item count informational" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 500
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 100
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotDetected"
            $script:CalendarStatisticsComparison.countDelta | Should -Be -400
        }

        It "marks an unavailable item count NotEvaluated" {
            $ownerStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = "Unavailable"
            }
            $receiverStatistics = [PSCustomObject]@{
                VisibleItemsInFolder = 10
            }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $ownerStatistics `
                -ReceiverFolderStatistics $receiverStatistics
            Complete-SharingFindings

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotEvaluated"
        }

        It "marks the comparison NotApplicable without a unique receiver match" {
            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics ([PSCustomObject]@{
                    VisibleItemsInFolder = 10
                }) `
                -ReceiverFolderStatistics $null

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotApplicable"
        }

        It "marks the comparison NotEvaluated when receiver statistics are unavailable" {
            $script:CollectorStatuses["ReceiverFolderStatistics"] =
            [PSCustomObject]@{ status = "Unavailable"; error = "Access denied" }

            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics ([PSCustomObject]@{
                    VisibleItemsInFolder = 10
                }) `
                -ReceiverFolderStatistics $null

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR432").status |
                Should -Be "NotEvaluated"
        }
    }

    Context "Selected-folder accept logs" {
        It "leaves accept-log entries unfiltered when the explicitly selected calendar is the default" {
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:RequestedOwnerCalendarLeafName = "Calendar"
            Mock -CommandName Get-Date -MockWith { [DateTime]::new(2026, 10, 21) }
            Mock -CommandName Export-MailboxDiagnosticLogs -MockWith {
                [PSCustomObject]@{
                    MailboxLog = @(
                        "9/22/2026 6:35:50 AM,Mailbox: receiver,Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for owner@contoso.com,calendar name Owner Calendar",
                        "9/22/2026 6:35:49 AM,Mailbox: receiver,Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for other@contoso.com,calendar name Other Calendar"
                    ) -join "`r`n"
                }
            }

            $output = ProcessCalendarSharingAcceptLogs -Identity "receiver@contoso.com" | Out-String

            $script:ReceiverSelectedAcceptLogEntries.Count | Should -Be 2
            $output | Should -Match "Owner Calendar"
            $output | Should -Match "Other Calendar"
            $IncludeSensitiveData = $true
            (Get-SharingJsonRawData).receiver_SelectedAcceptLog.source | Should -BeLike "Not filtered:*default owner calendar*"
        }

        It "ignores stack-trace method names when parsing accept-log entries" {
            Mock -CommandName Get-Date -MockWith { [DateTime]::new(2026, 10, 21) }
            Mock Export-MailboxDiagnosticLogs {
                [PSCustomObject]@{
                    MailboxLog = @(
                        "9/22/2026 6:35:50 AM,Mailbox: receiver,Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for owner@contoso.com,calendar name Owner Calendar",
                        "   at Microsoft.Exchange.Entities.Calendaring.InternalSharing.InternalSharingHelpers.CreateInternalSharedCalendarGroupEntry(InternalSharingParameters internalSharingParameters,",
                        "09/22/2026 18:35:49,Mailbox: receiver,Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for other@contoso.com,calendar name Other Calendar",
                        "   at Microsoft.Exchange.Entities.Calendaring.InternalSharing.InternalSharingHelpers.<>c__DisplayClass7_0.<CreateInternalSharedCalendarGroupEntryWithFallbackRetryInternal>b__0()"
                    ) -join "`r`n"
                }
            }
            Mock Write-Error {}

            $output = ProcessCalendarSharingAcceptLogs -Identity "receiver@contoso.com" | Out-String

            $script:ReceiverAcceptLogEntries.Count | Should -Be 2
            $script:ReceiverAcceptLogRaw | Should -BeLike "*Owner Calendar*Other Calendar*"
            $script:ReceiverAcceptLogEntries.SharedCalendarOwner |
                Should -Be @("owner@contoso.com", "other@contoso.com")
            $script:EvaluationErrors | Should -BeNullOrEmpty
            $output | Should -Match "Owner Calendar"
            $output | Should -Match "Other Calendar"
            Should -Not -Invoke Write-Error
        }

        It "filters entries by both expected owner and selected folder" {
            $script:OwnerCalendarFolderPathSpecified = $true
            $script:OwnerCalendarSubfolderSelected = $true
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
        It "parses European day-first accept-log timestamps without a timestamp finding" {
            $recentDay = (Get-Date).AddDays(-2)
            $olderDay = (Get-Date).AddDays(-300)
            Mock Export-MailboxDiagnosticLogs {
                [PSCustomObject]@{
                    MailboxLog = @(
                        "$($recentDay.ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)) 13:44:31, Mailbox: 'Receiver Name', Entry GetPreAcceptCacheBySmtpAddress: Looking for primary calendar cache by owner@contoso.com",
                        "",
                        "$($recentDay.ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)) 13:44:31, Mailbox: 'Receiver Name', Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for owner@contoso.com, calendar name Owner Calendar",
                        "",
                        "$($olderDay.ToString('dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)) 07:28:54, Mailbox: 'Receiver Name', Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for old@contoso.com, calendar name Old Calendar"
                    ) -join "`r`n"
                }
            }
            Mock Write-Error {}
            Mock Write-Warning {}

            $output = ProcessCalendarSharingAcceptLogs -Identity "receiver@contoso.com" | Out-String

            $script:ReceiverAcceptLogEntries.Count | Should -Be 2
            $output | Should -Match "Owner Calendar"
            $output | Should -Not -Match "Old Calendar"
            $script:SharingFindings.ruleId | Should -Not -Contain "SHR220"
            $script:EvaluationErrors | Should -BeNullOrEmpty
            Should -Not -Invoke Write-Error
            Should -Not -Invoke Write-Warning
        }

        It "keeps entries with unparsable timestamps and marks the check incomplete" {
            Mock Export-MailboxDiagnosticLogs {
                [PSCustomObject]@{
                    MailboxLog = @(
                        "15/10/2026 13:44:31, Mailbox: 'Receiver Name', Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for owner@contoso.com, calendar name Owner Calendar",
                        "99/99/2026 13:44:31, Mailbox: 'Receiver Name', Entry CreateInternalSharedCalendarGroupEntry: Creating a shared calendar for other@contoso.com, calendar name Other Calendar"
                    ) -join "`r`n"
                }
            }
            Mock Write-Warning {}

            $output = ProcessCalendarSharingAcceptLogs -Identity "receiver@contoso.com" | Out-String

            $output | Should -Match "Other Calendar"
            $script:SharingFindings.ruleId | Should -Contain "SHR220"
            Should -Invoke Write-Warning -ParameterFilter { $Message -like "*could not be parsed*" }
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

        It "treats an uninitialized last attempt with a valid last success as incomplete" {
            $uninitializedDate = [DateTime]::new(1, 2, 1)
            $Script:receiverCalendarFolder.LastAttemptedSyncTime = $uninitializedDate
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = Get-Date

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

        It "reports that a calendar with a recent attempt but no success has never successfully synchronized" {
            $uninitializedDate = [DateTime]::new(1, 2, 1)
            $Script:receiverCalendarFolder.LastAttemptedSyncTime = Get-Date
            $Script:receiverCalendarFolder.LastSuccessfulSyncTime = $uninitializedDate
            Mock Write-Host {}

            GetReceiverInformation -Receiver "receiver@contoso.com"
            Complete-SharingFindings

            $neverSynchronizedFinding = $script:SharingFindings |
                Where-Object -Property ruleId -EQ "SHR403"
            $neverSynchronizedFinding.status | Should -Be "Detected"
            $neverSynchronizedFinding.evidence.attemptedSyncTimeUninitialized | Should -BeFalse
            $neverSynchronizedFinding.evidence.successfulSyncTimeUninitialized | Should -BeTrue
            $neverSynchronizedFinding.evidence.lastAttemptedSyncTime | Should -Not -BeNullOrEmpty
            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR401").status |
                Should -Be "NotDetected"
            foreach ($ruleId in @("SHR400", "SHR402")) {
                ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status |
                    Should -Be "NotApplicable"
            }
            Should -Invoke Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Red") -and
                ($Object -like "This calendar has never successfully synchronized*")
            }
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

        It "does not report permission flag differences caused only by the Editor flag (<Shape>)" -TestCases @(
            @{ Shape = "single comma-separated value"; ReceiverFlags = @("Editor, Delegate") }
            @{ Shape = "separate values"; ReceiverFlags = @("Editor", "Delegate") }
        ) {
            param($Shape, $ReceiverFlags)

            $Script:receiverCalendarFolder.SharingPermissionFlags = $ReceiverFlags
            $script:OwnerCalendarPermsAvailable = $true
            $script:OwnerCalendarPerms = @([PSCustomObject]@{
                    User                   = "receiver@contoso.com"
                    AccessRights           = @("Reviewer")
                    SharingPermissionFlags = @("Delegate")
                })

            GetReceiverInformation -Receiver "receiver@contoso.com"

            $script:SharingFindings.ruleId | Should -Not -Contain "SHR322"
        }

        It "still reports a permission flag difference other than Editor" {
            $Script:receiverCalendarFolder.SharingPermissionFlags = @("Editor, Reviewer")
            $script:OwnerCalendarPermsAvailable = $true
            $script:OwnerCalendarPerms = @([PSCustomObject]@{
                    User                   = "receiver@contoso.com"
                    AccessRights           = @("Reviewer")
                    SharingPermissionFlags = @("Delegate")
                })

            GetReceiverInformation -Receiver "receiver@contoso.com"

            ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR322").status |
                Should -Be "Detected"
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

        It -Name "reports the dated receiver invitation through <Address> with earlier timestamp <EarlierTimestamp>" -TestCases @(
            @{ Address = "receiver@contoso.com"; EarlierTimestamp = "9/1/2026 12:00:00" }
            @{ Address = " OLD.RECEIVER@CONTOSO.COM "; EarlierTimestamp = "9/1/2026 12:00:00" }
            @{ Address = "receiver@contoso.com"; EarlierTimestamp = "not-a-date" }
            @{ Address = " OLD.RECEIVER@CONTOSO.COM "; EarlierTimestamp = "not-a-date" }
        ) {
            param($Address, $EarlierTimestamp)
            $script:ReceiverMB = [PSCustomObject]@{
                PrimarySmtpAddress = "receiver@contoso.com"
                EmailAddresses     = @("SMTP:receiver@contoso.com", "smtp:old.receiver@contoso.com")
            }
            $script:OwnerInviteData = @(
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = $EarlierTimestamp; SharingType = "publish"; DetailLevel = "Full" }
                [PSCustomObject]@{ Recipient = $Address; Timestamp = "10/22/2026 12:00:00"; SharingType = "internal"; DetailLevel = "Editor" }
                [PSCustomObject]@{ Recipient = "other@contoso.com"; Timestamp = "10/23/2026 12:00:00"; SharingType = "internal"; DetailLevel = "Reviewer" }
            )

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Host -Times 1 -Exactly -ParameterFilter {
                $Object -eq "Latest sent sharing invitation (CalendarSharingInvite): [10/22/2026 12:00:00] (parsed as [2026-10-22 12:00:00]; sharing type [internal], detail level [Editor])."
            }
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Owner [owner@contoso.com]; receiver [receiver@contoso.com]."
            }
            $script:PublishedSharing | Should -BeFalse
            Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -like "*this entry cannot confirm that the selected calendar*"
            }
        }

        It "distinguishes a mailbox-wide invitation from evidence for a selected calendar subfolder" {
            $script:OwnerCalendarSubfolderSelected = $true
            $script:NormalizedOwnerCalendarFolderPath = "\Calendar\Project"
            $script:RequestedOwnerCalendarLeafName = "Project"
            $script:OwnerInviteData = @(
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = "10/22/2026 12:00:00"; SharingType = "internal"; DetailLevel = "Editor" }
            )

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Latest sent sharing invitation (CalendarSharingInvite): [10/22/2026 12:00:00] (parsed as [2026-10-22 12:00:00]; sharing type [internal], detail level [Editor])."
            }
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "The sent-invitation row does not identify a calendar folder, so it cannot confirm that the selected calendar [\Calendar\Project] was shared."
            }
            Get-PairSharingInvite | Should -BeNullOrEmpty
        }

        It -Name "reports the invitation without inventing a date for timestamp <Timestamp>" -TestCases @(
            @{ Timestamp = $null }
            @{ Timestamp = "not-a-date" }
        ) {
            param($Timestamp)
            $script:OwnerInviteData = @(
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = $Timestamp; SharingType = "internal"; DetailLevel = "Editor" }
            )

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Host -ParameterFilter {
                ($ForegroundColor -eq "Yellow") -and
                ($Object -eq "The owner invite log contains a sharing invitation to this receiver, but no reliable timestamp could be established.")
            }
            Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -like "Latest sent sharing invitation (CalendarSharingInvite):*"
            }
        }

        It -Name "does not assert an invitation when OtherRecipientEntry=<OtherRecipientEntry>" -TestCases @(
            @{ OtherRecipientEntry = $false }
            @{ OtherRecipientEntry = $true }
        ) {
            param($OtherRecipientEntry)
            if ($OtherRecipientEntry) {
                $script:OwnerInviteData = @(
                    [PSCustomObject]@{ Recipient = "other@contoso.com"; Timestamp = "10/22/2026 12:00:00"; SharingType = "internal"; DetailLevel = "Editor" }
                )
            }

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Owner-to-Receiver Sharing Timeline:"
            }
        }

        It -Name "warns for a gap greater than one week with receiver date <ReceiverDate>" -TestCases @(
            @{ ReceiverDate = "10/15/2026 12:00:00"; Warn = $false }
            @{ ReceiverDate = "10/14/2026 12:00:00"; Warn = $false }
            @{ ReceiverDate = "10/14/2026 11:59:00"; Warn = $true }
            @{ ReceiverDate = "10/13/2026 12:00:00"; Warn = $true }
            @{ ReceiverDate = "10/29/2026 12:00:00"; Warn = $true }
        ) {
            param($ReceiverDate, $Warn)
            $script:RunStartedAt = [DateTime]::new(2026, 10, 30, 12, 0, 0, [DateTimeKind]::Utc)
            $script:OwnerInviteData = @(
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = "10/21/2026 12:00:00"; SharingType = "internal"; DetailLevel = "Editor" }
            )
            $script:ReceiverAcceptLogEntries = @(
                [PSCustomObject]@{ SharedCalendarOwner = "owner@contoso.com"; Timestamp = $ReceiverDate; FolderName = "Owner calendar" }
            )
            Mock -CommandName Write-Warning -MockWith {}

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Warning -Times ([int]$Warn) -Exactly -ParameterFilter {
                $Message -like "*more than 7 days*"
            }
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object.StartsWith("Latest receiver acceptance entry (AcceptCalendarSharingInvite):")
            }
        }

        It "compares the newest owner-matching receiver entry and recognizes owner aliases" {
            $script:OwnerMB = [PSCustomObject]@{ EmailAddresses = @("smtp:owner.alias@contoso.com") }
            $script:OwnerInviteData = @(
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = "10/21/2026 12:00:00"; SharingType = "internal"; DetailLevel = "Editor" }
            )
            $script:ReceiverAcceptLogEntries = @(
                [PSCustomObject]@{ SharedCalendarOwner = "owner@contoso.com"; Timestamp = "9/1/2026 12:00:00"; FolderName = "Old calendar" }
                [PSCustomObject]@{ SharedCalendarOwner = "owner.alias@contoso.com"; Timestamp = "10/20/2026 12:00:00"; FolderName = "Owner calendar" }
                [PSCustomObject]@{ SharedCalendarOwner = "other@contoso.com"; Timestamp = "10/22/2026 12:00:00"; FolderName = "Other calendar" }
            )
            Mock -CommandName Write-Warning -MockWith {}

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "Latest receiver acceptance entry (AcceptCalendarSharingInvite): [10/20/2026 12:00:00] (parsed as [2026-10-20 12:00:00]; calendar name [Owner calendar])."
            }
            Should -Not -Invoke -CommandName Write-Warning
        }

        It "does not invent a timing gap when receiver dates are unreadable" {
            $script:OwnerInviteData = @(
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = "10/21/2026 12:00:00"; SharingType = "internal"; DetailLevel = "Editor" }
            )
            $script:ReceiverAcceptLogEntries = @(
                [PSCustomObject]@{ SharedCalendarOwner = "owner@contoso.com"; Timestamp = "not-a-date"; FolderName = "Owner calendar" }
            )
            Mock -CommandName Write-Warning -MockWith {}

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Not -Invoke -CommandName Write-Warning
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "A matching receiver acceptance entry exists, but no reliable timestamp could be established."
            }
        }

        It "keeps selected-calendar sync requests distinct from acceptance of another calendar" {
            $script:OwnerMB = [PSCustomObject]@{ ExchangeGuid = "11111111-1111-1111-1111-111111111111" }
            $script:OwnerCalendarSubfolderSelected = $true
            $script:RequestedOwnerCalendarLeafName = "Project"
            $script:NormalizedOwnerCalendarFolderPath = "\Calendar\Project"
            $script:OwnerInviteData = @(
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = "12/10/2026 10:21:03"; SharingType = "internal"; DetailLevel = "Editor" }
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = "15/10/2026 15:44:29"; SharingType = "internal"; DetailLevel = "Editor" }
                [PSCustomObject]@{ Recipient = "receiver@contoso.com"; Timestamp = "10/21/2026 7:18:03 AM"; SharingType = "internal"; DetailLevel = "Editor" }
            )
            $script:ReceiverAcceptLogEntries = @(
                [PSCustomObject]@{ SharedCalendarOwner = "owner@contoso.com"; Timestamp = "10/22/2026 12:00:00"; FolderName = "Other owner calendar" }
            )
            $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"] = @{
                data = @(
                    "05/05/2026 11:51:32, Mailbox: receiver, Entry RequestId: 'request-1', Sync Details for folder Project are [RMGUID, 11111111-1111-1111-1111-111111111111];[SPF, Editor]"
                    "10/22/2026 11:51:32, Mailbox: receiver, Entry RequestId: 'request-2', Sync Details for folder Project are [RMGUID, 22222222-2222-2222-2222-222222222222];[SPF, Editor]"
                    "10/22/2026 11:51:32, Mailbox: receiver, Entry RequestId: 'request-3', Sync Details for folder Another calendar are [RMGUID, 11111111-1111-1111-1111-111111111111];[SPF, Editor]"
                )
            }
            Mock -CommandName Write-Warning -MockWith {}

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object.StartsWith("Latest sent sharing invitation (CalendarSharingInvite): [10/21/2026 7:18:03 AM]")
            }
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object.StartsWith("Latest receiver synchronization request (SharingSyncAssistant): [05/05/2026 11:51:32]")
            }
            Should -Invoke -CommandName Write-Host -ParameterFilter {
                $Object.StartsWith("No acceptance entry identifies the selected calendar [\Calendar\Project].")
            }
            Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
                $Object.StartsWith("Latest receiver acceptance entry (AcceptCalendarSharingInvite):")
            }
            Should -Invoke -CommandName Write-Warning -Times 1 -Exactly -ParameterFilter {
                $Message -like "*latest receiver-side synchronization request*more than 7 days*"
            }
        }

        It "states that no confirmed issues or incomplete checks were recorded" {
            foreach ($collectorName in $Script:collectorNames) {
                $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "Success"; error = $null }
            }
            $script:CalendarStatisticsComparisonPerformed = $true
            $script:OwnerCalendarPermsAvailable = $true
            Test-ReceiverDelegatePermissions

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

        It "prints recommended next steps as full-width lines below the findings table" {
            Add-SharingFinding -RuleId "SHR324" -Status Detected -Evidence @{
                reason = "Legacy MAPI relationship"
            }

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke Write-Host -ParameterFilter {
                $Object -eq "[SHR324] Upgrade to Modern Calendar Sharing by following https://support.microsoft.com/en-us/outlook/calendar-sharing-in-microsoft-365"
            }
        }

        It -Name "groups identical next steps for <Status> findings without combining the findings" -TestCases @(
            @{ Status = "Detected" }
            @{ Status = "NotEvaluated" }
        ) {
            param($Status)
            Add-SharingFinding -RuleId "SHR231" -Status $Status
            Add-SharingFinding -RuleId "SHR311" -Status $Status

            Write-SharingSummary -Owner "owner@contoso.com" -Receiver "receiver@contoso.com"

            Should -Invoke -CommandName Write-Host -Times 1 -Exactly -ParameterFilter {
                $Object -eq "[SHR231, SHR311] Inspect invite or accept logs and sharing assistant diagnostics."
            }
            Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
                $Object -eq "[SHR231] Inspect invite or accept logs and sharing assistant diagnostics." -or
                $Object -eq "[SHR311] Inspect invite or accept logs and sharing assistant diagnostics."
            }
            $findings = @((Get-SharingJsonReportObject).findings | Where-Object { $_.ruleId -in @("SHR231", "SHR311") })
            $findings.Count | Should -Be 2
            $findings.ruleId | Should -Be @("SHR231", "SHR311")
            foreach ($finding in $findings) {
                $finding.status | Should -Be $Status
                $finding.recommendedNextStep | Should -Be "Inspect invite or accept logs and sharing assistant diagnostics."
            }
        }

        It "preserves severity and rule ordering when grouping recommendations" {
            foreach ($ruleId in @("SHR409", "SHR311", "SHR213", "SHR231")) {
                Add-SharingFinding -RuleId $ruleId -Status Detected
            }
            $script:nextStepLines = [System.Collections.Generic.List[string]]::new()
            Mock -CommandName Write-Host -MockWith {
                if (($ForegroundColor -eq "Yellow") -and ($Object -like "[[]SHR*")) {
                    $script:nextStepLines.Add([string]$Object)
                }
            }

            Write-SharingFindingDetails -Findings $script:SharingFindings -SeverityOrder @{
                Critical = 0; Error = 1; Warning = 2; Information = 3
            }

            @($script:nextStepLines) | Should -Be @(
                "[SHR213] Inspect invite or accept logs and calendar entries for the pair."
                "[SHR231, SHR311] Inspect invite or accept logs and sharing assistant diagnostics."
                "[SHR409] Review the exceptions in the sharing logs (rawData in the JSON report) and correlate them with the synchronization state."
            )
            $script:SharingFindings.Count | Should -Be 4
        }

        It "capitalizes displayed finding table headers without changing structured properties" {
            Add-SharingFinding -RuleId "SHR121" -Status Detected -Evidence @{
                extendedFolderFlags = @()
            }

            $output = Write-SharingSummary `
                -Owner "owner@contoso.com" `
                -Receiver "receiver@contoso.com" |
                Out-String -Width 200

            $output | Should -Match "Severity\s+RuleId\s+Title\s+Evidence"
            $script:SharingFindings[0].PSObject.Properties.Name |
                Should -Contain "severity"
            $script:SharingFindings[0].PSObject.Properties.Name |
                Should -Contain "ruleId"
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

Describe "Check-SharingStatus external model applicability" {
    BeforeEach {
        Initialize-SharingTestState
        Initialize-OwnerMocks
        Initialize-ReceiverMocks
        $Script:receiverMailbox.OrganizationalUnitRoot = "OU2"
        $script:ReceiverMB = $Script:receiverMailbox
        $Script:calendarEntries = @()
        $Script:receiverCalendarFolder.ExtendedFolderFlags = @(
            "ReadOnly", "SharedIn", "PersonalShare", "ExclusivelyBound", "ExchangeCrossOrgShareFolder")
        $Script:receiverCalendarFolder.SharingPermissionFlags = @("None")
        $Script:receiverCalendarFolder.SharedCalendarSyncStartDate = [DateTime]::MinValue
        $script:OwnerCalendarFolder.ExtendedFolderFlags = @("SharedViaExchange")
        $script:OwnerSelectedCalendar = [PSCustomObject]@{ VisibleItemsInFolder = 10 }
        $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = "receiver@contoso.com"; SharingType = "external" })
        foreach ($collectorName in $Script:collectorNames) {
            $script:CollectorStatuses[$collectorName] = [PSCustomObject]@{ status = "Success"; error = $null }
        }
        Mock Write-Host {}
        Mock Get-CalendarEntries { throw "Internal calendar-entry diagnostics must not run for external sharing." }
    }

    It "does not report internal REST failures for the good external sharing repro" {
        foreach ($ruleId in $script:InternalRestRuleIds) {
            Add-SharingFinding -RuleId $ruleId -Status Detected -Evidence @{ reason = "Earlier internal-only observation." }
        }
        GetReceiverInformation -Receiver $Receiver
        Test-ReceiverDelegatePermissions
        Test-ReceiverSharingLogFreshness
        Complete-SharingFindings

        $script:ExternalSharing | Should -BeTrue
        $script:ModernSharing | Should -BeFalse
        Get-SharingRelationshipKind | Should -Be "External: External Sharing"
        foreach ($ruleId in $script:InternalRestRuleIds + @("SHR325")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotApplicable"
        }
        @($script:SharingFindings | Where-Object -Property status -EQ "Detected").Count | Should -Be 0
        Should -Not -Invoke Get-CalendarEntries
        Should -Not -Invoke ProcessCalendarSharingAcceptLogs
        Should -Not -Invoke Write-Host -ParameterFilter {
            $Object -like "*missing ExchangeShareFolder*" -or
            $Object -like "*does not have an initialized SharedCalendarSyncStartDate*" -or
            $Object -like "*more than 7 days old*"
        }
        $report = Get-SharingJsonReportObject
        $report.sharing.sharingModel | Should -Be "ExternalSharing"
        $report.sharing.relationshipKind | Should -Be "External: External Sharing"
        $report.summary.overallResult | Should -Be "Pass"
        $report.summary.inconclusiveCount | Should -Be 0
    }

    It "retains external owner, SharedIn and synchronization failure checks" {
        $Script:receiverCalendarFolder.ExtendedFolderFlags = @("ExchangeCrossOrgShareFolder")
        $Script:receiverCalendarFolder.CalendarSharingOwnerSmtpAddress = "other@contoso.com"
        $Script:receiverCalendarFolder.LastSuccessfulSyncTime = (Get-Date).AddHours(-1)
        GetReceiverInformation -Receiver $Receiver
        Complete-SharingFindings
        foreach ($ruleId in @("SHR241", "SHR243", "SHR402")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "Detected"
        }
    }

    It "recognizes publishing with disabled owner from <Signal>" -TestCases @(
        @{ Signal = "PublishInvite" }
        @{ Signal = "PublishedPermission" }
        @{ Signal = "WebCalFolder" }
    ) {
        param($Signal)
        $script:OwnerInviteData = @()
        switch ($Signal) {
            "PublishInvite" {
                $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = $Receiver; SharingType = "publish" })
            }
            "PublishedPermission" {
                $script:OwnerCalendarPerms = @([PSCustomObject]@{ User = "ExchangePublishedUser.$Receiver"; AccessRights = @("Reviewer") })
            }
            "WebCalFolder" {
                $Script:receiverCalendarFolder.ExtendedFolderFlags = @(
                    "ReadOnly", "WebCalFolder", "SharedIn", "PersonalShare", "SharedExchangeValid", "ExclusivelyBound")
            }
        }
        GetReceiverInformation -Receiver $Receiver
        Complete-SharingFindings
        $script:PublishedSharing | Should -BeTrue
        $script:ExternalSharing | Should -BeFalse
        $script:ModernSharing | Should -BeFalse
        Get-SharingRelationshipKind | Should -Be "External: Publishing"
        $finding = $script:SharingFindings | Where-Object -Property ruleId -EQ "SHR424"
        $finding.status | Should -Be "Detected"
        $finding.severity | Should -Be "Error"
        $finding.evidence.publishEnabled | Should -BeFalse
        foreach ($ruleId in @("SHR121", "SHR122", "SHR231", "SHR242", "SHR405", "SHR407", "SHR413", "SHR421", "SHR422", "SHR423")) {
            ($script:SharingFindings | Where-Object -Property ruleId -EQ $ruleId).status | Should -Be "NotApplicable"
        }
        Should -Not -Invoke Get-CalendarEntries
        Should -Not -Invoke ProcessInternetCalendarLogs
    }

    It "correlates published permission entries using the receiver's SMTP aliases" {
        $Script:receiverMailbox | Add-Member -NotePropertyName EmailAddresses -NotePropertyValue @(
            "SMTP:receiver@contoso.com", "smtp:alias@contoso.net", "X500:/o=NotAnSmtpAddress")
        $script:OwnerInviteData = @()
        $script:OwnerCalendarPerms = @([PSCustomObject]@{ User = "ExchangePublishedUser.alias@contoso.net" })
        GetReceiverInformation -Receiver $Receiver
        Complete-SharingFindings
        $script:PublishedSharing | Should -BeTrue
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR424").status | Should -Be "Detected"
    }

    It "does not infer publishing from another recipient or an enabled owner alone" {
        $script:OwnerPublished = $true
        $script:OwnerPublishedICalUrl = "https://example.com/calendar.ics"
        $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = "other@contoso.com"; SharingType = "publish" })
        $script:OwnerCalendarPerms = @([PSCustomObject]@{ User = "ExchangePublishedUser.other@contoso.com" })
        GetReceiverInformation -Receiver $Receiver
        Complete-SharingFindings
        $script:PublishedSharing | Should -BeFalse
        $script:ExternalSharing | Should -BeTrue
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR424").status | Should -Be "NotApplicable"
    }

    It "uses the most recent pair-specific sharing invitation rather than old publishing history" {
        $script:OwnerInviteData = @(
            [PSCustomObject]@{ Recipient = $Receiver; SharingType = "publish"; Timestamp = "2026-09-01T12:00:00Z" },
            [PSCustomObject]@{ Recipient = $Receiver; SharingType = "external"; Timestamp = "2026-10-01T12:00:00Z" }
        )
        GetReceiverInformation -Receiver $Receiver
        $script:PublishedSharing | Should -BeFalse
        $script:ExternalSharing | Should -BeTrue
    }

    It "does not infer a sharing model from incomplete organization evidence" {
        $Script:receiverMailbox.OrganizationalUnitRoot = $null
        $script:OwnerMB.OrganizationalUnitRoot = $null
        $script:OwnerInviteData = @()
        Initialize-SharingOrganizationScope
        $script:SharingType | Should -Be "Undetermined"
        Get-SharingRelationshipKind | Should -Be "Undetermined"
        Get-SharingRuleNotApplicableReason -RuleId "SHR121" | Should -BeNullOrEmpty
    }

    It "does not discard genuine exception diagnostics for an external relationship" {
        Initialize-SharingOrganizationScope
        $script:OwnerInviteLogRaw = "2026-10-22T12:00:00Z InvalidOperationException"
        Test-SharingLogExceptions
        Complete-SharingFindings
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR409").status | Should -Be "Detected"
    }

    It "removes irrelevant internal collector and rule-scoped evaluation failures only" {
        $script:CollectionErrors.Add([PSCustomObject]@{ collector = "CalendarEntries"; error = "Internal-only lookup failure" })
        $script:CollectionErrors.Add([PSCustomObject]@{ collector = "ReceiverFolderStatistics"; error = "Applicable failure" })
        $script:EvaluationErrors.Add([PSCustomObject]@{ evaluation = "Internal freshness"; ruleIds = @("SHR405"); error = "Internal-only failure" })
        $script:EvaluationErrors.Add([PSCustomObject]@{ evaluation = "Sync"; ruleIds = @("SHR402"); error = "Applicable failure" })
        Initialize-SharingOrganizationScope
        Complete-SharingFindings
        $script:CollectionErrors.Count | Should -Be 1
        $script:CollectionErrors[0].collector | Should -Be "ReceiverFolderStatistics"
        $script:EvaluationErrors.Count | Should -Be 1
        $script:EvaluationErrors[0].evaluation | Should -Be "Sync"
        $script:CollectorStatuses["CalendarEntries"].status | Should -Be "NotApplicable"
    }

    It "preserves mailbox-wide diagnostic collection status and failures for external sharing" {
        Initialize-SharingOrganizationScope
        $script:CollectorStatuses["ReceiverSharingSyncAssistantLog"].status = "Success"
        $script:CollectorStatuses["ReceiverSharingLog"].status = "Failed"
        $script:CollectionErrors.Add([PSCustomObject]@{ collector = "ReceiverSharingLog"; error = "Access denied" })

        Complete-SharingFindings

        $script:CollectorStatuses["ReceiverSharingSyncAssistantLog"].status | Should -Be "Success"
        $script:CollectorStatuses["ReceiverSharingLog"].status | Should -Be "Failed"
        $script:CollectionErrors.Count | Should -Be 1
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR405").status | Should -Be "NotApplicable"
    }

    It "does not execute rule-scoped internal evaluations for an external pair" {
        Initialize-SharingOrganizationScope
        Invoke-SharingEvaluation -Name "Internal freshness" -RuleIds @("SHR405") -Action { throw "Must not execute" }
        $script:EvaluationErrors.Count | Should -Be 0
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR405").status | Should -Be "NotApplicable"
    }

    It "keeps the full external orchestration from retrying internal-only collectors" {
        Mock Resolve-SharingMailboxPrerequisites { $true }
        Mock Resolve-OwnerCalendarPrerequisite { $true }
        Mock Test-ReceiverSharingLogFreshness {}
        Invoke-SharingDiagnostics
        $script:ExternalSharing | Should -BeTrue
        $script:CollectorStatuses["ReceiverAcceptLog"].status | Should -Be "NotApplicable"
        Should -Not -Invoke ProcessCalendarSharingAcceptLogs
        Should -Not -Invoke Get-CalendarEntries
        Should -Not -Invoke Get-CalendarActiveSharingInformation
        Should -Not -Invoke Test-ReceiverSharingLogFreshness
        $script:EvaluationErrors.Count | Should -Be 0
    }

    It "does not mistake an unavailable publishing setting for disabled publishing" {
        $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = $Receiver; SharingType = "publish" })
        $script:OwnerCalendarFolder.PSObject.Properties.Remove("PublishEnabled")
        GetReceiverInformation -Receiver $Receiver
        Complete-SharingFindings
        $script:PublishedSharing | Should -BeTrue
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR424").status | Should -Be "NotEvaluated"
    }

    It "does not use an unrelated mailbox-wide invitation for a selected calendar subfolder" {
        $script:OwnerCalendarSubfolderSelected = $true
        $script:RequestedOwnerCalendarLeafName = "Project"
        $script:OwnerInviteData = @([PSCustomObject]@{ Recipient = $Receiver; SharingType = "publish" })
        Get-PairSharingInvite | Should -BeNullOrEmpty
    }

    It "does not choose a current invitation from <History> conflicting history" -TestCases @(
        @{ History = "undated"; Timestamp = "not-a-date" }
        @{ History = "tied"; Timestamp = "2026-10-22T12:00:00Z" }
    ) {
        param($History, $Timestamp)
        $script:OwnerInviteData = @(
            [PSCustomObject]@{ Recipient = $Receiver; SharingType = "publish"; Timestamp = $Timestamp },
            [PSCustomObject]@{ Recipient = $Receiver; SharingType = "external"; Timestamp = $Timestamp }
        )
        Get-PairSharingInvite | Should -BeNullOrEmpty
    }

    It "preserves internal REST failures and explicit four-model labels" {
        $script:SharingType = "InternalSharing"
        $script:ModernSharing = $true
        Add-SharingFinding -RuleId "SHR121" -Status Detected -Evidence @{ reason = "Missing internal flag" }
        Complete-SharingFindings
        ($script:SharingFindings | Where-Object -Property ruleId -EQ "SHR121").status | Should -Be "Detected"
        Get-SharingRelationshipKind | Should -Be "Internal: REST (New Model)"
        $script:ModernSharing = $false
        $script:LegacyMapiSharing = $true
        Get-SharingRelationshipKind | Should -Be "Internal: MAPI (old Model)"
    }
}
