# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $Script:calendarPath = Split-Path -Path $PSScriptRoot -Parent
    $Script:scriptPath = Join-Path -Path $Script:calendarPath -ChildPath "Get-RBASummary.ps1"
    $Script:packageHelperPath = Join-Path -Path $Script:calendarPath -ChildPath "..\.build\BuildFunctions\New-PrototypeSkillFiles.ps1"
    $Script:skillPath = Join-Path -Path $Script:calendarPath -ChildPath "RBA\exo-rba-troubleshooting"

    function Get-Mailbox { param($Identity, $SoftDeletedMailbox, $ErrorAction) }
    function Get-Place { param($Identity, $ErrorAction) }
    function Get-InboxRule { param($Mailbox, $IncludeHidden, $ErrorAction) }
    function Get-CalendarProcessing { param($Identity, $ErrorAction) }
    function Get-MailboxFolderStatistics { param($Identity, $FolderScope, $ErrorAction) }
    function Get-MailboxFolderPermission { param($Identity, $ErrorAction) }
    function Get-MailboxPermission { param($Identity, $ErrorAction) }
    function Export-MailboxDiagnosticLogs { param($Identity, $ComponentName, $ErrorAction) }
    function Get-Recipient { param($Identity, $Organization, $ErrorAction) }

    function Get-TestCalendarProcessing {
        [PSCustomObject]@{
            AutomateProcessing                  = "AutoAccept"
            AllowConflicts                      = $false
            AllowDistributionGroup              = $true
            AllowMultipleResources              = $true
            MaximumDurationInMinutes            = 1440
            MinimumDurationInMinutes            = 0
            AllowRecurringMeetings              = $true
            ScheduleOnlyDuringWorkHours         = $false
            ProcessExternalMeetingMessages      = $false
            BookingWindowInDays                 = 180
            ConflictPercentageAllowed           = 0
            MaximumConflictInstances            = 0
            MaximumConflictPercentage           = 0
            EnforceSchedulingHorizon            = $true
            EnforceCapacity                     = $false
            RequestOutOfPolicy                  = @()
            AllRequestOutOfPolicy               = $false
            BookInPolicy                        = @("allowed@contoso.com")
            AllBookInPolicy                     = $true
            RequestInPolicy                     = @()
            AllRequestInPolicy                  = $true
            ResourceDelegates                   = @("delegate@contoso.com")
            AddNewRequestsTentatively           = $true
            ForwardRequestsToDelegates          = $true
            AddOrganizerToSubject               = $true
            DeleteSubject                       = $true
            DeleteComments                      = $false
            DeleteAttachments                   = $true
            RemovePrivateProperty               = $true
            DeleteNonCalendarItems              = $true
            RemoveForwardedMeetingNotifications = $false
            RemoveCanceledMeetings              = $false
            EnableAutoRelease                   = $false
            AddAdditionalResponse               = $true
            AdditionalResponse                  = "Contact delegate@contoso.com"
        }
    }

    function Initialize-StandardMocks {
        Mock Get-Place {
            [PSCustomObject]@{
                City            = "Redmond"
                Floor           = 1
                Capacity        = 8
                Localities      = @("RoomList@contoso.com")
                Street          = "1 Microsoft Way"
                State           = "WA"
                PostalCode      = "98052"
                CountryOrRegion = "US"
                Building        = "1"
                Tags            = @("Display")
            }
        }
        Mock Get-InboxRule { @([PSCustomObject]@{ Name = "Default Junk Email" }) }
        Mock Get-CalendarProcessing { Get-TestCalendarProcessing }
        Mock Get-MailboxFolderStatistics {
            [PSCustomObject]@{
                Name       = "Calendar"
                FolderType = "Calendar"
            }
        }
        Mock Get-MailboxFolderPermission {
            @(
                [PSCustomObject]@{
                    User                   = "Default"
                    AccessRights           = @("AvailabilityOnly")
                    SharingPermissionFlags = @()
                }
                [PSCustomObject]@{
                    User                   = "delegate@contoso.com"
                    AccessRights           = @("Editor")
                    SharingPermissionFlags = @("Delegate")
                }
            )
        }
        Mock Get-MailboxPermission {
            @([PSCustomObject]@{
                    User         = "NT AUTHORITY\SELF"
                    AccessRights = @("FullAccess")
                    IsInherited  = $false
                    Deny         = $false
                })
        }
        Mock Export-MailboxDiagnosticLogs {
            [PSCustomObject]@{
                MailboxLog = @(
                    "2026-08-28T10:00:02Z, Entry Action: Message, LogComment: Action:Accept"
                    "2026-08-28T10:00:00Z, START - HandleEventInternal Automatic Booking is enabled for resource."
                ) -join "`r`n"
            }
        }
        Mock Get-Recipient {
            [PSCustomObject]@{
                DisplayName        = "Resolved user"
                PrimarySmtpAddress = $Identity
            }
        }
    }

    function Invoke-TestRbaSummary {
        param(
            [switch]$IncludeSensitiveData,

            [string]$MeetingSubject
        )

        Push-Location -Path $TestDrive
        try {
            $params = @{
                Identity         = "room@contoso.com"
                SkipVersionCheck = $true
            }
            if ($IncludeSensitiveData) {
                $params.IncludeSensitiveData = $true
            }
            if (-not [string]::IsNullOrWhiteSpace($MeetingSubject)) {
                $params.MeetingSubject = $MeetingSubject
            }
            & $Script:scriptPath @params
            $jsonPath = Get-ChildItem -Path $TestDrive -Filter "RBA-Summary-For_room_*.json" |
                Sort-Object -Property LastWriteTime | Select-Object -Last 1
            return Get-Content -Path $jsonPath.FullName -Raw | ConvertFrom-Json
        } finally {
            Pop-Location
        }
    }
}

Describe "Get-RBASummary best-effort report" {
    BeforeEach {
        Initialize-StandardMocks
        Mock Get-Mailbox {
            [PSCustomObject]@{
                Identity                  = "room@contoso.com"
                DisplayName               = "Conference Room"
                Alias                     = "room"
                PrimarySmtpAddress        = "room@contoso.com"
                EmailAddresses            = @("SMTP:room@contoso.com", "smtp:old-room@contoso.com")
                ExchangeGuid              = "11111111-1111-1111-1111-111111111111"
                ExternalDirectoryObjectId = "22222222-2222-2222-2222-222222222222"
                WhenCreatedUTC            = [DateTime]"2025-01-01T00:00:00Z"
                WhenChangedUTC            = [DateTime]"2026-01-01T00:00:00Z"
                RecipientTypeDetails      = "RoomMailbox"
                ResourceType              = "Room"
                Database                  = "DatabaseGroup01"
                ServerName                = "server"
            }
        }
    }

    It "continues all collectors and writes partial JSON after a collector failure" {
        Mock Get-Mailbox { throw "Mailbox unavailable" }

        $report = Invoke-TestRbaSummary

        Assert-MockCalled -CommandName Get-Mailbox -Exactly 2
        Assert-MockCalled -CommandName Get-Place -Exactly 1
        Assert-MockCalled -CommandName Get-InboxRule -Exactly 1
        Assert-MockCalled -CommandName Get-CalendarProcessing -Exactly 1
        Assert-MockCalled -CommandName Get-MailboxFolderPermission -Exactly 1
        Assert-MockCalled -CommandName Get-MailboxPermission -Exactly 1
        Assert-MockCalled -CommandName Export-MailboxDiagnosticLogs -Exactly 1
        $report.metadata.collectionStatus | Should -Be "Partial"
        $report.collectors.Mailbox.status | Should -Be "Failed"
        $report.collectionErrors.collector | Should -Contain "Mailbox"
        @($report.collectionErrors | Where-Object { $_.collector -eq "Mailbox" }).Count | Should -Be 1
        ($report.findings | Where-Object { $_.ruleId -eq "RBA001" }).status | Should -Be "Detected"
    }

    It "detects a recoverable soft-deleted room after the active lookup fails" {
        Mock Get-Mailbox { throw "Active mailbox not found" } -ParameterFilter { -not $SoftDeletedMailbox }
        Mock Get-Mailbox {
            [PSCustomObject]@{
                Identity             = "room@contoso.com"
                PrimarySmtpAddress   = "room@contoso.com"
                EmailAddresses       = @("SMTP:room@contoso.com")
                RecipientTypeDetails = "RoomMailbox"
                ResourceType         = "Room"
            }
        } -ParameterFilter { $SoftDeletedMailbox }

        $report = Invoke-TestRbaSummary

        $report.collectors.Mailbox.status | Should -Be "Success"
        $report.mailbox.objectState | Should -Be "SoftDeleted"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA101" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA100" }).status | Should -Be "NotApplicable"
        Assert-MockCalled -CommandName Get-Mailbox -Exactly 1 -ParameterFilter { -not $SoftDeletedMailbox }
        Assert-MockCalled -CommandName Get-Mailbox -Exactly 1 -ParameterFilter { $SoftDeletedMailbox }
    }

    It "reports when an old SMTP proxy resolves to the current room mailbox" {
        Push-Location -Path $TestDrive
        try {
            & $Script:scriptPath -Identity "old-room@contoso.com" -SkipVersionCheck
            $jsonPath = Get-ChildItem -Path $TestDrive -Filter "RBA-Summary-For_old-room_*.json" |
                Sort-Object -Property LastWriteTime | Select-Object -Last 1
            $report = Get-Content -Path $jsonPath.FullName -Raw | ConvertFrom-Json
        } finally {
            Pop-Location
        }

        $report.mailbox.primarySmtpAddress | Should -Be "room@contoso.com"
        $report.mailbox.inputIdentityMatch | Should -Be "ProxyAddress"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA102" }).status | Should -Be "Detected"
    }

    It "continues to skill guidance when the JSON file write fails" {
        Mock Set-Content { throw [System.IO.IOException]::new("JSON destination unavailable") } -ParameterFilter {
            $Path -like "RBA-Summary-For_room_*.json"
        }

        Push-Location -Path $TestDrive
        try {
            $output = & $Script:scriptPath -Identity "room@contoso.com" -SkipVersionCheck *>&1 | Out-String
        } finally {
            Pop-Location
        }

        Assert-MockCalled -CommandName Set-Content -Exactly 1 -ParameterFilter {
            $Path -like "RBA-Summary-For_room_*.json" -and $ErrorAction -eq "Stop"
        }
        $output | Should -Match "Unable to write RBA JSON output"
        $output | Should -Match "Tenant admins can install and use the EXO RBA troubleshooting skill"
    }

    It "marks a collector failed when post-collection evidence processing throws" {
        Push-Location -Path $TestDrive
        try {
            . $Script:scriptPath -Identity "room@contoso.com" -SkipVersionCheck *>&1 | Out-Null
            $collectedEvidence = @($script:RBALog)
            $unknownError = ConvertTo-RbaErrorInfo -ErrorRecord ([PSCustomObject]@{})

            Invoke-RbaCollectorOperation -Name "RbaLog" -Action {
                throw [System.InvalidOperationException]::new("RBA log processing failed")
            }
            $JsonFilename = Join-Path -Path $TestDrive -ChildPath "PostCollectionFailure.json"
            Write-RbaJson
            $report = Get-Content -Path $JsonFilename -Raw | ConvertFrom-Json
        } finally {
            Pop-Location
        }

        $report.metadata.collectionStatus | Should -Be "Partial"
        $report.collectors.RbaLog.status | Should -Be "Failed"
        $report.collectors.RbaLog.error | Should -Be "RBA log processing failed"
        @($report.collectionErrors | Where-Object { $_.collector -eq "RbaLog" }).Count | Should -Be 1
        $report.rbaLogSummary | Should -BeNullOrEmpty
        ($report.findings | Where-Object { $_.ruleId -eq "RBA005" }).status | Should -Be "Detected"
        @($script:RBALog) | Should -Be $collectedEvidence
        $unknownError.message | Should -Be "Unknown error."
        $unknownError.exceptionType | Should -BeNullOrEmpty
        $unknownError.category | Should -BeNullOrEmpty
        $unknownError.fullyQualifiedErrorId | Should -BeNullOrEmpty
    }

    It "emits bounded structured error metadata without diagnostic internals" {
        Mock Get-Mailbox {
            $innerException = [System.Exception]::new("Inner detail")
            $errorMessage = [string]::Join([Environment]::NewLine, @("Mailbox", "unavailable"))
            $exception = [System.InvalidOperationException]::new($errorMessage, $innerException)
            Write-Error -Exception $exception -Message $exception.Message -Category PermissionDenied `
                -ErrorId "RbaMailboxFailure" -ErrorAction Stop
        }

        $report = Invoke-TestRbaSummary
        $collector = $report.collectors.Mailbox
        $errorEntry = @($report.collectionErrors | Where-Object { $_.collector -eq "Mailbox" })[0]

        $collector.error | Should -Be "Mailbox unavailable"
        $collector.exceptionType | Should -Be "System.InvalidOperationException"
        $collector.category | Should -Be "PermissionDenied"
        $collector.fullyQualifiedErrorId | Should -Match "RbaMailboxFailure"
        $collector.innerExceptionMessage | Should -Be "Inner detail"
        $collector.error.Length | Should -BeLessOrEqual 2048
        $errorEntry.message | Should -Be $collector.error
        $errorEntry.PSObject.Properties.Name | Should -Not -Contain "scriptStackTrace"
        $errorEntry.PSObject.Properties.Name | Should -Not -Contain "invocationInfo"
        $errorEntry.PSObject.Properties.Name | Should -Not -Contain "targetObject"
        $errorEntry.PSObject.Properties.Name | Should -Not -Contain "positionMessage"
    }

    It "treats an empty inbox-rule result as successful evidence" {
        Mock Get-InboxRule { @() }

        $report = Invoke-TestRbaSummary

        $report.collectors.InboxRules.status | Should -Be "Success"
        $report.inboxRules.totalCount | Should -Be 0
        $report.inboxRules.delegateRuleCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA200" }).status | Should -Be "NotDetected"
    }

    It "still treats a null scalar collector result as a failure" {
        Mock Get-Place { $null }

        $report = Invoke-TestRbaSummary

        $report.collectors.Place.status | Should -Be "Failed"
        $report.collectionErrors.collector | Should -Contain "Place"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA002" }).status | Should -Be "Detected"
    }

    It "sanitizes non-target identities and emits the documented finding families by default" {
        $report = Invoke-TestRbaSummary

        $report.metadata.privacyMode | Should -Be "Sanitized"
        $report.metadata.identity | Should -Be "room@contoso.com"
        $report.mailbox.objectState | Should -Be "Active"
        $report.mailbox.inputIdentityMatch | Should -Be "PrimarySmtpAddress"
        $report.mailbox.PSObject.Properties.Name | Should -Not -Contain "emailAddresses"
        $report.mailbox.PSObject.Properties.Name | Should -Not -Contain "exchangeGuid"
        $report.calendarProcessing.resourceDelegates | Should -Contain "SanitizedIdentity-2"
        $report.calendarProcessing.resourceDelegates | Should -Not -Contain "delegate@contoso.com"
        $report.calendarProcessing.PSObject.Properties.Name | Should -Not -Contain "additionalResponse"
        $report.PSObject.Properties.Name | Should -Not -Contain "fullRbaLog"
        $report.meetingLogSearch.searchSubject | Should -BeNullOrEmpty
        $report.meetingLogSearch.status | Should -Be "NotRequested"
        $report.meetingLogSearch.sourceOrder | Should -Be "NewestFirst"
        $report.meetingLogSearch.eventOrder | Should -Be "NewestFirst"
        $report.meetingLogSearch.rawLogChronologicalReadDirection | Should -Be "BottomToTop"
        $report.meetingLogSearch.subjectMatchCount | Should -Be 0
        @($report.meetingLogSearch.meetingIds).Count | Should -Be 0
        $report.meetingLogSearch.eventCount | Should -Be 0
        $report.meetingLogSearch.acceptCount | Should -Be 0
        $report.meetingLogSearch.tentativeCount | Should -Be 0
        $report.meetingLogSearch.declineCount | Should -Be 0
        $report.meetingLogSearch.updateCount | Should -Be 0
        $report.meetingLogSearch.cancellationCount | Should -Be 0
        $report.meetingLogSearch.delegateReferralCount | Should -Be 0
        $report.meetingLogSearch.externalSkippedCount | Should -Be 0
        $report.meetingLogSearch.horizonDeclineCount | Should -Be 0
        $report.meetingLogSearch.recurrenceTruncateCount | Should -Be 0
        @($report.meetingLogSearch.events).Count | Should -Be 0
        @($report.findings.ruleId) | Should -Contain "RBA001"
        @($report.findings.ruleId) | Should -Contain "RBA100"
        @($report.findings.ruleId) | Should -Contain "RBA101"
        @($report.findings.ruleId) | Should -Contain "RBA102"
        @($report.findings.ruleId) | Should -Contain "RBA200"
        @($report.findings.ruleId) | Should -Contain "RBA300"
        @($report.findings.ruleId) | Should -Contain "RBA400"
        @($report.findings.ruleId) | Should -Contain "RBA500"
        @($report.findings.ruleId) | Should -Contain "RBA600"
        @($report.findings.ruleId) | Should -Contain "RBA700"
        @($report.findings.ruleId) | Should -Contain "RBA703"
        @($report.findings.ruleId) | Should -Contain "RBA710"
        @($report.findings.ruleId) | Should -Contain "RBA715"
        @($report.findings.ruleId) | Should -Contain "RBA801"
        @($report.findings.ruleId) | Should -Contain "RBA820"
        @($report.findings.ruleId | Sort-Object -Unique).Count | Should -Be @($report.findings).Count
        ($report.findings | Where-Object { $_.ruleId -eq "RBA500" }).status | Should -Be "NotApplicable"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA411" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA801" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA801" }).evidence.accessRights | Should -Contain "AvailabilityOnly"
        foreach ($ruleId in @("RBA710", "RBA711", "RBA712", "RBA713", "RBA714", "RBA715")) {
            ($report.findings | Where-Object { $_.ruleId -eq $ruleId }).status | Should -Be "NotApplicable"
        }
        ($report.findings | Where-Object { $_.ruleId -eq "RBA710" }).evidence.searchStatus | Should -Be "NotRequested"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA710" }).evidence.subjectMatchCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA711" }).evidence.searchStatus | Should -Be "NotRequested"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA711" }).evidence.subjectMatchCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA711" }).evidence.meetingIdCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA711" }).evidence.eventCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA712" }).evidence.updateCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA713" }).evidence.cancellationCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA714" }).evidence.searchStatus | Should -Be "NotRequested"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA714" }).evidence.subjectMatchCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA715" }).evidence.declineCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA715" }).evidence.horizonDeclineCount | Should -Be 0
    }

    It "summarizes and writes collected RBA log content after a successful collection" {
        $report = Invoke-TestRbaSummary
        $logPath = Get-ChildItem -Path $TestDrive -Filter "RBA-Logs_room_*.txt" |
            Sort-Object -Property LastWriteTime | Select-Object -Last 1

        $report.collectors.RbaLog.status | Should -Be "Success"
        $report.rbaLogSummary.entryCount | Should -Be 2
        $report.rbaLogSummary.acceptedCount | Should -Be 1
        $logPath | Should -Not -BeNullOrEmpty
        $logContent = Get-Content -Path $logPath.FullName -Raw
        $logContent | Should -Match "Action:Accept"
        $logContent | Should -Match "START - HandleEventInternal Automatic Booking is enabled for resource\."
    }

    It "emits delegate-routing and post-processing conditions with minimal evidence" {
        Mock Get-CalendarProcessing {
            $settings = Get-TestCalendarProcessing
            $settings.AllBookInPolicy = $false
            $settings.BookInPolicy = @("allowed@contoso.com")
            $settings.AddNewRequestsTentatively = $false
            $settings.AllRequestOutOfPolicy = $false
            $settings.RequestOutOfPolicy = @("exception@contoso.com")
            $settings.DeleteComments = $true
            $settings
        }

        $report = Invoke-TestRbaSummary

        ($report.findings | Where-Object { $_.ruleId -eq "RBA410" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA412" }).evidence.bookInPolicyCount | Should -Be 1
        ($report.findings | Where-Object { $_.ruleId -eq "RBA421" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA600" }).status | Should -Be "Detected"
    }

    It "does not report no delegates as a fault when all valid requests auto-book" {
        Mock Get-CalendarProcessing {
            $settings = Get-TestCalendarProcessing
            $settings.ResourceDelegates = @()
            $settings.AllBookInPolicy = $true
            $settings.AllRequestOutOfPolicy = $false
            $settings.RequestOutOfPolicy = @()
            $settings
        }

        $report = Invoke-TestRbaSummary

        ($report.findings | Where-Object { $_.ruleId -eq "RBA400" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA400" }).severity | Should -Be "Information"
        ($report.findings | Where-Object { $_.ruleId -in @("RBA401", "RBA402", "RBA403") -and $_.status -eq "Detected" }) | Should -BeNullOrEmpty
    }

    It "reports restrictive booking and post-processing policy consequences" {
        Mock Get-CalendarProcessing {
            $settings = Get-TestCalendarProcessing
            $settings.BookingWindowInDays = 30
            $settings.MaximumDurationInMinutes = 60
            $settings.AllowRecurringMeetings = $false
            $settings.ScheduleOnlyDuringWorkHours = $true
            $settings.AllowConflicts = $true
            $settings.ConflictPercentageAllowed = 25
            $settings.MaximumConflictInstances = 3
            $settings.ProcessExternalMeetingMessages = $false
            $settings.RemovePrivateProperty = $true
            $settings.DeleteSubject = $true
            $settings.AddOrganizerToSubject = $true
            $settings.RemoveCanceledMeetings = $false
            $settings
        }

        $report = Invoke-TestRbaSummary

        ($report.findings | Where-Object { $_.ruleId -eq "RBA302" }).evidence.bookingWindowInDays | Should -Be 30
        ($report.findings | Where-Object { $_.ruleId -eq "RBA303" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA304" }).status | Should -Be "Detected"
        @($report.findings | Where-Object { $_.ruleId -in @("RBA305", "RBA306") -and $_.status -ne "NotApplicable" }) | Should -BeNullOrEmpty
        ($report.findings | Where-Object { $_.ruleId -eq "RBA307" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA308" }).status | Should -Be "Detected"
        @($report.findings | Where-Object { $_.ruleId -in @("RBA309", "RBA310") -and $_.status -ne "NotApplicable" }) | Should -BeNullOrEmpty
        ($report.findings | Where-Object { $_.ruleId -eq "RBA311" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA601" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA602" }).evidence.addOrganizerToSubject | Should -BeTrue
        ($report.findings | Where-Object { $_.ruleId -eq "RBA603" }).evidence.deleteSubject | Should -BeTrue
        ($report.findings | Where-Object { $_.ruleId -eq "RBA604" }).status | Should -Be "Detected"
    }

    It "reports recurring conflict thresholds and the non-enforced horizon behavior" {
        Mock Get-CalendarProcessing {
            $settings = Get-TestCalendarProcessing
            $settings.AllowRecurringMeetings = $true
            $settings.AllowConflicts = $false
            $settings.ConflictPercentageAllowed = 10
            $settings.MaximumConflictInstances = 2
            $settings.EnforceSchedulingHorizon = $false
            $settings
        }

        $report = Invoke-TestRbaSummary

        ($report.findings | Where-Object { $_.ruleId -eq "RBA305" }).status | Should -Be "NotDetected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA306" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA309" }).evidence.conflictPercentageAllowed | Should -Be 10
        ($report.findings | Where-Object { $_.ruleId -eq "RBA310" }).evidence.maximumConflictInstances | Should -Be 2
    }

    It "distinguishes observed recurrence horizon outcomes from configuration" {
        Mock Export-MailboxDiagnosticLogs {
            [PSCustomObject]@{
                MailboxLog = @(
                    "2026-08-28, Entry Action: Message, LogComment: Action:Decline"
                    "2026-08-28, Truncating meeting recurrence end window (endBookingWindowLocal) from X to Y"
                    "2026-08-28, Recurrence ends is past the booking window. Meeting will be declined."
                    "2026-08-28, START - HandleEventInternal Automatic Booking is enabled for resource."
                ) -join "`r`n"
            }
        }

        $report = Invoke-TestRbaSummary

        $report.rbaLogSummary.horizonDeclineCount | Should -Be 1
        $report.rbaLogSummary.recurrenceTruncateCount | Should -Be 1
        ($report.findings | Where-Object { $_.ruleId -eq "RBA704" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA705" }).status | Should -Be "Detected"
    }

    It "collects every retained RBA processing block for meeting IDs found by subject" {
        $meetingIdWithComma = "040000008,00E00074C5A7101A82E007000000004220FC5BAC74D90100000000000000001000000068B165058D1E2E439252F58379D4FE92"
        $meetingId = $meetingIdWithComma -replace ',', ''
        $unrelatedMeetingId = "040000008200E00074C5B7101A82E00800000000FFFFFFFFFFFFFFFF"
        Mock Export-MailboxDiagnosticLogs {
            [PSCustomObject]@{
                MailboxLog = @(
                    "2026-08-22T10:00:03Z, Cancellation processing completed."
                    "MeetingId: $meetingId"
                    "It's a meeting cancellation."
                    "2026-08-22T10:00:00Z, START - HandleEventInternal Automatic Booking is enabled for resource."
                    "2026-08-21T10:00:04Z, END - Sending the acceptance response to organizer."
                    "2026-08-21T10:00:03Z, Entry Action: Message, LogComment: Action:Accept"
                    "2026-08-21T10:00:01Z, Begin ProcessUpdateRequest Goid: $meetingId"
                    "2026-08-21T10:00:00Z, START - HandleEventInternal Automatic Booking is enabled for resource."
                    "2026-08-20T10:00:05Z, END - Sending the acceptance response to organizer."
                    "2026-08-20T10:00:04Z, PostProcessing completed on ItemId."
                    "2026-08-20T10:00:03Z, Entry Action: Message, LogComment: Action:Accept"
                    "2026-08-20T10:00:02Z, Received Request from: Organizer subject Project Falcon"
                    "2026-08-20T10:00:01Z, Begin ProcessRequest Goid: $meetingIdWithComma"
                    "2026-08-20T10:00:00Z, START - HandleEventInternal Automatic Booking is enabled for resource."
                    "2026-08-19T10:00:03Z, Entry Action: Message, LogComment: Action:Decline"
                    "Subject: Different meeting"
                    "2026-08-19T10:00:01Z, Begin ProcessRequest Goid: $unrelatedMeetingId"
                    "2026-08-19T10:00:00Z, START - HandleEventInternal Automatic Booking is enabled for resource."
                ) -join "`r`n"
            }
        }

        $report = Invoke-TestRbaSummary -MeetingSubject "project falcon"

        $report.metadata.privacyMode | Should -Be "TargetedMeeting"
        $report.PSObject.Properties.Name | Should -Not -Contain "fullRbaLog"
        $report.meetingLogSearch.status | Should -Be "Found"
        $report.meetingLogSearch.subjectMatchCount | Should -Be 1
        $report.meetingLogSearch.meetingIds | Should -Contain $meetingId
        $report.meetingLogSearch.eventCount | Should -Be 3
        $report.meetingLogSearch.updateCount | Should -Be 1
        $report.meetingLogSearch.cancellationCount | Should -Be 1
        $report.meetingLogSearch.declineCount | Should -Be 0
        $report.meetingLogSearch.sourceOrder | Should -Be "NewestFirst"
        $report.meetingLogSearch.eventOrder | Should -Be "NewestFirst"
        $report.meetingLogSearch.rawLogChronologicalReadDirection | Should -Be "BottomToTop"
        $report.meetingLogSearch.events[0].cancellationDetected | Should -BeTrue
        $report.meetingLogSearch.events[1].updateDetected | Should -BeTrue
        $initialEvent = $report.meetingLogSearch.events[2]
        $initialEvent.subjectMatched | Should -BeTrue
        $initialEvent.startBoundaryFound | Should -BeTrue
        $initialEvent.boundaryStatus | Should -Be "BetweenExactStartBoundaries"
        $initialEvent.startMarker | Should -Be "2026-08-20T10:00:00Z, START - HandleEventInternal Automatic Booking is enabled for resource."
        $initialEvent.startTimeText.ToUniversalTime().ToString("o") | Should -Be "2026-08-20T10:00:00.0000000Z"
        $initialEvent.eventTimeText | Should -Be $initialEvent.startTimeText
        $initialEvent.rawLogOrder | Should -Be "NewestFirst"
        $initialEvent.chronologicalReadDirection | Should -Be "BottomToTop"
        $initialEvent.rawLog[0] | Should -Be "2026-08-20T10:00:05Z, END - Sending the acceptance response to organizer."
        $initialEvent.rawLog[-1] | Should -Be $initialEvent.startMarker
        @($initialEvent.rawLog).Count | Should -Be 6
        $initialEvent.rawLog | Should -Contain "2026-08-20T10:00:04Z, PostProcessing completed on ItemId."
        $initialEvent.rawLog | Should -Contain "2026-08-20T10:00:01Z, Begin ProcessRequest Goid: $meetingIdWithComma"
        @($report.meetingLogSearch.events.rawLog | Where-Object { $_ -match "Different meeting" }) | Should -BeNullOrEmpty
        @($report.meetingLogSearch.events.meetingIds | Where-Object { $_ -eq $unrelatedMeetingId }) | Should -BeNullOrEmpty
        ($report.findings | Where-Object { $_.ruleId -eq "RBA711" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA712" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA713" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA715" }).status | Should -Be "NotDetected"
    }

    It "reports that a subject is not found without claiming the meeting was never processed" {
        $report = Invoke-TestRbaSummary -MeetingSubject "Missing meeting"

        $report.metadata.privacyMode | Should -Be "TargetedMeeting"
        $report.meetingLogSearch.status | Should -Be "NotFound"
        $report.meetingLogSearch.eventCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA710" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA711" }).status | Should -Be "NotDetected"
    }

    It "keeps Calendar access, booking delegates, and post-processing as separate findings" {
        Mock Get-MailboxFolderPermission {
            @(
                [PSCustomObject]@{
                    User                   = "Default"
                    AccessRights           = @("LimitedDetails")
                    SharingPermissionFlags = @()
                }
                [PSCustomObject]@{
                    User                   = "calendar.owner@contoso.com"
                    AccessRights           = @("Owner")
                    SharingPermissionFlags = @()
                }
            )
        }

        $report = Invoke-TestRbaSummary

        ($report.findings | Where-Object { $_.ruleId -eq "RBA801" }).evidence.accessRights | Should -Contain "LimitedDetails"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA802" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA803" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA804" }).evidence.relatedRuleIds | Should -Contain "RBA602"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA805" }).evidence.relatedRuleIds | Should -Contain "RBA601"
        $report.calendarPermissions.entries.principal | Should -Contain "Default"
        $report.calendarPermissions.entries.principal | Should -Contain "SanitizedIdentity-3"
        $report.calendarPermissions.entries.principal | Should -Not -Contain "calendar.owner@contoso.com"
    }

    It "uses stable sanitized identities across processing and permission sections" {
        Mock Get-CalendarProcessing {
            $settings = Get-TestCalendarProcessing
            $settings.RequestOutOfPolicy = @(" Shared.User@Contoso.com ")
            $settings.BookInPolicy = @("different.user@contoso.com")
            $settings.RequestInPolicy = @("SHARED.USER@CONTOSO.COM")
            $settings.ResourceDelegates = @("shared.user@contoso.com")
            $settings
        }
        Mock Get-MailboxFolderPermission {
            @(
                [PSCustomObject]@{
                    User                   = "Default"
                    AccessRights           = @("AvailabilityOnly")
                    SharingPermissionFlags = @()
                }
                [PSCustomObject]@{
                    User                   = "sHaReD.uSeR@cOnToSo.cOm"
                    AccessRights           = @("Editor")
                    SharingPermissionFlags = @("Delegate")
                }
                [PSCustomObject]@{
                    User                   = "Anonymous"
                    AccessRights           = @("None")
                    SharingPermissionFlags = @()
                }
            )
        }
        Mock Get-MailboxPermission {
            @([PSCustomObject]@{
                    User         = "SHARED.USER@CONTOSO.COM"
                    AccessRights = @("FullAccess")
                    IsInherited  = $false
                    Deny         = $false
                })
        }

        $report = Invoke-TestRbaSummary

        $sharedIdentity = @($report.calendarProcessing.requestOutOfPolicy)[0]
        $differentIdentity = @($report.calendarProcessing.bookInPolicy)[0]
        $sharedIdentity | Should -Match "^SanitizedIdentity-\d+$"
        $differentIdentity | Should -Match "^SanitizedIdentity-\d+$"
        $differentIdentity | Should -Not -Be $sharedIdentity
        @($report.calendarProcessing.requestInPolicy)[0] | Should -Be $sharedIdentity
        @($report.calendarProcessing.resourceDelegates)[0] | Should -Be $sharedIdentity
        ($report.calendarPermissions.entries | Where-Object { $_.principal -like "SanitizedIdentity-*" }).principal | Should -Be $sharedIdentity
        @($report.mailboxPermissions.grantees)[0] | Should -Be $sharedIdentity
        $report.calendarPermissions.entries.principal | Should -Contain "Default"
        $report.calendarPermissions.entries.principal | Should -Contain "Anonymous"
        $report.PSObject.Properties.Name | Should -Not -Contain "SanitizedIdentityMap"
    }

    It "assigns separate placeholders when an identity has no stable key" {
        Mock Get-CalendarProcessing {
            $settings = Get-TestCalendarProcessing
            $settings.RequestOutOfPolicy = @($null, "")
            $settings
        }

        $report = Invoke-TestRbaSummary

        $report.calendarProcessing.requestOutOfPolicy.Count | Should -Be 2
        $report.calendarProcessing.requestOutOfPolicy[0] | Should -Match "^SanitizedIdentity-\d+$"
        $report.calendarProcessing.requestOutOfPolicy[1] | Should -Match "^SanitizedIdentity-\d+$"
        $report.calendarProcessing.requestOutOfPolicy[0] | Should -Not -Be $report.calendarProcessing.requestOutOfPolicy[1]
    }

    It "preserves the target identity in CalendarProcessing recipient wells" {
        Mock Get-CalendarProcessing {
            $settings = Get-TestCalendarProcessing
            $settings.RequestOutOfPolicy = @("ROOM@CONTOSO.COM")
            $settings
        }

        $report = Invoke-TestRbaSummary

        $report.calendarProcessing.requestOutOfPolicy | Should -Contain "ROOM@CONTOSO.COM"
    }

    It "matches a resource delegate through its resolved SMTP identity" {
        Mock Get-CalendarProcessing {
            $settings = Get-TestCalendarProcessing
            $settings.ResourceDelegates = @("Delegate Directory Identity")
            $settings
        }
        Mock Get-Recipient {
            [PSCustomObject]@{
                DisplayName        = "Resolved delegate"
                PrimarySmtpAddress = "delegate@contoso.com"
            }
        }

        $report = Invoke-TestRbaSummary

        ($report.findings | Where-Object { $_.ruleId -eq "RBA803" }).status | Should -Be "NotDetected"
    }

    It "reports explicit Full Access without claiming direct Calendar editing" {
        Mock Get-MailboxPermission {
            @(
                [PSCustomObject]@{
                    User         = "NT AUTHORITY\SELF"
                    AccessRights = @("FullAccess")
                    IsInherited  = $false
                    Deny         = $false
                }
                [PSCustomObject]@{
                    User         = "operator@contoso.com"
                    AccessRights = @("FullAccess")
                    IsInherited  = $false
                    Deny         = $false
                }
            )
        }

        $report = Invoke-TestRbaSummary

        ($report.findings | Where-Object { $_.ruleId -eq "RBA820" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA820" }).evidence.explicitFullAccessCount | Should -Be 1
        $report.mailboxPermissions.grantees | Should -Contain "SanitizedIdentity-3"
        $report.mailboxPermissions.grantees | Should -Not -Contain "operator@contoso.com"
        @($report.findings.ruleId) | Should -Not -Contain "RBA830"
    }

    It "marks permission findings not evaluated when permission collection fails" {
        Mock Get-MailboxFolderPermission { throw "Calendar permissions unavailable" }
        Mock Get-MailboxPermission { throw "Mailbox permissions unavailable" }

        $report = Invoke-TestRbaSummary

        $report.metadata.collectionStatus | Should -Be "Partial"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA006" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA007" }).status | Should -Be "Detected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA801" }).status | Should -Be "NotEvaluated"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA820" }).status | Should -Be "NotEvaluated"
    }

    It "keeps Calendar permissions successful when CalendarProcessing fails" {
        Mock Get-CalendarProcessing { throw "Calendar processing unavailable" }

        $report = Invoke-TestRbaSummary

        $report.metadata.collectionStatus | Should -Be "Partial"
        $report.collectors.CalendarProcessing.status | Should -Be "Failed"
        $report.collectors.CalendarFolderPermissions.status | Should -Be "Success"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA006" }).status | Should -Be "NotDetected"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA803" }).status | Should -Be "NotEvaluated"
        ($report.findings | Where-Object { $_.ruleId -eq "RBA803" }).evidence.configuredDelegateCount | Should -Be 0
        ($report.findings | Where-Object { $_.ruleId -eq "RBA803" }).evidence.unmatchedIdentityCount | Should -Be 0
        Assert-MockCalled -CommandName Get-Mailbox -Exactly 1
        Assert-MockCalled -CommandName Get-Place -Exactly 1
        Assert-MockCalled -CommandName Get-InboxRule -Exactly 1
        Assert-MockCalled -CommandName Get-CalendarProcessing -Exactly 1
        Assert-MockCalled -CommandName Get-MailboxFolderPermission -Exactly 1
        Assert-MockCalled -CommandName Get-MailboxPermission -Exactly 1
        Assert-MockCalled -CommandName Export-MailboxDiagnosticLogs -Exactly 1
    }

    It "includes full-fidelity identities, RBA log, and transcript only when requested" {
        Mock Get-MailboxPermission {
            @([PSCustomObject]@{
                    User         = "operator@contoso.com"
                    AccessRights = @("FullAccess")
                    IsInherited  = $false
                    Deny         = $false
                })
        }

        $report = Invoke-TestRbaSummary -IncludeSensitiveData

        $report.metadata.privacyMode | Should -Be "Full"
        $report.calendarProcessing.resourceDelegates | Should -Contain "delegate@contoso.com"
        $report.calendarProcessing.additionalResponse | Should -Be "Contact delegate@contoso.com"
        $report.calendarPermissions.entries.principal | Should -Contain "delegate@contoso.com"
        $report.mailboxPermissions.grantees | Should -Contain "operator@contoso.com"
        $report.mailbox.emailAddresses | Should -Contain "smtp:old-room@contoso.com"
        $report.mailbox.exchangeGuid | Should -Be "11111111-1111-1111-1111-111111111111"
        $report.mailbox.externalDirectoryId | Should -Be "22222222-2222-2222-2222-222222222222"
        @($report.fullRbaLog).Count | Should -BeGreaterThan 0
        $report.transcript | Should -Not -BeNullOrEmpty
    }

    It "writes full-fidelity output without room lists when Place collection fails" {
        Mock Get-Place { throw "Place unavailable" }

        $report = Invoke-TestRbaSummary -IncludeSensitiveData

        $report.metadata.privacyMode | Should -Be "Full"
        $report.metadata.collectionStatus | Should -Be "Partial"
        $report.collectors.Place.status | Should -Be "Failed"
        $report.place | Should -BeNullOrEmpty
        $report.evaluationErrors | Should -BeNullOrEmpty
    }
}

Describe "RBA log processing block extraction" {
    BeforeEach {
        Initialize-StandardMocks
        Mock Get-Mailbox {
            [PSCustomObject]@{
                Identity             = "room@contoso.com"
                PrimarySmtpAddress   = "room@contoso.com"
                EmailAddresses       = @("SMTP:room@contoso.com")
                RecipientTypeDetails = "RoomMailbox"
                ResourceType         = "Room"
            }
        }
    }

    It "uses only the exact RBA START marker as a boundary" {
        Mock Export-MailboxDiagnosticLogs {
            [PSCustomObject]@{
                MailboxLog = @(
                    "2026-08-28T10:00:03Z, END - Sending the acceptance response to organizer."
                    "2026-08-28T10:00:02Z, START - Retry checkpoint"
                    "2026-08-28T10:00:01Z, Subject: Boundary test"
                    "2026-08-28T10:00:00Z, START - HandleEventInternal Automatic Booking is enabled for resource."
                    "2026-08-27T10:00:02Z, Older retained result"
                    "2026-08-27T10:00:01Z, START - Generic older marker"
                ) -join "`r`n"
            }
        }

        $report = Invoke-TestRbaSummary -MeetingSubject "Boundary test"
        $report.meetingLogSearch.eventCount | Should -Be 1
        $report.meetingLogSearch.events[0].startBoundaryFound | Should -BeTrue
        $report.meetingLogSearch.events[0].rawLog | Should -Contain "2026-08-28T10:00:02Z, START - Retry checkpoint"
        $report.meetingLogSearch.events[0].rawLog.Count | Should -Be 4
        $report.meetingLogSearch.events[0].rawLog | Should -Not -Contain "2026-08-27T10:00:02Z, Older retained result"
    }

    It "retains a log with no exact START boundary as one incomplete block" {
        Mock Export-MailboxDiagnosticLogs {
            [PSCustomObject]@{
                MailboxLog = @(
                    "2026-08-28T10:00:04Z, Action:Accept"
                    "2026-08-28T10:00:03Z, Subject: Missing boundary test"
                    "2026-08-28T10:00:02Z, Begin ProcessRequest Goid: 040000008,00E00074C5A7101A82E007000000004220FC5BAC74D90100000000000000001000000068B165058D1E2E439252F58379D4FE92"
                    "2026-08-28T10:00:01Z, START - Generic marker"
                ) -join "`r`n"
            }
        }

        $report = Invoke-TestRbaSummary -MeetingSubject "Missing boundary test"
        $report.meetingLogSearch.eventCount | Should -Be 1
        $report.meetingLogSearch.events[0].startBoundaryFound | Should -BeFalse
        $report.meetingLogSearch.events[0].boundaryStatus | Should -Be "MissingStartBoundary"
        $report.meetingLogSearch.events[0].startMarker | Should -BeNullOrEmpty
        $report.meetingLogSearch.events[0].rawLog.Count | Should -Be 4
        $report.meetingLogSearch.events[0].meetingIds | Should -Contain "04000000800E00074C5A7101A82E007000000004220FC5BAC74D90100000000000000001000000068B165058D1E2E439252F58379D4FE92"
    }
}

Describe "EXO RBA troubleshooting skill package" {
    It "combines the skill, package metadata, and all rules into one Markdown file" {
        . $Script:packageHelperPath
        $destinationPath = Join-Path -Path $TestDrive -ChildPath "EXO-RBA-Troubleshooting-SKILL.md"

        New-RbaTroubleshootingSkillFile `
            -SkillPath (Join-Path -Path $Script:skillPath -ChildPath "SKILL.md") `
            -TsgRulesPath (Join-Path -Path $Script:skillPath -ChildPath "TSG-Rules.md") `
            -RulesPath (Join-Path -Path $Script:skillPath -ChildPath "RBA-Rules.md") `
            -ManifestPath (Join-Path -Path $Script:skillPath -ChildPath "manifest.json") `
            -DestinationPath $destinationPath

        $content = Get-Content -Path $destinationPath -Raw
        $content | Should -Match "^---\r?\nname: exo-rba-troubleshooting\r?\n"
        $content | Should -Match "Skill version: ``0\.1\.0-preview``"
        $content | Should -Match "TSG rules version: ``0\.1\.0-preview``"
        $content | Should -Match "Canonical download: https://github.com/microsoft/CSS-Exchange/releases/latest/download/EXO-RBA-Troubleshooting-SKILL\.md"
        $content | Should -Match "## TSG core rules"
        $content | Should -Match "### TSG002 — No fabrication"
        $content | Should -Match "### TSG405 — Escalate instead of guessing"
        $content | Should -Match "## RBA finding rules"
        $content | Should -Match "## Explicit out-of-scope routing"
        $content | Should -Match "## Lifecycle and item propagation triage"
        $content | Should -Match "\| Soft-deleted room mailbox \|"
        $content | Should -Match "\| Duplicate or stale room object \|"
        $content | Should -Match "\| Room rename or SMTP change \|"
        $content | Should -Match "\| Former organizer reservations \|"
        $content | Should -Match "\| Stale room calendar items \|"
        $content | Should -Match "\| Cancellation or update not reflected \|"
        $content | Should -Match "\| Orphaned recurring meetings \|"
        $content | Should -Match "\| Teams Rooms device health \|"
        $content | Should -Match "\| Microsoft Places and PlaceV3 \|"
        $content | Should -Match "\| Graph and Power Automate \|"
        $content | Should -Match "\| Non-resource calendar sharing and delegation \|"
        $content | Should -Match "\| Generic calendar-event repair \|"
        $content | Should -Match "\| Copilot Rebook or automated room booking \|"
        $content | Should -Match "\| Service availability or processing delay \|"
        $content | Should -Match "\| Reporting and audit \|"
        $content | Should -Match "A supplied RBA JSON report does not make an otherwise out-of-scope question an RBA question"
        $content | Should -Match "\| RBA001 \|"
        $content | Should -Match "\| RBA101 \|"
        $content | Should -Match "\| RBA102 \|"
        $content | Should -Match "\| RBA302 \|"
        $content | Should -Match "\| RBA311 \|"
        $content | Should -Match "\| RBA604 \|"
        $content | Should -Match "\| RBA703 \|"
        $content | Should -Match "\| RBA705 \|"
        $content | Should -Match "\| RBA710 \|"
        $content | Should -Match "\| RBA715 \|"
        $content | Should -Match "## Targeted meeting log analysis"
        $content | Should -Match "START - HandleEventInternal Automatic Booking is enabled for resource\."
        $content | Should -Match "newest-first"
        $content | Should -Match "bottom-up"
        $content | Should -Match "single-threaded"
        $content | Should -Match "## Future decline evidence contract"
        $content | Should -Match "\| RBA801 \|"
        $content | Should -Match "RBA830"
        $content | Should -Not -Match "\[TSG-Rules\.md\]\(TSG-Rules\.md\)"
        $content | Should -Not -Match "\[RBA-Rules\.md\]\(RBA-Rules\.md\)"
    }
}
