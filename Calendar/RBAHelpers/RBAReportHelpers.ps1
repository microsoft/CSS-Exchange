# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-RbaReportErrorMessage {
    param(
        [AllowNull()]
        [string]$Message
    )

    if ($IncludeSensitiveData -or [string]::IsNullOrWhiteSpace($Message)) {
        return $Message
    }
    return "Error details omitted in sanitized mode."
}

function Get-RbaFindings {
    $findings = [System.Collections.Generic.List[object]]::new()
    $mailboxAvailable = $script:collectorStatuses["Mailbox"].status -eq "Success"
    $placeAvailable = $script:collectorStatuses["Place"].status -eq "Success"
    $rulesAvailable = $script:collectorStatuses["InboxRules"].status -eq "Success"
    $settingsAvailable = $script:collectorStatuses["CalendarProcessing"].status -eq "Success"
    $logAvailable = $script:collectorStatuses["RbaLog"].status -eq "Success"
    $calendarPermissionsAvailable = $script:collectorStatuses["CalendarFolderPermissions"].status -eq "Success"
    $mailboxPermissionsAvailable = $script:collectorStatuses["MailboxPermissions"].status -eq "Success"

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA001" -Severity Error `
        -Status $(if ($mailboxAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Mailbox evidence unavailable" `
        -Evidence @{ error = Get-RbaReportErrorMessage -Message $script:collectorStatuses["Mailbox"].error }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA002" -Severity Error `
        -Status $(if ($placeAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Place evidence unavailable" -Evidence (Get-RbaReportErrorMessage -Message $script:collectorStatuses["Place"].error)

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA003" -Severity Error `
        -Status $(if ($rulesAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Inbox rule evidence unavailable" -Evidence (Get-RbaReportErrorMessage -Message $script:collectorStatuses["InboxRules"].error)

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA004" -Severity Error `
        -Status $(if ($settingsAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Calendar processing evidence unavailable" -Evidence (Get-RbaReportErrorMessage -Message $script:collectorStatuses["CalendarProcessing"].error)

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA005" -Severity Warning `
        -Status $(if ($logAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "RBA log evidence unavailable" -Evidence (Get-RbaReportErrorMessage -Message $script:collectorStatuses["RbaLog"].error)

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA006" -Severity Warning `
        -Status $(if ($calendarPermissionsAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Calendar folder permission evidence unavailable" -Evidence (Get-RbaReportErrorMessage -Message $script:collectorStatuses["CalendarFolderPermissions"].error)

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA007" -Severity Warning `
        -Status $(if ($mailboxPermissionsAvailable) { "NotDetected" } else { "Detected" }) `
        -Title "Mailbox permission evidence unavailable" -Evidence (Get-RbaReportErrorMessage -Message $script:collectorStatuses["MailboxPermissions"].error)

    $mailboxIsSoftDeleted = $mailboxAvailable -and $script:MailboxObjectState -eq "SoftDeleted"
    $invalidMailboxType = $mailboxAvailable -and -not $mailboxIsSoftDeleted -and
    $script:Mailbox.RecipientTypeDetails -notin @("RoomMailbox", "EquipmentMailbox")
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA100" -Severity Critical `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif ($mailboxIsSoftDeleted) { "NotApplicable" } elseif ($invalidMailboxType) { "Detected" } else { "NotDetected" }) `
        -Title "Mailbox type is not supported by RBA" -Evidence $script:Mailbox.RecipientTypeDetails

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA101" -Severity Critical `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif ($mailboxIsSoftDeleted) { "Detected" } else { "NotDetected" }) `
        -Title "Resource mailbox is soft-deleted" `
        -Evidence @{ objectState = $script:MailboxObjectState; recipientTypeDetails = $script:Mailbox.RecipientTypeDetails }

    $mailboxIdentitySummary = Get-RbaMailboxIdentitySummaryObject
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA102" -Severity Information `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif ($mailboxIdentitySummary.inputIdentityMatch -eq "ProxyAddress") { "Detected" } else { "NotDetected" }) `
        -Title "Input identity resolved through a proxy address" `
        -Evidence @{ inputIdentityMatch = $mailboxIdentitySummary.inputIdentityMatch; primarySmtpAddress = $mailboxIdentitySummary.primarySmtpAddress }

    $delegateRules = @($script:InboxRules | Where-Object { $_.Name -like "Delegate Rule*" })
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA200" -Severity Critical `
        -Status $(if (-not $rulesAvailable) { "NotEvaluated" } elseif ($delegateRules.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Delegate inbox rule can block RBA" -Evidence @{ count = $delegateRules.Count }

    $redactedRules = @($script:InboxRules | Where-Object { $_.Name -like "REDACTED-*" })
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA201" -Severity Warning `
        -Status $(if (-not $rulesAvailable) { "NotEvaluated" } elseif ($redactedRules.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Inbox rule visibility is redacted" -Evidence @{ count = $redactedRules.Count }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA300" -Severity Critical `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.AutomateProcessing -ne "AutoAccept") { "Detected" } else { "NotDetected" }) `
        -Title "AutomateProcessing is not AutoAccept" -Evidence $RbaSettings.AutomateProcessing

    $noProcessingRoutes = $settingsAvailable -and $RbaSettings.RequestOutOfPolicy.Count -eq 0 -and
    $RbaSettings.AllRequestOutOfPolicy -eq $false -and $RbaSettings.BookInPolicy.Count -eq 0 -and
    $RbaSettings.AllBookInPolicy -eq $false -and $RbaSettings.RequestInPolicy.Count -eq 0 -and
    $RbaSettings.AllRequestInPolicy -eq $false
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA301" -Severity Critical `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($noProcessingRoutes) { "Detected" } else { "NotDetected" }) `
        -Title "RBA has no configured processing route" -Evidence $noProcessingRoutes

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA302" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } else { "Detected" }) `
        -Title "A resource booking window is configured" `
        -Evidence @{ bookingWindowInDays = $RbaSettings.BookingWindowInDays; allowRecurringMeetings = $RbaSettings.AllowRecurringMeetings; enforceSchedulingHorizon = $RbaSettings.EnforceSchedulingHorizon }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA303" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.MaximumDurationInMinutes -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting duration is limited" `
        -Evidence @{ maximumDurationInMinutes = $RbaSettings.MaximumDurationInMinutes }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA304" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.AllowRecurringMeetings) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring meetings are disabled" `
        -Evidence @{ allowRecurringMeetings = $RbaSettings.AllowRecurringMeetings }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA305" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.AllowRecurringMeetings) { "NotApplicable" } elseif ($RbaSettings.EnforceSchedulingHorizon) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring series beyond the booking window are declined" `
        -Evidence @{ enforceSchedulingHorizon = $RbaSettings.EnforceSchedulingHorizon; bookingWindowInDays = $RbaSettings.BookingWindowInDays }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA306" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.AllowRecurringMeetings) { "NotApplicable" } elseif (-not $RbaSettings.EnforceSchedulingHorizon) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring series are truncated at the booking window" `
        -Evidence @{ enforceSchedulingHorizon = $RbaSettings.EnforceSchedulingHorizon; bookingWindowInDays = $RbaSettings.BookingWindowInDays }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA307" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.ScheduleOnlyDuringWorkHours) { "Detected" } else { "NotDetected" }) `
        -Title "Bookings are restricted to resource work hours" `
        -Evidence @{ scheduleOnlyDuringWorkHours = $RbaSettings.ScheduleOnlyDuringWorkHours }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA308" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.AllowConflicts) { "Detected" } else { "NotDetected" }) `
        -Title "Conflicting requests are allowed" `
        -Evidence @{ allowConflicts = $RbaSettings.AllowConflicts; conflictPercentageAllowed = $RbaSettings.ConflictPercentageAllowed; maximumConflictInstances = $RbaSettings.MaximumConflictInstances }

    $recurringConflictThresholdsApply = $settingsAvailable -and $RbaSettings.AllowRecurringMeetings -and
    -not $RbaSettings.AllowConflicts
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA309" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $recurringConflictThresholdsApply) { "NotApplicable" } elseif ($RbaSettings.ConflictPercentageAllowed -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "A recurring-series conflict percentage is allowed" `
        -Evidence @{ allowConflicts = $RbaSettings.AllowConflicts; allowRecurringMeetings = $RbaSettings.AllowRecurringMeetings; conflictPercentageAllowed = $RbaSettings.ConflictPercentageAllowed }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA310" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $recurringConflictThresholdsApply) { "NotApplicable" } elseif ($RbaSettings.MaximumConflictInstances -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "A recurring-series conflict count is allowed" `
        -Evidence @{ allowConflicts = $RbaSettings.AllowConflicts; allowRecurringMeetings = $RbaSettings.AllowRecurringMeetings; maximumConflictInstances = $RbaSettings.MaximumConflictInstances }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA311" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.ProcessExternalMeetingMessages) { "Detected" } else { "NotDetected" }) `
        -Title "External meeting messages are not processed" `
        -Evidence @{ processExternalMeetingMessages = $RbaSettings.ProcessExternalMeetingMessages }

    $isWorkspace = $mailboxAvailable -and $script:Mailbox.ResourceType -eq "Workspace"
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA500" -Severity Error `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif (-not $isWorkspace) { "NotApplicable" } elseif (-not $placeAvailable) { "NotEvaluated" } elseif ([string]::IsNullOrEmpty($script:Place.Capacity)) { "Detected" } else { "NotDetected" }) `
        -Title "Workspace capacity is missing" -Evidence @{ capacity = $script:Place.Capacity }

    $workspaceSettingsInvalid = $isWorkspace -and $settingsAvailable -and
    ($RbaSettings.EnforceCapacity -ne $true -or $RbaSettings.AllowConflicts -ne $true)
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA501" -Severity Error `
        -Status $(if (-not $mailboxAvailable) { "NotEvaluated" } elseif (-not $isWorkspace) { "NotApplicable" } elseif (-not $settingsAvailable) { "NotEvaluated" } elseif ($workspaceSettingsInvalid) { "Detected" } else { "NotDetected" }) `
        -Title "Workspace calendar settings are incomplete" `
        -Evidence @{ enforceCapacity = $RbaSettings.EnforceCapacity; allowConflicts = $RbaSettings.AllowConflicts }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA510" -Severity Warning `
        -Status $(if (-not $placeAvailable) { "NotEvaluated" } elseif ([string]::IsNullOrEmpty($script:Place.Localities)) { "Detected" } else { "NotDetected" }) `
        -Title "Resource is not in a room list" -Evidence @{ roomListCount = @($script:Place.Localities).Count }

    $missingPlaceProperties = if ($placeAvailable) {
        @(@("City", "Floor", "Capacity") | Where-Object { [string]::IsNullOrEmpty($script:Place.$_) })
    } else { @() }
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA511" -Severity Warning `
        -Status $(if (-not $placeAvailable) { "NotEvaluated" } elseif ($missingPlaceProperties.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Room finder properties are missing" -Evidence @{ properties = $missingPlaceProperties }

    $delegateCount = @($RbaSettings.ResourceDelegates).Count
    $requestOutOfPolicyCount = @($RbaSettings.RequestOutOfPolicy).Count
    $bookInPolicyCount = @($RbaSettings.BookInPolicy).Count
    $noDelegates = $settingsAvailable -and $delegateCount -eq 0
    $noDelegateRouteRequired = $noDelegates -and $RbaSettings.AllBookInPolicy -eq $true -and
    $RbaSettings.AllRequestOutOfPolicy -eq $false -and $requestOutOfPolicyCount -eq 0
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA400" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($noDelegateRouteRequired) { "Detected" } else { "NotApplicable" }) `
        -Title "No delegates are required by the configured request routes" `
        -Evidence @{ delegateCount = $delegateCount; allBookInPolicy = $RbaSettings.AllBookInPolicy; allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; requestOutOfPolicyCount = $requestOutOfPolicyCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA401" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $noDelegates) { "NotApplicable" } elseif ($RbaSettings.ForwardRequestsToDelegates -and -not $RbaSettings.AllBookInPolicy) { "Detected" } else { "NotDetected" }) `
        -Title "Forwarding is enabled without delegates for in-policy requests" `
        -Evidence @{ delegateCount = $delegateCount; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; allBookInPolicy = $RbaSettings.AllBookInPolicy }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA402" -Severity Error `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $noDelegates) { "NotApplicable" } elseif ($requestOutOfPolicyCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Out-of-policy requesters are configured without delegates" -Evidence @{ requesterCount = $requestOutOfPolicyCount; delegateCount = $delegateCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA403" -Severity Error `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $noDelegates) { "NotApplicable" } elseif ($RbaSettings.AllRequestOutOfPolicy) { "Detected" } else { "NotDetected" }) `
        -Title "All out-of-policy requests are enabled without delegates" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; delegateCount = $delegateCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA600" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.DeleteComments) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting body deletion can remove Teams information" -Evidence $RbaSettings.DeleteComments

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA601" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.RemovePrivateProperty) { "Detected" } else { "NotDetected" }) `
        -Title "The private flag is cleared from incoming meetings" `
        -Evidence @{ removePrivateProperty = $RbaSettings.RemovePrivateProperty }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA602" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.DeleteSubject) { "Detected" } else { "NotDetected" }) `
        -Title "The original meeting subject is removed" `
        -Evidence @{ deleteSubject = $RbaSettings.DeleteSubject; addOrganizerToSubject = $RbaSettings.AddOrganizerToSubject }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA603" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($RbaSettings.AddOrganizerToSubject) { "Detected" } else { "NotDetected" }) `
        -Title "The organizer name replaces the meeting subject" `
        -Evidence @{ addOrganizerToSubject = $RbaSettings.AddOrganizerToSubject; deleteSubject = $RbaSettings.DeleteSubject }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA604" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.RemoveCanceledMeetings) { "Detected" } else { "NotDetected" }) `
        -Title "Canceled meetings are retained on the resource calendar" `
        -Evidence @{ removeCanceledMeetings = $RbaSettings.RemoveCanceledMeetings }

    $skippedExternalCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Skipping processing because user settings for processing external items is false.").Count
    } else { 0 }
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA700" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($skippedExternalCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "External meeting requests were skipped" -Evidence @{ count = $skippedExternalCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA410" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($delegateCount -eq 0) { "NotApplicable" } elseif (-not $RbaSettings.AddNewRequestsTentatively) { "Detected" } else { "NotDetected" }) `
        -Title "New requests are not added tentatively for delegate review" `
        -Evidence @{ addNewRequestsTentatively = $RbaSettings.AddNewRequestsTentatively; delegateCount = $delegateCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA411" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($delegateCount -eq 0 -or -not $RbaSettings.ForwardRequestsToDelegates) { "NotApplicable" } elseif ($RbaSettings.AllBookInPolicy) { "Detected" } else { "NotDetected" }) `
        -Title "All in-policy requests auto-book without delegate review" `
        -Evidence @{ allBookInPolicy = $RbaSettings.AllBookInPolicy; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA412" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif ($delegateCount -eq 0 -or -not $RbaSettings.ForwardRequestsToDelegates -or $RbaSettings.AllBookInPolicy) { "NotApplicable" } elseif ($bookInPolicyCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "BookInPolicy users auto-book without delegate review" `
        -Evidence @{ bookInPolicyCount = $bookInPolicyCount; allBookInPolicy = $RbaSettings.AllBookInPolicy; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    $delegateRoutingApplies = $settingsAvailable -and $delegateCount -gt 0 -and $RbaSettings.ForwardRequestsToDelegates
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA420" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $delegateRoutingApplies) { "NotApplicable" } elseif (-not $RbaSettings.AllRequestOutOfPolicy -and $requestOutOfPolicyCount -eq 0) { "Detected" } else { "NotDetected" }) `
        -Title "No out-of-policy requests can be routed to delegates" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; requestOutOfPolicyCount = $requestOutOfPolicyCount; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA421" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $delegateRoutingApplies -or $RbaSettings.AllRequestOutOfPolicy) { "NotApplicable" } elseif ($requestOutOfPolicyCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Out-of-policy delegate referrals are limited to listed requesters" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; requestOutOfPolicyCount = $requestOutOfPolicyCount; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA422" -Severity Information `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $delegateRoutingApplies) { "NotApplicable" } elseif ($RbaSettings.AllRequestOutOfPolicy) { "Detected" } else { "NotDetected" }) `
        -Title "All users can submit out-of-policy requests for delegate review" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; forwardRequestsToDelegates = $RbaSettings.ForwardRequestsToDelegates; delegateCount = $delegateCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA423" -Severity Warning `
        -Status $(if (-not $settingsAvailable) { "NotEvaluated" } elseif (-not $RbaSettings.AllRequestOutOfPolicy) { "NotApplicable" } elseif ($requestOutOfPolicyCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "AllRequestOutOfPolicy overrides the requester list" `
        -Evidence @{ allRequestOutOfPolicy = $RbaSettings.AllRequestOutOfPolicy; requestOutOfPolicyCount = $requestOutOfPolicyCount }

    $logEntryCount = @($script:RBALog).Count
    $processedActionCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Action:Accept|Action:Decline|Action:Tentative").Count
    } else { 0 }
    $updatedCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Begin ProcessUpdateRequest").Count
    } else { 0 }
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA701" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($logEntryCount -le 1) { "Detected" } else { "NotDetected" }) `
        -Title "No usable RBA log history was found" -Evidence @{ entryCount = $logEntryCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA702" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($logEntryCount -le 1) { "NotApplicable" } elseif ($processedActionCount -eq 0) { "Detected" } else { "NotDetected" }) `
        -Title "No meeting actions were found in the RBA log" `
        -Evidence @{ entryCount = $logEntryCount; processedActionCount = $processedActionCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA703" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($logEntryCount -le 1) { "NotApplicable" } elseif ($updatedCount -eq 0) { "Detected" } else { "NotDetected" }) `
        -Title "No meeting updates were found in the RBA log" `
        -Evidence @{ entryCount = $logEntryCount; updatedCount = $updatedCount }

    $recurrenceHorizonDeclineCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Recurrence ends is past the booking window. Meeting will be declined.").Count
    } else { 0 }
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA704" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($recurrenceHorizonDeclineCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring requests exceeded the booking window and were declined" `
        -Evidence @{ count = $recurrenceHorizonDeclineCount }

    $recurrenceTruncationCount = if ($logAvailable) {
        @($script:RBALog | Select-String -Pattern "Truncating meeting recurrence end window").Count
    } else { 0 }
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA705" -Severity Warning `
        -Status $(if (-not $logAvailable) { "NotEvaluated" } elseif ($recurrenceTruncationCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Recurring requests were truncated at the booking window" `
        -Evidence @{ count = $recurrenceTruncationCount }

    $meetingSearchRequested = -not [string]::IsNullOrWhiteSpace($Subject) -or -not [string]::IsNullOrWhiteSpace($MeetingId)
    $meetingSearchStatus = $script:MeetingLogSearch.status
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA710" -Severity Warning `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($meetingSearchStatus -eq "NotFound") { "Detected" } else { "NotDetected" }) `
        -Title "Requested meeting was not found in the retained RBA log" `
        -Evidence @{ searchStatus = $meetingSearchStatus; subjectMatchCount = $script:MeetingLogSearch.subjectMatchCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA711" -Severity Information `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($meetingSearchStatus -in @("Found", "FoundWithoutMeetingId")) { "Detected" } else { "NotDetected" }) `
        -Title "Requested meeting was found in the retained RBA log" `
        -Evidence @{ searchStatus = $meetingSearchStatus; subjectMatchCount = $script:MeetingLogSearch.subjectMatchCount; meetingIdCount = @($script:MeetingLogSearch.meetingIds).Count; eventCount = $script:MeetingLogSearch.eventCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA712" -Severity Information `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($script:MeetingLogSearch.updateCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting updates were found in targeted RBA log events" `
        -Evidence @{ updateCount = $script:MeetingLogSearch.updateCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA713" -Severity Information `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($script:MeetingLogSearch.cancellationCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Meeting cancellations were found in targeted RBA log events" `
        -Evidence @{ cancellationCount = $script:MeetingLogSearch.cancellationCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA714" -Severity Warning `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($meetingSearchStatus -eq "FoundWithoutMeetingId") { "Detected" } else { "NotDetected" }) `
        -Title "Meeting subject matched but no meeting ID was extracted" `
        -Evidence @{ searchStatus = $meetingSearchStatus; subjectMatchCount = $script:MeetingLogSearch.subjectMatchCount }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA715" -Severity Information `
        -Status $(if (-not $meetingSearchRequested) { "NotApplicable" } elseif (-not $logAvailable) { "NotEvaluated" } elseif ($script:MeetingLogSearch.declineCount -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Decline actions were found in targeted RBA log events" `
        -Evidence @{ declineCount = $script:MeetingLogSearch.declineCount; horizonDeclineCount = $script:MeetingLogSearch.horizonDeclineCount }

    $defaultCalendarPermission = @($script:CalendarFolderPermissions | Where-Object {
            (Get-RbaPermissionIdentity -PermissionUser $_.User) -eq "default"
        } | Select-Object -First 1)
    $defaultAccessRights = if ($defaultCalendarPermission.Count -gt 0) {
        @($defaultCalendarPermission[0].AccessRights | ForEach-Object { [string]$_ })
    } else { @() }
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA801" -Severity Information `
        -Status $(if (-not $calendarPermissionsAvailable) { "NotEvaluated" } else { "Detected" }) `
        -Title "Default Calendar folder visibility" `
        -Evidence @{ present = $defaultCalendarPermission.Count -gt 0; accessRights = $defaultAccessRights }

    $ownerPermissions = @($script:CalendarFolderPermissions | Where-Object {
            @($_.AccessRights | ForEach-Object { [string]$_ }) -contains "Owner"
        })
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA802" -Severity Warning `
        -Status $(if (-not $calendarPermissionsAvailable) { "NotEvaluated" } elseif ($ownerPermissions.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Owner access is assigned on the resource Calendar folder" `
        -Evidence @{ ownerPermissionCount = $ownerPermissions.Count }

    $directCalendarEditorIdentities = @($script:CalendarFolderPermissions | Where-Object {
            $rights = @($_.AccessRights | ForEach-Object { [string]$_ })
            $rights -contains "Editor" -or $rights -contains "Owner"
        } | ForEach-Object { Get-RbaPermissionIdentity -PermissionUser $_.User })
    $configuredDelegateCount = if ($settingsAvailable) {
        @($script:RbaSettings.ResourceDelegates).Count
    } else { 0 }
    $delegatesWithoutDirectCalendarAccess = if ($settingsAvailable -and $calendarPermissionsAvailable -and
        $script:ResourceDelegateIdentitySetsAvailable) {
        @($script:ResourceDelegateIdentitySets | Where-Object {
                @($_.aliases | Where-Object { $_ -in $directCalendarEditorIdentities }).Count -eq 0
            })
    } else { @() }
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA803" -Severity Warning `
        -Status $(if (-not $settingsAvailable -or -not $calendarPermissionsAvailable -or -not $script:ResourceDelegateIdentitySetsAvailable) { "NotEvaluated" } elseif ($configuredDelegateCount -eq 0) { "NotApplicable" } elseif ($delegatesWithoutDirectCalendarAccess.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "A resource delegate has no matching direct Calendar Editor permission" `
        -Evidence @{ configuredDelegateCount = $configuredDelegateCount; unmatchedIdentityCount = $delegatesWithoutDirectCalendarAccess.Count }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA804" -Severity Information `
        -Status $(if (-not $settingsAvailable -or -not $calendarPermissionsAvailable) { "NotEvaluated" } else { "Detected" }) `
        -Title "Calendar visibility and subject post-processing are separate controls" `
        -Evidence @{ defaultAccessRights = $defaultAccessRights; deleteSubject = $RbaSettings.DeleteSubject; addOrganizerToSubject = $RbaSettings.AddOrganizerToSubject; relatedRuleIds = @("RBA602", "RBA603") }

    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA805" -Severity Information `
        -Status $(if (-not $settingsAvailable -or -not $calendarPermissionsAvailable) { "NotEvaluated" } else { "Detected" }) `
        -Title "Calendar visibility and private-property removal are separate controls" `
        -Evidence @{ defaultAccessRights = $defaultAccessRights; removePrivateProperty = $RbaSettings.RemovePrivateProperty; relatedRuleIds = @("RBA601") }

    $explicitFullAccessPermissions = @($script:MailboxPermissions | Where-Object {
            -not $_.IsInherited -and -not $_.Deny -and
            @($_.AccessRights | ForEach-Object { [string]$_ }) -contains "FullAccess" -and
            (Get-RbaPermissionIdentity -PermissionUser $_.User) -notin @("nt authority\self", "self")
        })
    Add-CalendarDiagnosticFinding -Findings $findings -RuleId "RBA820" -Severity Warning `
        -Status $(if (-not $mailboxPermissionsAvailable) { "NotEvaluated" } elseif ($explicitFullAccessPermissions.Count -gt 0) { "Detected" } else { "NotDetected" }) `
        -Title "Explicit Full Access is assigned on the resource mailbox" `
        -Evidence @{ explicitFullAccessCount = $explicitFullAccessPermissions.Count }

    return $findings
}

function ConvertTo-RbaIdentityList {
    param(
        [AllowNull()]
        [object[]]$Value
    )

    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Value)) {
        $result.Add((Get-RbaSanitizedIdentity -Value $item -PreserveTargetIdentity))
    }
    return $result.ToArray()
}

function Get-RbaSanitizedIdentity {
    param(
        [AllowNull()]
        [object]$Value,

        [switch]$PreserveTargetIdentity
    )

    $identityText = [string]$Value
    if ($IncludeSensitiveData) {
        return $identityText
    }

    $normalizedIdentity = $identityText.Trim().ToLowerInvariant()
    if ($PreserveTargetIdentity -and $normalizedIdentity -eq $Identity.Trim().ToLowerInvariant()) {
        return $identityText
    }

    if (-not [string]::IsNullOrEmpty($normalizedIdentity) -and
        $script:SanitizedIdentityMap.ContainsKey($normalizedIdentity)) {
        return $script:SanitizedIdentityMap[$normalizedIdentity]
    }

    $script:SanitizedIdentitySequence++
    $sanitizedIdentity = "SanitizedIdentity-$($script:SanitizedIdentitySequence)"
    if (-not [string]::IsNullOrEmpty($normalizedIdentity)) {
        $script:SanitizedIdentityMap.Add($normalizedIdentity, $sanitizedIdentity)
    }
    # An identity without a stable key receives a unique placeholder for each occurrence.
    return $sanitizedIdentity
}

function Get-RbaMailboxIdentitySummaryObject {
    if ($script:collectorStatuses["Mailbox"].status -ne "Success") {
        return $null
    }

    $primarySmtpAddress = [string]$script:Mailbox.PrimarySmtpAddress
    $emailAddresses = @($script:Mailbox.EmailAddresses | ForEach-Object { [string]$_ })
    $normalizedInput = $Identity.Trim()
    $proxyAddressMatch = @($emailAddresses | Where-Object {
            ($_ -replace '^(?i)smtp:', '') -ieq $normalizedInput
        }).Count -gt 0
    $inputIdentityMatch = if (-not [string]::IsNullOrWhiteSpace($primarySmtpAddress) -and
        $primarySmtpAddress -ieq $normalizedInput) {
        "PrimarySmtpAddress"
    } elseif ($proxyAddressMatch) {
        "ProxyAddress"
    } else {
        "OtherResolvedIdentity"
    }

    return [PSCustomObject]@{
        objectState         = $script:MailboxObjectState
        displayName         = [string]$script:Mailbox.DisplayName
        alias               = [string]$script:Mailbox.Alias
        primarySmtpAddress  = $primarySmtpAddress
        inputIdentityMatch  = $inputIdentityMatch
        emailAddressCount   = $emailAddresses.Count
        whenCreatedUtc      = $(if ($null -ne $script:Mailbox.WhenCreatedUTC) { ([DateTime]$script:Mailbox.WhenCreatedUTC).ToUniversalTime().ToString("o") } else { $null })
        whenChangedUtc      = $(if ($null -ne $script:Mailbox.WhenChangedUTC) { ([DateTime]$script:Mailbox.WhenChangedUTC).ToUniversalTime().ToString("o") } else { $null })
        emailAddresses      = $emailAddresses
        exchangeGuid        = [string]$script:Mailbox.ExchangeGuid
        externalDirectoryId = [string]$script:Mailbox.ExternalDirectoryObjectId
    }
}

function Get-RbaLogSummaryObject {
    if ($script:collectorStatuses["RbaLog"].status -ne "Success") {
        return $null
    }

    $starts = @($script:RBALog | Select-String -Pattern "START -")
    return [PSCustomObject]@{
        entryCount                                 = @($script:RBALog).Count
        processedEventCount                        = $starts.Count
        processedEventCountRepresents              = "ProcessingBlocks"
        markerCountCategoryRelationship            = "IndependentNonMutuallyExclusive"
        markerCountCategoriesMayOverlapWithinBlock = $true
        acceptedCount                              = @($script:RBALog | Select-String -Pattern "Action:Accept").Count
        declinedCount                              = @($script:RBALog | Select-String -Pattern "Action:Decline").Count
        tentativeCount                             = @($script:RBALog | Select-String -Pattern "Action:Tentative").Count
        updatedCount                               = @($script:RBALog | Select-String -Pattern "Begin ProcessUpdateRequest").Count
        cancellationCount                          = @($script:RBALog | Select-String -Pattern "It's a meeting cancellation.").Count
        delegateReferralCount                      = @($script:RBALog | Select-String -Pattern "Forwarding Request To Delegates").Count
        skippedExternalCount                       = @($script:RBALog | Select-String -Pattern "Skipping processing because user settings for processing external items is false.").Count
        horizonDeclineCount                        = @($script:RBALog | Select-String -Pattern "Recurrence ends is past the booking window. Meeting will be declined.").Count
        recurrenceTruncateCount                    = @($script:RBALog | Select-String -Pattern "Truncating meeting recurrence end window").Count
    }
}

function Get-RbaCalendarPermissionSummaryObject {
    if ($script:collectorStatuses["CalendarFolderPermissions"].status -ne "Success") {
        return $null
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($permission in @($script:CalendarFolderPermissions)) {
        $permissionIdentity = Get-RbaPermissionIdentity -PermissionUser $permission.User
        $principal = if ($permissionIdentity.Trim() -in @("default", "anonymous") -or $IncludeSensitiveData) {
            [string]$permission.User
        } else {
            Get-RbaSanitizedIdentity -Value $permissionIdentity
        }
        $entries.Add([PSCustomObject]@{
                principal              = $principal
                accessRights           = @($permission.AccessRights | ForEach-Object { [string]$_ })
                sharingPermissionFlags = @($permission.SharingPermissionFlags | ForEach-Object { [string]$_ })
            })
    }

    return [PSCustomObject]@{
        entryCount = $entries.Count
        entries    = $entries.ToArray()
    }
}

function Get-RbaMailboxPermissionSummaryObject {
    if ($script:collectorStatuses["MailboxPermissions"].status -ne "Success") {
        return $null
    }

    $fullAccessPermissions = @($script:MailboxPermissions | Where-Object {
            -not $_.IsInherited -and -not $_.Deny -and
            @($_.AccessRights | ForEach-Object { [string]$_ }) -contains "FullAccess" -and
            (Get-RbaPermissionIdentity -PermissionUser $_.User) -notin @("nt authority\self", "self")
        })
    $grantees = @($fullAccessPermissions | ForEach-Object {
            if ($IncludeSensitiveData) {
                [string]$_.User
            } else {
                Get-RbaSanitizedIdentity -Value (Get-RbaPermissionIdentity -PermissionUser $_.User)
            }
        })

    return [PSCustomObject]@{
        explicitFullAccessCount = $fullAccessPermissions.Count
        grantees                = $grantees
    }
}

function Write-RbaJson {
    Write-RbaPhaseVerbose -Message "Building JSON collector metadata."
    $successfulCollectors = @($script:collectorStatuses.Values | Where-Object { $_.status -eq "Success" }).Count
    $collectionStatus = if ($successfulCollectors -eq $script:collectorStatuses.Count) {
        "Complete"
    } elseif ($successfulCollectors -eq 0) {
        "Failed"
    } else {
        "Partial"
    }

    $jsonCollectorStatuses = [ordered]@{}
    foreach ($collectorName in $script:collectorStatuses.Keys) {
        $collectorStatus = $script:collectorStatuses[$collectorName]
        $jsonCollectorStatuses[$collectorName] = [PSCustomObject]@{
            status                = $collectorStatus.status
            error                 = Get-RbaReportErrorMessage -Message $collectorStatus.error
            exceptionType         = $collectorStatus.exceptionType
            category              = $collectorStatus.category
            fullyQualifiedErrorId = $(if ($IncludeSensitiveData) { $collectorStatus.fullyQualifiedErrorId } else { $null })
            innerExceptionMessage = $(if ($IncludeSensitiveData) { $collectorStatus.innerExceptionMessage } else { $null })
        }
    }
    $jsonCollectionErrors = @($script:collectionErrors | ForEach-Object {
            [PSCustomObject]@{
                collector             = $_.collector
                message               = Get-RbaReportErrorMessage -Message $_.message
                exceptionType         = $_.exceptionType
                category              = $_.category
                fullyQualifiedErrorId = $(if ($IncludeSensitiveData) { $_.fullyQualifiedErrorId } else { $null })
                innerExceptionMessage = $(if ($IncludeSensitiveData) { $_.innerExceptionMessage } else { $null })
            }
        })
    $jsonEvaluationErrors = @($script:evaluationErrors | ForEach-Object {
            [PSCustomObject]@{
                evaluation            = $_.evaluation
                message               = Get-RbaReportErrorMessage -Message $_.message
                exceptionType         = $_.exceptionType
                category              = $_.category
                fullyQualifiedErrorId = $(if ($IncludeSensitiveData) { $_.fullyQualifiedErrorId } else { $null })
                innerExceptionMessage = $(if ($IncludeSensitiveData) { $_.innerExceptionMessage } else { $null })
            }
        })
    Write-RbaPhaseVerbose -Message "JSON collector metadata completed."

    Write-RbaPhaseVerbose -Message "Building JSON evidence summaries."
    $inboxRules = if ($script:collectorStatuses["InboxRules"].status -eq "Success") {
        [PSCustomObject]@{
            totalCount        = @($script:InboxRules).Count
            delegateRuleCount = @($script:InboxRules | Where-Object { $_.Name -like "Delegate Rule*" }).Count
            redactedCount     = @($script:InboxRules | Where-Object { $_.Name -like "REDACTED-*" }).Count
        }
    } else { $null }
    if ($IncludeSensitiveData -and $null -ne $inboxRules) {
        $inboxRules | Add-Member -MemberType NoteProperty -Name ruleNames `
            -Value @(ConvertTo-CalendarDiagnosticPlainStringList -Value $script:InboxRules.Name)
    }

    $calendarProcessing = if ($script:collectorStatuses["CalendarProcessing"].status -eq "Success") {
        [PSCustomObject]@{
            automateProcessing                  = $RbaSettings.AutomateProcessing
            allowConflicts                      = $RbaSettings.AllowConflicts
            allowDistributionGroup              = $RbaSettings.AllowDistributionGroup
            allowMultipleResources              = $RbaSettings.AllowMultipleResources
            maximumDurationInMinutes            = $RbaSettings.MaximumDurationInMinutes
            minimumDurationInMinutes            = $RbaSettings.MinimumDurationInMinutes
            allowRecurringMeetings              = $RbaSettings.AllowRecurringMeetings
            scheduleOnlyDuringWorkHours         = $RbaSettings.ScheduleOnlyDuringWorkHours
            processExternalMeetingMessages      = $RbaSettings.ProcessExternalMeetingMessages
            bookingWindowInDays                 = $RbaSettings.BookingWindowInDays
            conflictPercentageAllowed           = $RbaSettings.ConflictPercentageAllowed
            maximumConflictInstances            = $RbaSettings.MaximumConflictInstances
            enforceSchedulingHorizon            = $RbaSettings.EnforceSchedulingHorizon
            enforceCapacity                     = $RbaSettings.EnforceCapacity
            requestOutOfPolicy                  = ConvertTo-RbaIdentityList -Value $RbaSettings.RequestOutOfPolicy
            allRequestOutOfPolicy               = $RbaSettings.AllRequestOutOfPolicy
            bookInPolicy                        = ConvertTo-RbaIdentityList -Value $RbaSettings.BookInPolicy
            allBookInPolicy                     = $RbaSettings.AllBookInPolicy
            requestInPolicy                     = ConvertTo-RbaIdentityList -Value $RbaSettings.RequestInPolicy
            allRequestInPolicy                  = $RbaSettings.AllRequestInPolicy
            resourceDelegates                   = ConvertTo-RbaIdentityList -Value $RbaSettings.ResourceDelegates
            addNewRequestsTentatively           = $RbaSettings.AddNewRequestsTentatively
            forwardRequestsToDelegates          = $RbaSettings.ForwardRequestsToDelegates
            addOrganizerToSubject               = $RbaSettings.AddOrganizerToSubject
            deleteSubject                       = $RbaSettings.DeleteSubject
            deleteComments                      = $RbaSettings.DeleteComments
            deleteAttachments                   = $RbaSettings.DeleteAttachments
            removePrivateProperty               = $RbaSettings.RemovePrivateProperty
            deleteNonCalendarItems              = $RbaSettings.DeleteNonCalendarItems
            removeForwardedMeetingNotifications = $RbaSettings.RemoveForwardedMeetingNotifications
            removeCanceledMeetings              = $RbaSettings.RemoveCanceledMeetings
            enableAutoRelease                   = $RbaSettings.EnableAutoRelease
            addAdditionalResponse               = $RbaSettings.AddAdditionalResponse
        }
    } else { $null }
    if ($IncludeSensitiveData -and $null -ne $calendarProcessing) {
        $calendarProcessing | Add-Member -MemberType NoteProperty -Name additionalResponse `
            -Value (ConvertTo-CalendarDiagnosticPlainString -Value $RbaSettings.AdditionalResponse)
    }

    $mailboxIdentitySummary = Get-RbaMailboxIdentitySummaryObject
    $mailboxSummary = if ($null -ne $mailboxIdentitySummary) {
        $summary = [PSCustomObject]@{
            identity             = $Identity
            recipientTypeDetails = $script:Mailbox.RecipientTypeDetails
            resourceType         = $script:Mailbox.ResourceType
            objectState          = $mailboxIdentitySummary.objectState
            displayName          = $mailboxIdentitySummary.displayName
            alias                = $mailboxIdentitySummary.alias
            primarySmtpAddress   = $mailboxIdentitySummary.primarySmtpAddress
            inputIdentityMatch   = $mailboxIdentitySummary.inputIdentityMatch
            emailAddressCount    = $mailboxIdentitySummary.emailAddressCount
            whenCreatedUtc       = $mailboxIdentitySummary.whenCreatedUtc
            whenChangedUtc       = $mailboxIdentitySummary.whenChangedUtc
        }
        if ($IncludeSensitiveData) {
            $summary | Add-Member -MemberType NoteProperty -Name emailAddresses -Value $mailboxIdentitySummary.emailAddresses
            $summary | Add-Member -MemberType NoteProperty -Name exchangeGuid -Value $mailboxIdentitySummary.exchangeGuid
            $summary | Add-Member -MemberType NoteProperty -Name externalDirectoryId -Value $mailboxIdentitySummary.externalDirectoryId
        }
        $summary
    } else { $null }

    Write-RbaPhaseVerbose -Message "Building JSON findings."
    $jsonFindings = @(Get-RbaFindings)
    Write-RbaPhaseVerbose -Message "JSON findings completed."

    Write-RbaPhaseVerbose -Message "Assembling JSON report."
    $data = [ordered]@{
        metadata            = [ordered]@{
            schemaVersion    = "1.1-preview"
            scriptVersion    = $BuildVersion
            collectedAtUtc   = (Get-Date).ToUniversalTime().ToString("o")
            identity         = $Identity
            commandLine      = $script:InvocationCommandLine
            collectionStatus = $collectionStatus
            privacyMode      = $(if ($IncludeSensitiveData) { "Full" } elseif (-not [string]::IsNullOrWhiteSpace($Subject) -or -not [string]::IsNullOrWhiteSpace($MeetingId)) { "TargetedMeeting" } else { "Sanitized" })
        }
        collectors          = $jsonCollectorStatuses
        mailbox             = $mailboxSummary
        place               = $(if ($script:collectorStatuses["Place"].status -eq "Success") {
                [PSCustomObject]@{
                    city          = $script:Place.City
                    floor         = $script:Place.Floor
                    capacity      = $script:Place.Capacity
                    roomListCount = @($script:Place.Localities).Count
                }
            } else { $null })
        calendarProcessing  = $calendarProcessing
        calendarPermissions = Get-RbaCalendarPermissionSummaryObject
        mailboxPermissions  = Get-RbaMailboxPermissionSummaryObject
        inboxRules          = $inboxRules
        rbaLogSummary       = Get-RbaLogSummaryObject
        meetingLogSearch    = $script:MeetingLogSearch
        findings            = $jsonFindings
        collectionErrors    = $jsonCollectionErrors
        evaluationErrors    = $jsonEvaluationErrors
    }

    if ($IncludeSensitiveData) {
        Write-RbaPhaseVerbose -Message "Attaching sensitive JSON evidence."
        if ($null -ne $data.place) {
            $data.place | Add-Member -MemberType NoteProperty -Name roomLists `
                -Value @(ConvertTo-CalendarDiagnosticPlainStringList -Value $script:Place.Localities)
        }
        $data.fullRbaLog = @(ConvertTo-CalendarDiagnosticPlainStringList -Value $script:RBALog)
        if (Test-Path -Path $SummaryFilename) {
            $data.transcript = ConvertTo-CalendarDiagnosticPlainString -Value (Get-Content -Path $SummaryFilename -Raw)
        }
    }

    Write-RbaPhaseVerbose -Message "Serializing JSON report."
    Write-RbaPhaseVerbose -Message "Writing JSON report file."
    Write-CalendarDiagnosticJsonFile -InputObject $data -Path $JsonFilename -Depth 8
    Write-RbaPhaseVerbose -Message "JSON report file written."
}
