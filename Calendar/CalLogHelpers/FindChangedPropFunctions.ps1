# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns true if the value is effectively "not found" / empty.
#>
function IsNotFound {
    param($Value)
    return ([string]::IsNullOrEmpty($Value) -or $Value -eq "NotFound" -or $Value -eq "-")
}

<#
.SYNOPSIS
    Checks if a property changed between two CalLog entries, ignoring transitions to/from NotFound.
    Returns true if there is a meaningful change worth reporting.
#>
function HasMeaningfulChange {
    param(
        $OldValue,
        $NewValue
    )
    if ([string]::Equals([string]$OldValue, [string]$NewValue, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ((IsNotFound $OldValue) -or (IsNotFound $NewValue)) { return $false }
    return $true
}

<#
.SYNOPSIS
    Determines if key properties of the calendar log have changed.
.DESCRIPTION
    This function checks if the properties of the calendar log have changed by comparing the current
    Calendar log to the Previous calendar log (where it was an IPM.Appointment - i.e. the meeting)

    Changed properties will be added to the Timeline.
#>
function FindChangedProperties {
    if ($CalLog.Client -ne "LocationProcessor" -and $CalLog.Client -notlike "*EBA*" -and $CalLog.Client -notlike "*TBA*") {
        if ($script:PreviousCalLog -and $script:AddChangedProperties) {
            if (HasMeaningfulChange $script:PreviousCalLog.StartTime.ToString() $CalLog.StartTime.ToString()) {
                [Array]$TimeLineText = "The StartTime changed from [$($script:PreviousCalLog.StartTime)] to: [$($CalLog.StartTime)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.EndTime.ToString() $CalLog.EndTime.ToString()) {
                [Array]$TimeLineText = "The EndTime changed from [$($script:PreviousCalLog.EndTime)] to: [$($CalLog.EndTime)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.SubjectProperty $CalLog.SubjectProperty) {
                [Array]$TimeLineText = "The SubjectProperty changed from [$($script:PreviousCalLog.SubjectProperty)] to: [$($CalLog.SubjectProperty)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.NormalizedSubject $CalLog.NormalizedSubject) {
                [Array]$TimeLineText = "The NormalizedSubject changed from [$($script:PreviousCalLog.NormalizedSubject)] to: [$($CalLog.NormalizedSubject)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.Location $CalLog.Location) {
                [Array]$TimeLineText = "The Location changed from [$($script:PreviousCalLog.Location)] to: [$($CalLog.Location)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.TimeZone $CalLog.TimeZone) {
                [Array]$TimeLineText = "The TimeZone changed from [$($script:PreviousCalLog.TimeZone)] to: [$($CalLog.TimeZone)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.DisplayAttendeesAll $CalLog.DisplayAttendeesAll) {
                [Array]$TimeLineText = "The All Attendees changed from [$($script:PreviousCalLog.DisplayAttendeesAll)] to: [$($CalLog.DisplayAttendeesAll)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.AppointmentRecurring $CalLog.AppointmentRecurring) {
                [Array]$TimeLineText = "The Appointment Recurrence changed from [$($script:PreviousCalLog.AppointmentRecurring)] to: [$($CalLog.AppointmentRecurring)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.HasAttachment $CalLog.HasAttachment) {
                [Array]$TimeLineText = "The Meeting has Attachment changed from [$($script:PreviousCalLog.HasAttachment)] to: [$($CalLog.HasAttachment)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.IsCancelled $CalLog.IsCancelled) {
                [Array]$TimeLineText = "The Meeting is Cancelled changed from [$($script:PreviousCalLog.IsCancelled)] to: [$($CalLog.IsCancelled)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.IsAllDayEvent $CalLog.IsAllDayEvent) {
                [Array]$TimeLineText = "The Meeting is an All Day Event changed from [$($script:PreviousCalLog.IsAllDayEvent)] to: [$($CalLog.IsAllDayEvent)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.IsException $CalLog.IsException) {
                [Array]$TimeLineText = "The Meeting Is Exception changed from [$($script:PreviousCalLog.IsException)] to: [$($CalLog.IsException)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.IsSeriesCancelled $CalLog.IsSeriesCancelled) {
                [Array]$TimeLineText = "The Is Series Cancelled changed from [$($script:PreviousCalLog.IsSeriesCancelled)] to: [$($CalLog.IsSeriesCancelled)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.EventEmailReminderTimer $CalLog.EventEmailReminderTimer) {
                [Array]$TimeLineText = "The Email Reminder changed from [$($script:PreviousCalLog.EventEmailReminderTimer)] to: [$($CalLog.EventEmailReminderTimer)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.FreeBusyStatus $CalLog.FreeBusyStatus) {
                [Array]$TimeLineText = "The FreeBusy Status changed from [$($script:PreviousCalLog.FreeBusyStatus)] to: [$($CalLog.FreeBusyStatus)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.AppointmentState $CalLog.AppointmentState) {
                [Array]$TimeLineText = "The Appointment State changed from [$($script:PreviousCalLog.AppointmentState)] to: [$($CalLog.AppointmentState)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.MeetingRequestType $CalLog.MeetingRequestType) {
                [Array]$TimeLineText = "The Meeting Request Type changed from [$($script:PreviousCalLog.MeetingRequestType.Value)] to: [$($CalLog.MeetingRequestType.Value)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.CalendarItemType $CalLog.CalendarItemType) {
                [Array]$TimeLineText = "The Calendar Item Type changed from [$($script:PreviousCalLog.CalendarItemType)] to: [$($CalLog.CalendarItemType)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.ResponseType $CalLog.ResponseType) {
                [Array]$TimeLineText = "The ResponseType changed from [$($script:PreviousCalLog.ResponseType)] to: [$($CalLog.ResponseType)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if (HasMeaningfulChange $script:PreviousCalLog.Sender $CalLog.Sender) {
                if (-not (IsSameOrganizerIdentity $script:PreviousCalLog.Sender $CalLog.Sender)) {
                    [Array]$TimeLineText = "The Sender Email Address changed from [$($script:PreviousCalLog.Sender)] to: [$($CalLog.Sender)]"
                    CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
                }
            }

            if (HasMeaningfulChange $script:PreviousCalLog.From $CalLog.From) {
                if (-not (IsSameOrganizerIdentity $script:PreviousCalLog.From $CalLog.From)) {
                    [Array]$TimeLineText = "The From changed from [$($script:PreviousCalLog.From)] to: [$($CalLog.From)]"
                    CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
                }
            }

            if (HasMeaningfulChange $script:PreviousCalLog.ReceivedRepresenting $CalLog.ReceivedRepresenting) {
                [Array]$TimeLineText = "The Received Representing changed from [$($script:PreviousCalLog.ReceivedRepresenting)] to: [$($CalLog.ReceivedRepresenting)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }
        }
    }
}
