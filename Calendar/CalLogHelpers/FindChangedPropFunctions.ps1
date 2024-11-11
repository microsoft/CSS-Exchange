# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Determines if key properties of the calendar log have changed.
.DESCRIPTION
    This function checks if the properties of the calendar log have changed by comparing the current
    Calendar log to the Previous calendar log (where it was an IPM.Appointment - i.e. the meeting)

    Changed properties will be added to the Timeline.
#>
function FindChangedProperties {
    if ($CalLog.Client -ne "LocationProcessor" -or $CalLog.Client -notlike "*EBA*" -or $CalLog.Client -notlike "*TBA*") {
        if ($script:PreviousCalLog -and $script:AddChangedProperties) {
            if ($CalLog.StartTime.ToString() -ne $script:PreviousCalLog.StartTime.ToString()) {
                [Array]$TimeLineText = "The StartTime changed from [$($script:PreviousCalLog.StartTime)] to: [$($CalLog.StartTime)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.EndTime.ToString() -ne $script:PreviousCalLog.EndTime.ToString()) {
                [Array]$TimeLineText = "The EndTime changed from [$($script:PreviousCalLog.EndTime)] to: [$($CalLog.EndTime)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.SubjectProperty -ne $script:PreviousCalLog.SubjectProperty) {
                [Array]$TimeLineText = "The SubjectProperty changed from [$($script:PreviousCalLog.SubjectProperty)] to: [$($CalLog.SubjectProperty)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.NormalizedSubject -ne $script:PreviousCalLog.NormalizedSubject) {
                [Array]$TimeLineText = "The NormalizedSubject changed from [$($script:PreviousCalLog.NormalizedSubject)] to: [$($CalLog.NormalizedSubject)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.Location -ne $script:PreviousCalLog.Location) {
                [Array]$TimeLineText = "The Location changed from [$($script:PreviousCalLog.Location)] to: [$($CalLog.Location)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.TimeZone -ne $script:PreviousCalLog.TimeZone) {
                [Array]$TimeLineText = "The TimeZone changed from [$($script:PreviousCalLog.TimeZone)] to: [$($CalLog.TimeZone)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.DisplayAttendeesAll -ne $script:PreviousCalLog.DisplayAttendeesAll) {
                [Array]$TimeLineText = "The All Attendees changed from [$($script:PreviousCalLog.DisplayAttendeesAll)] to: [$($CalLog.DisplayAttendeesAll)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.AppointmentRecurring -ne $script:PreviousCalLog.AppointmentRecurring) {
                [Array]$TimeLineText = "The Appointment Recurrence changed from [$($script:PreviousCalLog.AppointmentRecurring)] to: [$($CalLog.AppointmentRecurring)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.HasAttachment -ne $script:PreviousCalLog.HasAttachment) {
                [Array]$TimeLineText = "The Meeting has Attachment changed from [$($script:PreviousCalLog.HasAttachment)] to: [$($CalLog.HasAttachment)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.IsCancelled -ne $script:PreviousCalLog.IsCancelled) {
                [Array]$TimeLineText = "The Meeting is Cancelled changed from [$($script:PreviousCalLog.IsCancelled)] to: [$($CalLog.IsCancelled)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.IsAllDayEvent -ne $script:PreviousCalLog.IsAllDayEvent) {
                [Array]$TimeLineText = "The Meeting is an All Day Event changed from [$($script:PreviousCalLog.IsAllDayEvent)] to: [$($CalLog.IsAllDayEvent)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.IsException -ne $script:PreviousCalLog.IsException) {
                [Array]$TimeLineText = "The Meeting Is Exception changed from [$($script:PreviousCalLog.IsException)] to: [$($CalLog.IsException)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.IsSeriesCancelled -ne $script:PreviousCalLog.IsSeriesCancelled) {
                [Array]$TimeLineText = "The Is Series Cancelled changed from [$($script:PreviousCalLog.IsSeriesCancelled)] to: [$($CalLog.IsSeriesCancelled)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.EventEmailReminderTimer -ne $script:PreviousCalLog.EventEmailReminderTimer) {
                [Array]$TimeLineText = "The Email Reminder changed from [$($script:PreviousCalLog.EventEmailReminderTimer)] to: [$($CalLog.EventEmailReminderTimer)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.FreeBusyStatus -ne $script:PreviousCalLog.FreeBusyStatus) {
                [Array]$TimeLineText = "The FreeBusy Status changed from [$($script:PreviousCalLog.FreeBusyStatus)] to: [$($CalLog.FreeBusyStatus)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.AppointmentState -ne $script:PreviousCalLog.AppointmentState) {
                [Array]$TimeLineText = "The Appointment State changed from [$($script:PreviousCalLog.AppointmentState)] to: [$($CalLog.AppointmentState)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.MeetingRequestType -ne $script:PreviousCalLog.MeetingRequestType) {
                [Array]$TimeLineText = "The Meeting Request Type changed from [$($script:PreviousCalLog.MeetingRequestType.Value)] to: [$($CalLog.MeetingRequestType.Value)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.CalendarItemType -ne $script:PreviousCalLog.CalendarItemType) {
                [Array]$TimeLineText = "The Calendar Item Type changed from [$($script:PreviousCalLog.CalendarItemType)] to: [$($CalLog.CalendarItemType)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.ResponseType -ne $script:PreviousCalLog.ResponseType) {
                [Array]$TimeLineText = "The ResponseType changed from [$($script:PreviousCalLog.ResponseType)] to: [$($CalLog.ResponseType)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.SenderSMTPAddress -ne $script:PreviousCalLog.SenderSMTPAddress) {
                [Array]$TimeLineText = "The Sender Email Address changed from [$($script:PreviousCalLog.SenderSMTPAddress)] to: [$($CalLog.SenderSMTPAddress)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.From -ne $script:PreviousCalLog.From) {
                [Array]$TimeLineText = "The From changed from [$($script:PreviousCalLog.From)] to: [$($CalLog.From)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.ReceivedBy -ne $script:PreviousCalLog.ReceivedBy) {
                [Array]$TimeLineText = "The Received By changed from [$($script:PreviousCalLog.ReceivedBy)] to: [$($CalLog.ReceivedBy)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }

            if ($CalLog.ReceivedRepresenting -ne $script:PreviousCalLog.ReceivedRepresenting) {
                [Array]$TimeLineText = "The Received Representing changed from [$($script:PreviousCalLog.ReceivedRepresenting)] to: [$($CalLog.ReceivedRepresenting)]"
                CreateMeetingSummary -Time " " -MeetingChanges $TimeLineText
            }
        }
    }
}
