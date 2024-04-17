# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# BuildTimeline
# ===================================================================================================

<#
.SYNOPSIS
    Tries to builds a timeline of the history of the meeting based on the diagnostic objects.

.DESCRIPTION
    By using the time sorted diagnostic objects for one user on one meeting, we try to give a high level
    overview of what happened to the meeting. This can be use to get a quick overview of the meeting and
    then you can look into the CalLog in Excel to get more details.

    The timeline will skip a lot of the noise (isIgnorable) in the CalLogs. It skips EBA (Event Based Assistants),
    and other EXO internal processes, which are (99% of the time) not interesting to the end user and just setting
    hidden internal properties (i.e. things like HasBeenIndex, etc.)

    It also skips items from Shared Calendars, which are calendars that have a Modern Sharing relationship setup,
    which creates a replicated copy of another users. If you want to look at the actions this user took on
    another users calendar, you can look at that users Calendar Logs.

.NOTES
    The timeline will never be perfect, but if you see a way to make it more understandable, readable, etc.,
    please let me know or fix it yourself on GitHub.
    I use a iterative approach to building this, so it will get better over time.
#>
function BuildTimeline {
    param (
        [string] $Identity
    )
    $ThisMeetingID = $script:GCDO.CleanGlobalObjectId | Select-Object -Unique
    $ShortMeetingID = $ThisMeetingID.Substring($ThisMeetingID.length - 6)
    if ($Identity -like "*@*") {
        $ShortName = $Identity.Split('@')[0]
    }
    $ShortName = $ShortName.Substring(0, [System.Math]::Min(20, $ShortName.Length))
    $Script:TimeLineFilename = "$($ShortName)_TimeLine_$ShortMeetingID.csv"

    Write-DashLineBoxColor " TimeLine for [$Identity]:",
    "  Subject: $($script:GCDO[0].NormalizedSubject)",
    "  Organizer: $($script:GCDO[0].SentRepresentingDisplayName)",
    "  MeetingID: $($script:GCDO[0].CleanGlobalObjectId)"
    [Array]$Header = ("Subject: " + ($script:GCDO[0].NormalizedSubject) + " | MeetingID: "+ ($script:GCDO[0].CleanGlobalObjectId))
    MeetingSummary -Time "Calendar Log Timeline for Meeting with" -MeetingChanges $Header
    MeetingSummary -Time "Initial Message Values" -Entry $script:GCDO[0] -LongVersion
    # Ignorable and items from Shared Calendars are not included in the TimeLine.
    $MeetingTimeLine = $Results | Where-Object { $_.IsIgnorable -eq "False" -and $_.IsFromSharedCalendar -eq $False }

    Write-Host "`n`n`nThis is the meetingID $ThisMeetingID`nThis is Short MeetingID $ShortMeetingID"
    if ($MeetingTimeLine.count -eq 0) {
        Write-Host "All CalLogs are Ignorable, nothing to create a timeline with, displaying initial values."
    } else {
        Write-Host "Found $($script:GCDO.count) Log entries, only the $($MeetingTimeLine.count) Non-Ignorable entries will be analyzed in the TimeLine."
    }

    foreach ($CalLog in $MeetingTimeLine) {
        [bool] $MeetingSummaryNeeded = $False
        [bool] $AddChangedProperties = $False

        <#
        .SYNOPSIS
            Determines if key properties of the calendar log have changed.
        .DESCRIPTION
            This function checks if the properties of the calendar log have changed by comparing the current
            Calendar log to the Previous calendar log (where it was an IPM.Appointment - i.e. the meeting)

            Changed properties will be added to the Timeline.
        #>
        function ChangedProperties {
            if ($CalLog.Client -ne "LocationProcessor" -or $CalLog.Client -notlike "EBA:*" -or $CalLog.Client -notlike "TBA:*") {
                if ($PreviousCalLog -and $AddChangedProperties) {
                    if ($CalLog.StartTime.ToString() -ne $PreviousCalLog.StartTime.ToString()) {
                        [Array]$TimeLineText = "The StartTime changed from [$($PreviousCalLog.StartTime)] to: [$($CalLog.StartTime)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.EndTime.ToString() -ne $PreviousCalLog.EndTime.ToString()) {
                        [Array]$TimeLineText = "The EndTime changed from [$($PreviousCalLog.EndTime)] to: [$($CalLog.EndTime)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.SubjectProperty -ne $PreviousCalLog.SubjectProperty) {
                        [Array]$TimeLineText = "The SubjectProperty changed from [$($PreviousCalLog.SubjectProperty)] to: [$($CalLog.SubjectProperty)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.NormalizedSubject -ne $PreviousCalLog.NormalizedSubject) {
                        [Array]$TimeLineText = "The NormalizedSubject changed from [$($PreviousCalLog.NormalizedSubject)] to: [$($CalLog.NormalizedSubject)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.Location -ne $PreviousCalLog.Location) {
                        [Array]$TimeLineText = "The Location changed from [$($PreviousCalLog.Location)] to: [$($CalLog.Location)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.TimeZone -ne $PreviousCalLog.TimeZone) {
                        [Array]$TimeLineText = "The TimeZone changed from [$($PreviousCalLog.TimeZone)] to: [$($CalLog.TimeZone)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.DisplayAttendeesAll -ne $PreviousCalLog.DisplayAttendeesAll) {
                        [Array]$TimeLineText = "The All Attendees changed from [$($PreviousCalLog.DisplayAttendeesAll)] to: [$($CalLog.DisplayAttendeesAll)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.AppointmentRecurring -ne $PreviousCalLog.AppointmentRecurring) {
                        [Array]$TimeLineText = "The Appointment Recurrence changed from [$($PreviousCalLog.AppointmentRecurring)] to: [$($CalLog.AppointmentRecurring)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.HasAttachment -ne $PreviousCalLog.HasAttachment) {
                        [Array]$TimeLineText = "The Meeting has Attachment changed from [$($PreviousCalLog.HasAttachment)] to: [$($CalLog.HasAttachment)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsCancelled -ne $PreviousCalLog.IsCancelled) {
                        [Array]$TimeLineText = "The Meeting is Cancelled changed from [$($PreviousCalLog.IsCancelled)] to: [$($CalLog.IsCancelled)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsAllDayEvent -ne $PreviousCalLog.IsAllDayEvent) {
                        [Array]$TimeLineText = "The Meeting is an All Day Event changed from [$($PreviousCalLog.IsAllDayEvent)] to: [$($CalLog.IsAllDayEvent)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsException -ne $PreviousCalLog.IsException) {
                        [Array]$TimeLineText = "The Meeting Is Exception changed from [$($PreviousCalLog.IsException)] to: [$($CalLog.IsException)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.IsSeriesCancelled -ne $PreviousCalLog.IsSeriesCancelled) {
                        [Array]$TimeLineText = "The Is Series Cancelled changed from [$($PreviousCalLog.IsSeriesCancelled)] to: [$($CalLog.IsSeriesCancelled)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.EventEmailReminderTimer -ne $PreviousCalLog.EventEmailReminderTimer) {
                        [Array]$TimeLineText = "The Email Reminder changed from [$($PreviousCalLog.EventEmailReminderTimer)] to: [$($CalLog.EventEmailReminderTimer)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.FreeBusyStatus -ne $PreviousCalLog.FreeBusyStatus) {
                        [Array]$TimeLineText = "The FreeBusy Status changed from [$($PreviousCalLog.FreeBusyStatus)] to: [$($CalLog.FreeBusyStatus)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.AppointmentState -ne $PreviousCalLog.AppointmentState) {
                        [Array]$TimeLineText = "The Appointment State changed from [$($PreviousCalLog.AppointmentState)] to: [$($CalLog.AppointmentState)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.MeetingRequestType -ne $PreviousCalLog.MeetingRequestType) {
                        [Array]$TimeLineText = "The Meeting Request Type changed from [$($PreviousCalLog.MeetingRequestType.Value)] to: [$($CalLog.MeetingRequestType.Value)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.CalendarItemType -ne $PreviousCalLog.CalendarItemType) {
                        [Array]$TimeLineText = "The Calendar Item Type changed from [$($PreviousCalLog.CalendarItemType)] to: [$($CalLog.CalendarItemType)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.ResponseType -ne $PreviousCalLog.ResponseType) {
                        [Array]$TimeLineText = "The ResponseType changed from [$($PreviousCalLog.ResponseType)] to: [$($CalLog.ResponseType)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.SenderSMTPAddress -ne $PreviousCalLog.SenderSMTPAddress) {
                        [Array]$TimeLineText = "The Sender Email Address changed from [$($PreviousCalLog.SenderSMTPAddress)] to: [$($CalLog.SenderSMTPAddress)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.From -ne $PreviousCalLog.From) {
                        [Array]$TimeLineText = "The From changed from [$($PreviousCalLog.From)] to: [$($CalLog.From)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.ReceivedBy -ne $PreviousCalLog.ReceivedBy) {
                        [Array]$TimeLineText = "The Received By changed from [$($PreviousCalLog.ReceivedBy)] to: [$($CalLog.ReceivedBy)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }

                    if ($CalLog.ReceivedRepresenting -ne $PreviousCalLog.ReceivedRepresenting) {
                        [Array]$TimeLineText = "The Received Representing changed from [$($PreviousCalLog.ReceivedRepresenting)] to: [$($CalLog.ReceivedRepresenting)]"
                        MeetingSummary -Time " " -MeetingChanges $TimeLineText
                    }
                }
            }
        }

        <#
        .SYNOPSIS
            This is the part that generates the heart of the timeline, a Giant Switch statement based on the ItemClass.
        #>
        switch -Wildcard ($CalendarItemTypes.($CalLog.ItemClass)) {
            MeetingRequest {
                switch ($CalLog.TriggerAction) {
                    Create {
                        if ($IsOrganizer) {
                            if ($CalLog.IsException -eq $True) {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Created an Exception Meeting Request with $($CalLog.Client) for [$($CalLog.StartTime)]."
                            } else {
                                [array] $Output  = "[$($CalLog.ResponsibleUser)] Created a Meeting Request was with $($CalLog.Client)"
                            }
                        } else {
                            if ($CalLog.DisplayAttendeesTo -ne $PreviousCalLog.DisplayAttendeesTo -or $CalLog.DisplayAttendeesCc -ne $PreviousCalLog.DisplayAttendeesCc) {
                                [array] $Output = "The user Forwarded a Meeting Request with $($CalLog.Client)."
                            } else {
                                if ($CalLog.Client -eq "Transport") {
                                    if ($CalLog.IsException -eq $True) {
                                        [array] $Output = "Transport delivered a new Meeting Request from [$($CalLog.SentRepresentingDisplayName)] for an exception starting on [$($CalLog.StartTime)]" + $(if ($null -ne $($CalLog.ReceivedRepresenting)) { " for user [$($CalLog.ReceivedRepresenting)]" })  + "."
                                        $MeetingSummaryNeeded = $True
                                    } else {
                                        [Array]$Output = "Transport delivered a new Meeting Request from [$($CalLog.SentRepresentingDisplayName)]" +
                                        $(if ($null -ne $($CalLog.ReceivedRepresenting) -and $CalLog.ReceivedRepresenting -ne $CalLog.ReceivedBy)
                                            { " for user [$($CalLog.ReceivedRepresenting)]" }) + "."
                                    }
                                } elseif ($CalLog.Client -eq "CalendarRepairAssistant") {
                                    if ($CalLog.IsException -eq $True) {
                                        [array] $Output = "CalendarRepairAssistant Created a new Meeting Request to repair an inconsistency with an exception starting on [$($CalLog.StartTime)]."
                                    } else {
                                        [array] $Output = "CalendarRepairAssistant Created a new Meeting Request to repair an inconsistency."
                                    }
                                } else {
                                    if ($CalLog.IsException -eq $True) {
                                        [array] $Output = "[$($CalLog.ResponsibleUser)] Created a new Meeting Request with $($CalLog.Client) for an exception starting on [$($CalLog.StartTime)]."
                                    } else {
                                        [array] $Output = "[$($CalLog.ResponsibleUser)] Created a new Meeting Request with $($CalLog.Client)."
                                    }
                                }
                            }
                        }
                    }
                    Update {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Updated on the $($CalLog.MeetingRequestType.Value) Meeting Request with $($CalLog.Client)."
                    }
                    MoveToDeletedItems {
                        if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                            [array] $Output = "$($CalLog.Client) Deleted the Meeting Request."
                        } else {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Deleted the Meeting Request with $($CalLog.Client)."
                        }
                    }
                    default {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Deleted the $($CalLog.MeetingRequestType.Value) Meeting Request with $($CalLog.Client)."
                    }
                }
            }
            Resp* {
                switch ($CalLog.ItemClass) {
                    "IPM.Schedule.Meeting.Resp.Tent" { $MeetingRespType = "Tentative" }
                    "IPM.Schedule.Meeting.Resp.Neg" { $MeetingRespType = "DECLINE" }
                    "IPM.Schedule.Meeting.Resp.Pos" { $MeetingRespType = "ACCEPT" }
                }

                if ($CalLog.AppointmentCounterProposal -eq "True") {
                    [array] $Output = "[$($CalLog.SentRepresentingDisplayName)] send a $($MeetingRespType) response message with a New Time Proposal: $($CalLog.StartTime) to $($CalLog.EndTime)"
                } else {
                    switch -Wildcard ($CalLog.TriggerAction) {
                        "Update" { $Action = "Updated" }
                        "Create" { $Action = "Sent" }
                        "*Delete*" { $Action = "Deleted" }
                        default {
                            $Action = "Updated"
                        }
                    }

                    $Extra = ""
                    if ($CalLog.IsException) {
                        $Extra = " to the meeting starting $($CalLog.StartTime)"
                    } elseif ($CalLog.AppointmentRecurring) {
                        $Extra = " to the meeting series"
                    }

                    if ($IsOrganizer) {
                        [array] $Output = "[$($CalLog.SentRepresentingDisplayName)] $($Action) a $($MeetingRespType) Meeting Response message$($Extra)."
                    } else {
                        switch ($CalLog.Client) {
                            ResourceBookingAssistant {
                                [array] $Output = "ResourceBookingAssistant $($Action) a $($MeetingRespType) Meeting Response message."
                            }
                            Transport {
                                [array] $Output = "[$($CalLog.From)] $($Action) $($MeetingRespType) Meeting Response message."
                            }
                            default {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] $($Action) [$($CalLog.SentRepresentingDisplayName)]'s $($MeetingRespType) Meeting Response with $($CalLog.Client)."
                            }
                        }
                    }
                }
            }
            ForwardNotification {
                [array] $Output = "The meeting was FORWARDED by [$($CalLog.SentRepresentingDisplayName)]."
            }
            ExceptionMsgClass {
                if ($CalLog.ResponsibleUser -ne "Calendar Assistant") {
                    [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d Exception to the meeting series with $($CalLog.Client)."
                }
            }
            IpmAppointment {
                switch ($CalLog.TriggerAction) {
                    Create {
                        if ($IsOrganizer) {
                            if ($CalLog.Client -eq "Transport") {
                                [array] $Output = "Transport Created a new meeting."
                            } else {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Created a new Meeting with $($CalLog.Client)."
                            }
                        } else {
                            switch ($CalLog.Client) {
                                Transport {
                                    [array] $Output = "Transport Created a new Meeting on the calendar from [$($CalLog.SentRepresentingDisplayName)] and marked it Tentative."
                                }
                                ResourceBookingAssistant {
                                    [array] $Output = "ResourceBookingAssistant Created a new Meeting on the calendar from [$($CalLog.SentRepresentingDisplayName)] and marked it Tentative."
                                }
                                default {
                                    [array] $Output = "[$($CalLog.ResponsibleUser)] Created the Meeting with $($CalLog.Client)."
                                }
                            }
                        }
                    }
                    Update {
                        switch ($CalLog.Client) {
                            Transport {
                                if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                                    [array] $Output = "Transport Updated the meeting based on changes made to the meeting on [$($CalLog.Sender)] calendar."
                                } else {
                                    [array] $Output = "Transport $($CalLog.TriggerAction)d the meeting based on changes made by [$($CalLog.ResponsibleUser)]."
                                }
                            }
                            LocationProcessor {
                                [array] $Output = ""
                            }
                            ResourceBookingAssistant {
                                [array] $Output = "ResourceBookingAssistant $($CalLog.TriggerAction)d the Meeting."
                            }
                            CalendarRepairAssistant {
                                [array] $Output = "CalendarRepairAssistant $($CalLog.TriggerAction)d the Meeting to repair an inconsistency."
                            }
                            default {
                                if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                                    [array] $Output = "The Exchange System $($CalLog.TriggerAction)d the meeting via the Calendar Assistant."
                                } else {
                                    [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d the Meeting with $($CalLog.Client)."
                                    $AddChangedProperties = $True
                                }
                            }
                        }

                        if ($CalLog.FreeBusyStatus -eq 2 -and $PreviousCalLog.FreeBusyStatus -ne 2) {
                            if ($CalLog.ResponsibleUserName -eq "Calendar Assistant") {
                                [array] $Output = "$($CalLog.Client) Accepted the meeting."
                            } else {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Accepted the meeting with $($CalLog.Client)."
                            }
                            $AddChangedProperties = $False
                        } elseif ($CalLog.FreeBusyStatus -ne 2 -and $PreviousCalLog.FreeBusyStatus -eq 2) {
                            if ($IsOrganizer) {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Cancelled the Meeting with $($CalLog.Client)."
                            } else {
                                if ($CalLog.ResponsibleUser -ne "Calendar Assistant") {
                                    [array] $Output = "[$($CalLog.ResponsibleUser)] Declined the meeting with $($CalLog.Client)."
                                }
                            }
                            $AddChangedProperties = $False
                        }
                    }
                    SoftDelete {
                        switch ($CalLog.Client) {
                            Transport {
                                [array] $Output = "Transport $($CalLog.TriggerAction)d the meeting based on changes by [$($CalLog.SentRepresentingDisplayName)]."
                            }
                            LocationProcessor {
                                [array] $Output = ""
                            }
                            ResourceBookingAssistant {
                                [array] $Output = "ResourceBookingAssistant $($CalLog.TriggerAction)d the Meeting."
                            }
                            default {
                                if ($CalLog.ResponsibleUser -eq "Calendar Assistant") {
                                    [array] $Output = "The Exchange System $($CalLog.TriggerAction)d the meeting via the Calendar Assistant."
                                } else {
                                    [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d the meeting with $($CalLog.Client)."
                                    $AddChangedProperties = $True
                                }
                            }
                        }

                        if ($CalLog.FreeBusyStatus -eq 2 -and $PreviousCalLog.FreeBusyStatus -ne 2) {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Accepted the Meeting with $($CalLog.Client)."
                            $AddChangedProperties = $False
                        } elseif ($CalLog.FreeBusyStatus -ne 2 -and $PreviousCalLog.FreeBusyStatus -eq 2) {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Declined the Meeting with $($CalLog.Client)."
                            $AddChangedProperties = $False
                        }
                    }
                    MoveToDeletedItems {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Deleted the Meeting with $($CalLog.Client) (Moved the Meeting to the Deleted Items)."
                    }
                    default {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction) the Meeting with $($CalLog.Client)."
                        $MeetingSummaryNeeded = $False
                    }
                }
            }
            Cancellation {
                switch ($CalLog.Client) {
                    Transport {
                        if ($CalLog.IsException -eq $True) {
                            [array] $Output = "Transport $($CalLog.TriggerAction)d a Meeting Cancellation based on changes by [$($CalLog.SenderSMTPAddress)] for the exception starting on [$($CalLog.StartTime)]"
                        } else {
                            [array] $Output = "Transport $($CalLog.TriggerAction)d a Meeting Cancellation based on changes by [$($CalLog.SenderSMTPAddress)]."
                        }
                    }
                    default {
                        if ($CalLog.IsException -eq $True) {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d a Cancellation with $($CalLog.Client) for the exception starting on [$($CalLog.StartTime)]."
                        } elseif ($CalLog.CalendarItemType -eq "RecurringMaster") {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d a Cancellation for the Series with $($CalLog.Client)."
                        } else {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d the Cancellation with $($CalLog.Client)."
                        }
                    }
                }
            }
            default {
                if ($CalLog.TriggerAction -eq "Create") {
                    $Action = "New"
                } else {
                    $Action = "$($CalLog.TriggerAction)"
                }
                [array] $Output = "[$($CalLog.ResponsibleUser)] performed a $($Action) on the $($CalLog.ItemClass) with $($CalLog.Client)."
            }
        }

        # Create the Timeline by adding to Time to the generated Output
        $Time = "$($CalLog.LogRow) -- $($CalLog.LastModifiedTime)"

        if ($Output) {
            if ($MeetingSummaryNeeded) {
                MeetingSummary -Time $Time -MeetingChanges $Output
                MeetingSummary -Time " " -ShortVersion -Entry $CalLog
            } else {
                MeetingSummary -Time $Time -MeetingChanges $Output
                if ($AddChangedProperties) {
                    ChangedProperties
                }
            }
        }

        # Setup Previous log (if current logs is an IPM.Appointment)
        if ($CalendarItemTypes.($CalLog.ItemClass) -eq "IpmAppointment" -or $CalendarItemTypes.($CalLog.ItemClass) -eq "ExceptionMsgClass") {
            $PreviousCalLog = $CalLog
        }
    }

    $Results = @()
}
