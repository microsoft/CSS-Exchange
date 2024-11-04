# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    This is the part that generates the heart of the timeline, a Giant Switch statement based on the ItemClass.
#>
function CreateTimelineRow {
    switch -Wildcard ($CalLog.ItemClass) {
        Meeting.Request {
            switch ($CalLog.TriggerAction) {
                Create {
                    if ($IsOrganizer) {
                        if ($CalLog.IsException -eq $True) {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Created an Exception Meeting Request with $($CalLog.Client) for [$($CalLog.StartTime)]."
                        } else {
                            [array] $Output  = "[$($CalLog.ResponsibleUser)] Created a Meeting Request with $($CalLog.Client)"
                        }
                    } else {
                        if ($CalLog.DisplayAttendeesTo -ne $script:PreviousCalLog.DisplayAttendeesTo -or $CalLog.DisplayAttendeesCc -ne $script:PreviousCalLog.DisplayAttendeesCc) {
                            [array] $Output = "The user Forwarded a Meeting Request with $($CalLog.Client)."
                        } else {
                            if ($CalLog.Client -eq "Transport") {
                                if ($CalLog.IsException -eq $True) {
                                    [array] $Output = "Transport delivered a new Meeting Request from [$($CalLog.From)] for an exception starting on [$($CalLog.StartTime)]" + $(if ($null -ne $($CalLog.ReceivedRepresenting)) { " for user [$($CalLog.ReceivedRepresenting)]" }) + "."
                                    $script:MeetingSummaryNeeded = $True
                                } else {
                                    [Array] $Output = "Transport delivered a new Meeting Request from [$($CalLog.From)]" +
                                    $(if ($null -ne $($CalLog.ReceivedRepresenting) -and $CalLog.ReceivedRepresenting -ne $CalLog.ReceivedBy)
                                        { " for user [$($CalLog.ReceivedRepresenting)]" }) + "."
                                }
                            } elseif ($calLog.client -eq "ResourceBookingAssistant") {
                                [array] $Output  = "ResourceBookingAssistant Forwarded a Meeting Request to a Resource Delegate."
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
                    if ($calLog.client -eq "ResourceBookingAssistant") {
                        [array] $Output  = "ResourceBookingAssistant Updated the Meeting Request."
                    } else {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Updated the $($CalLog.MeetingRequestType.Value) Meeting Request with $($CalLog.Client)."
                    }
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
                "Resp.Tent" { $MeetingRespType = "Tentative" }
                "Resp.Neg" { $MeetingRespType = "DECLINE" }
                "Resp.Pos" { $MeetingRespType = "ACCEPT" }
            }

            if ($CalLog.AppointmentCounterProposal -eq "True") {
                [array] $Output = "[$($CalLog.Organizer)] send a $($MeetingRespType) response message with a New Time Proposal: $($CalLog.StartTime) to $($CalLog.EndTime)"
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
                    [array] $Output = "[$($CalLog.Organizer)] $($Action) a $($MeetingRespType) meeting Response message$($Extra)."
                } else {
                    switch ($CalLog.Client) {
                        ResourceBookingAssistant {
                            [array] $Output = "ResourceBookingAssistant $($Action) a $($MeetingRespType) Meeting Response message$($Extra)."
                        }
                        Transport {
                            [array] $Output = "[$($CalLog.From)] $($Action) $($MeetingRespType) Meeting Response message$($Extra)."
                        }
                        default {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] $($Action) [$($CalLog.Organizer)]'s $($MeetingRespType) Meeting Response with $($CalLog.Client)$($Extra)."
                        }
                    }
                }
            }
        }
        Forward.Notification {
            [array] $Output = "The meeting was FORWARDED by [$($CalLog.Organizer)]."
        }
        Exception {
            if ($CalLog.ResponsibleUser -ne "Calendar Assistant") {
                [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction)d Exception starting $($CalLog.StartTime) to the meeting series with $($CalLog.Client)."
            }
        }
        Ipm.Appointment {
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
                                [array] $Output = "Transport Created a new Meeting on the calendar from [$($CalLog.Organizer)] and marked it Tentative."
                            }
                            ResourceBookingAssistant {
                                [array] $Output = "ResourceBookingAssistant Created a new Meeting on the calendar from [$($CalLog.Organizer)] and marked it Tentative."
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
                                $script:AddChangedProperties = $True
                            }
                        }
                    }

                    if ($CalLog.FreeBusyStatus -eq 2 -and $script:PreviousCalLog.FreeBusyStatus -ne 2) {
                        if ($CalLog.ResponsibleUserName -eq "Calendar Assistant") {
                            [array] $Output = "$($CalLog.Client) Accepted the meeting."
                        } else {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Accepted the meeting with $($CalLog.Client)."
                        }
                        $script:AddChangedProperties = $False
                    } elseif ($CalLog.FreeBusyStatus -ne 2 -and $script:PreviousCalLog.FreeBusyStatus -eq 2) {
                        if ($IsOrganizer) {
                            [array] $Output = "[$($CalLog.ResponsibleUser)] Cancelled the Meeting with $($CalLog.Client)."
                        } else {
                            if ($CalLog.ResponsibleUser -ne "Calendar Assistant") {
                                [array] $Output = "[$($CalLog.ResponsibleUser)] Declined the meeting with $($CalLog.Client)."
                            }
                        }
                        $script:AddChangedProperties = $False
                    }
                }
                SoftDelete {
                    switch ($CalLog.Client) {
                        Transport {
                            [array] $Output = "Transport $($CalLog.TriggerAction)d the meeting based on changes by [$($CalLog.Organizer)]."
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
                                $script:AddChangedProperties = $True
                            }
                        }
                    }

                    if ($CalLog.FreeBusyStatus -eq 2 -and $script:PreviousCalLog.FreeBusyStatus -ne 2) {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Accepted the Meeting with $($CalLog.Client)."
                        $script:AddChangedProperties = $False
                    } elseif ($CalLog.FreeBusyStatus -ne 2 -and $script:PreviousCalLog.FreeBusyStatus -eq 2) {
                        [array] $Output = "[$($CalLog.ResponsibleUser)] Declined the Meeting with $($CalLog.Client)."
                        $script:AddChangedProperties = $False
                    }
                }
                MoveToDeletedItems {
                    [array] $Output = "[$($CalLog.ResponsibleUser)] Deleted the Meeting with $($CalLog.Client) (Moved the Meeting to the Deleted Items)."
                }
                default {
                    [array] $Output = "[$($CalLog.ResponsibleUser)] $($CalLog.TriggerAction) the Meeting with $($CalLog.Client)."
                    $script:MeetingSummaryNeeded = $False
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
                ResourceBookingAssistant {
                    if ($CalLog.TriggerAction -eq "MoveToDeletedItems") {
                        [array] $Output = "ResourceBookingAssistant Deleted the Cancellation."
                    } else {
                        [array] $Output = "ResourceBookingAssistant $($CalLog.TriggerAction)d the Cancellation."
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
                $Action = "New "
            } else {
                $Action = "$($CalLog.TriggerAction)"
            }
            [array] $Output = "[$($CalLog.ResponsibleUser)] performed a $($Action) on the $($CalLog.ItemClass) with $($CalLog.Client)."
        }
    }

    return $Output
}
