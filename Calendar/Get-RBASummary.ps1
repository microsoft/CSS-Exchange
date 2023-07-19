# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.exchange

#
# .DESCRIPTION
# This script runs the Get-CalendarProcessing cmdlet and returns the output with more details in clear english,
# highlighting the key settings that affect RBA and some of the common errors in configuration.
#
# .PARAMETER Identity
# Address of Resource Mailbox to query
#
# .EXAMPLE
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com
# or
# .\Get-RBASummary.ps1 -Identity Room1@Contoso.com -Verbose

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Identity
)

$BuildVersion = ""

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if (Test-ScriptVersion -AutoUpdate) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."  -ForegroundColor Yellow
    return
}

Write-Verbose "Script Versions: $BuildVersion"

function ValidateMailbox {
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-Mailbox -Identity $Identity"
    $script:Mailbox = Get-Mailbox -Identity $Identity

    # check we get a response
    if ($null -eq $Mailbox) {
        Write-Host -ForegroundColor Red "Get-Mailbox returned null. Make sure you Import-Module ExchangeOnlineManagement and  Connect-ExchangeOnline. Exiting script.";
        exit;
    } else {
        if ($Mailbox.RecipientTypeDetails -ne "RoomMailbox" -and $Mailbox.RecipientTypeDetails -ne "EquipmentMailbox") {
            Write-Host -ForegroundColor Red "The mailbox is not a Room Mailbox / Equipment Mailbox. RBA will only work with these. Exiting script.";
            exit;
        }
        if ($Mailbox.RecipientType -eq "Workspace") {
            $script:Workspace = $true;
        }
        Write-Host -ForegroundColor Green "The mailbox is valid for RBA will work with.";
    }

    Write-Host -ForegroundColor Yellow "For more information see https://learn.microsoft.com/en-us/powershell/module/exchange/get-mailbox?view=exchange-ps";
    Write-Host ;
}

# Retrieve the CalendarProcessing information
function GetCalendarProcessing {
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-CalendarProcessing -Identity $Identity"
    $script:RbaSettings = Get-CalendarProcessing -Identity $Identity

    # check we get a response
    if ($null -eq $RbaSettings) {
        Write-Host -ForegroundColor Red "Get-CalendarProcessing returned null.
                Make sure you Import-Module ExchangeOnlineManagement
                and  Connect-ExchangeOnline
                Exiting script.";
        exit;
    }

    Write-Host -ForegroundColor Yellow "For more information see
                https://learn.microsoft.com/en-us/powershell/module/exchange/set-calendarprocessing?view=exchange-ps";
    Write-Host ;

    $RbaSettings | Format-List
}

function EvaluateCalProcessing {

    if ($RbaSettings.AutomateProcessing -ne "AutoAccept") {
        Write-Host -ForegroundColor Red "AutomateProcessing is not set to AutoAccept. RBA will not work as configured. "
        Write-Host -ForegroundColor Red "AutomateProcessing is set to"$RbaSettings.AutomateProcessing
        Write-Host -ForegroundColor Yellow "Use 'Set-CalendarProcessing -Identity $Identity -AutomateProcessing AutoAccept' to set AutomateProcessing to AutoAccept."
        Write-Host -ForegroundColor Red "Exiting script."
        exit
    } else {
        Write-Host -ForegroundColor Green "AutomateProcessing is set to AutoAccept. RBA will analyze the meeting request."
    }
}

# RBA processing logic
function ProcessingLogic {
    Write-Host "`r`nRBA Processing Logic`r`n";
    @"
        The RBA first evaluates a request against all the policy configuration constraints assigned in the calendar
        processing object for the resource mailbox.

        This will result in the request either being in-policy or out-of-policy. The RBA then reads the recipient well
        values to determine where to send or handle in-policy requests and out-of-policy requests.

        Lastly if the Request is accepted, the PostProcessing steps will be performed.
"@
}

function RBACriteria {
    Write-Host "`r`n===================="
    Write-Host "Policy Configuration";
    Write-Host "====================r`n";

    Write-Host " The following criteria are used to determine if a meeting request is in-policy or out-of-policy. ";
    Write-Host -ForegroundColor Cyan "`t Setting                          Value"
    Write-Host -ForegroundColor Cyan "`t -------------------------------  -----------------------------"
    Write-Host -ForegroundColor Cyan "`t AllowConflicts:                 "$RbaSettings.AllowConflicts
    Write-Host -ForegroundColor Cyan "`t AllowDistributionGroup:         "$RbaSettings.AllowDistributionGroup
    Write-Host -ForegroundColor Cyan "`t AllowMultipleResources:         "$RbaSettings.AllowMultipleResources
    Write-Host -ForegroundColor Cyan "`t MaximumDurationInMinutes:       "$RbaSettings.MaximumDurationInMinutes
    Write-Host -ForegroundColor Cyan "`t MinimumDurationInMinutes:       "$RbaSettings.MinimumDurationInMinutes
    Write-Host -ForegroundColor Cyan "`t AllowRecurringMeetings:         "$RbaSettings.AllowRecurringMeetings
    Write-Host -ForegroundColor Cyan "`t ScheduleOnlyDuringWorkHours:    "$RbaSettings.ScheduleOnlyDuringWorkHours
    Write-Host -ForegroundColor Cyan "`t ProcessExternalMeetingMessages: "$RbaSettings.ProcessExternalMeetingMessages
    Write-Host -ForegroundColor Cyan "`t BookingWindowInDays:            "$RbaSettings.BookingWindowInDays
    Write-Host -ForegroundColor Cyan "`t ConflictPercentageAllowed:      "$RbaSettings.ConflictPercentageAllowed
    Write-Host -ForegroundColor Cyan "`t MaximumConflictInstances:       "$RbaSettings.MaximumConflictInstances
    Write-Host -ForegroundColor Cyan "`t MaximumConflictPercentage:      "$RbaSettings.MaximumConflictPercentage
    Write-Host -ForegroundColor Cyan "`t EnforceSchedulingHorizon:       "$RbaSettings.EnforceSchedulingHorizon
    Write-Host -ForegroundColor Cyan "`t SchedulingHorizonInDays:        "$RbaSettings.SchedulingHorizonInDays

    Write-Host -NoNewline "`r`nIf all the above criteria are met, the request is "
    Write-Host -ForegroundColor Yellow -NoNewline "In-Policy."
    Write-Host -NoNewline "`r`nIf any of the above criteria are not met, the request is "
    Write-Host -ForegroundColor DarkYellow -NoNewline  "Out-of-Policy.";
    Write-Host;
}

# RBA processing settings Verbose Output
function RBACriteriaExtra {
    if ($PSBoundParameters['Verbose']) {

        $RBACriteriaExtra = ""

        if ($RbaSettings.AllowConflicts -eq $true) {
            $RBACriteriaExtra += "Unlimited conflicts are allowed. This is Required for Workspaces.`r`n"
        } elseif ($RbaSettings.ConflictPercentageAllowed -eq 0 `
                -and $RbaSettings.MaximumConflictInstances -eq 0) {
            $RBACriteriaExtra += "No conflicts are allowed.`r`n"
        } else {
            $RBACriteriaExtra += "For Recurring meetings, conflicts are allowed as long as they are less than $($RbaSettings.ConflictPercentageAllowed)% or less than $($RbaSettings.MaximumConflictInstances) instances.`r`n"
        }

        if ($RbaSettings.AllowDistributionGroup -eq $true) {
            $RBACriteriaExtra += "Distribution groups are allowed.`r`n"
        } else {
            $RBACriteriaExtra += "Distribution groups are not allowed.`r`n"
        }

        if ($RbaSettings.AllowMultipleResources -eq $true) {
            $RBACriteriaExtra += "Multiple resources are allowed.`r`n"
        } else {
            $RBACriteriaExtra += "Multiple resources are not allowed.`r`n"
        }

        if ($RbaSettings.MaximumDurationInMinutes -gt 0) {
            $RBACriteriaExtra += "Maximum meeting duration is $($RbaSettings.MaximumDurationInMinutes) minutes.`r`n"
        }

        if ($RbaSettings.MinimumDurationInMinutes -gt 0) {
            $RBACriteriaExtra += "Minimum meeting duration is $($RbaSettings.MinimumDurationInMinutes) minutes.`r`n"
        }

        if ($RbaSettings.AllowRecurringMeetings -eq $true) {
            $RBACriteriaExtra += "Recurring meetings are allowed.`r`n"
        } else {
            $RBACriteriaExtra += "Recurring meetings are not allowed.`r`n"
        }

        if ($RbaSettings.ScheduleOnlyDuringWorkHours -eq $true) {
            $RBACriteriaExtra += "Meetings are only allowed during work hours.`r`n"
        } else {
            $RBACriteriaExtra += "Meetings are allowed at any time.`r`n"
        }

        if ($RbaSettings.EnforceSchedulingHorizon -eq $true -and $RbaSettings.BookingWindowInDays -gt 0) {
            $RBACriteriaExtra += "Meetings are only allowed if it starts within $($RbaSettings.BookingWindowInDays) days.`r`n"
        } else {
            $RBACriteriaExtra += "SchedulingHorizon is not enforced.`r`n"
        }

        if ($RbaSettings.ProcessExternalMeetingMessages -eq $true) {
            $RBACriteriaExtra += "External meeting requests will be evaluated.`r`n"
        } else {
            $RBACriteriaExtra += "RBA will reject all External meeting requests.`r`n"
        }

        $RBACriteriaExtra += "Meetings will only be accepted if within $($RbaSettings.BookingWindowInDays) days.`r`n";

        Write-Verbose $RBACriteriaExtra
    }
}

# RBA processing settings
function RBAProcessing {
    Write-Host "`r`n==================";
    Write-Host "Policy Processing:";
    Write-Host "==================";

    # check for False null False null False null - RBA is configured to do nothing.
    if ($RbaSettings.RequestOutOfPolicy.Count -eq 0 `
            -and $RbaSettings.AllRequestOutOfPolicy -eq $false `
            -and $RbaSettings.BookInPolicy.Count -eq 0 `
            -and $RbaSettings.AllBookInPolicy -eq $false `
            -and $RbaSettings.RequestInPolicy.Count -eq 0 `
            -and $RbaSettings.AllRequestInPolicy -eq $false ) {
        Write-Host -ForegroundColor Red "`r`n Error: The RBA isn’t configured to process items. No RBA processing of Meeting Requests will occur."
        Write-Host -ForegroundColor Red "Consider configuring the properties below to process all requests.  (Default is null, True, null, False, null, True)."
        Write-Host
        Write-Host "`t RequestOutOfPolicy:            {$($RbaSettings.RequestOutOfPolicy)}"
        Write-Host "`t AllRequestOutOfPolicy:        "$RbaSettings.AllRequestOutOfPolicy
        Write-Host "`t BookInPolicy:                  {$($RbaSettings.BookInPolicy)}"
        Write-Host "`t AllBookInPolicy:              "$RbaSettings.AllBookInPolicy
        Write-Host "`t RequestInPolicy:               {$($RbaSettings.RequestInPolicy)}"
        Write-Host "`t AllRequestInPolicy:           "$RbaSettings.AllRequestInPolicy
        Write-Host -ForegroundColor Red "Exiting script.";
        exit
    }
}

# ToDo check if workspace settings...

function InPolicyProcessing {
    # In-policy request processing
    Write-Host -ForegroundColor Yellow "`r`n  -----------------------------"
    Write-Host -ForegroundColor Yellow "  In-Policy request processing:"
    Write-Host -ForegroundColor Yellow "  -----------------------------"

    if ($RbaSettings.BookInPolicy.Count -eq 0) {
        Write-Host "`t BookInPolicy:                     {$($RbaSettings.BookInPolicy)}"
    } else {
        Write-Host "`t BookInPolicy:                     These $($RbaSettings.BookInPolicy.count) accounts do not require the delegate approval."
        foreach ($BIPUser in $RbaSettings.BookInPolicy) { Write-Host " `t `t $BIPUser " }
    }
    Write-Host "`t AllBookInPolicy:                 "$RbaSettings.AllBookInPolicy
    Write-Host "`t RequestInPolicy:                  {$($RbaSettings.RequestInPolicy)}"
    Write-Host "`t AllRequestInPolicy:              "$RbaSettings.AllRequestInPolicy
    Write-Host

    if ($RbaSettings.AllBookInPolicy -eq $true) {
        Write-Host "- The RBA will process (auto-book) all in-policy meetings. (Default)"
        Write-Host "`t Note - This supersedes the all of the other in-policy setting."
    } else {
        if ($RbaSettings.BookInPolicy.Count -gt 0) {
            Write-Host "- The RBA will process (auto-book / accept) in-policy requests from this list of Users:"
            foreach ($BIPUser in $RbaSettings.BookInPolicy) { Write-Host " `t `t $BIPUser" }
        }

        Write-Host "- RBA will forward all in-policy meetings to the resource delegates."

        if ($RbaSettings.AllRequestInPolicy -eq $true) {
            Write-Host "- All users are allowed to submit in-policy requests to the resource delegates."
        } else {
            Write-Host "- Users are not allowed to submit request for this resource. (Default)"
        }
    }
}

# Out-of-policy request processing
function OutOfPolicyProcessing {
    Write-Host -ForegroundColor DarkYellow "`r`n  ---------------------------------"
    Write-Host -ForegroundColor DarkYellow "  Out-of-Policy request processing:"
    Write-Host -ForegroundColor DarkYellow "  ---------------------------------"
    if ($RbaSettings.RequestOutOfPolicy.Count -gt 0) {
        Write-Host "`t RequestOutOfPolicy:           These {$($RbaSettings.RequestOutOfPolicy.Count)} accounts are allowed to submit out-of-policy requests (that require approval by a resource delegate)."
        foreach ($OutOfPolicyUser in $RbaSettings.RequestOutOfPolicy) { Write-Host "`t `t $OutOfPolicyUser" }
    } else {
        Write-Host "`t RequestOutOfPolicy:               {$($RbaSettings.RequestOutOfPolicy)}"
    }
    Write-Host "`t AllRequestOutOfPolicy:           "$RbaSettings.AllRequestOutOfPolicy

    if ($RbaSettings.AllRequestOutOfPolicy -eq $true ) {
        Write-Host "- All users are allowed to submit out-of-policy requests to the resource mailbox. Out-of-policy requests require approval by a resource mailbox delegate."

        if ($RbaSettings.RequestOutOfPolicy.count -gt 0) {
            Write-Host -ForegroundColor Red "Warning: The users that are listed in BookInPolicy are overridden by the AllRequestOutOfPolicy as everyone can submit out of policy requests."
        }
    } else {
        if ($RbaSettings.RequestOutOfPolicy.count -eq 0) {
            Write-Host "- No User can submit out-of-policy requests to this resource mailbox. (Default)"
        } else {
            Write-Host "- Only the users in the RequestOutOfPolicy list can submit out-of-policy requests to this resource mailbox."
        }
    }
}

# RBA Delegate Settings
function RBADelegateSettings {
    Write-Host "`r`n=========================";
    Write-Host "Resource Delegate Settings";
    Write-Host "`=========================";
    # Write-Host "`r`n The Resource Delegates are able accept or reject the meeting requests forwarded to them by the RBA.";

    if ($RbaSettings.ResourceDelegates.Count -eq 0) {
        Write-Host "`t ResourceDelegates:               "$RbaSettings.ResourceDelegates
    } else {
        Write-Host "`t ResourceDelegates:               $($RbaSettings.ResourceDelegates.Count) Resource Delegate`(s`) have been configured."
        foreach ($RDUser in $RbaSettings.ResourceDelegates) { Write-Host " `t `t $RDUser" }
    }

    Write-Host "`t AddNewRequestsTentatively:       "$RbaSettings.AddNewRequestsTentatively
    Write-Host "`t ForwardRequestsToDelegates:      "$RbaSettings.ForwardRequestsToDelegates
    Write-Host

    if ($RbaSettings.ResourceDelegates.Count -gt 0) {
        if ($RbaSettings.AddNewRequestsTentatively -eq $true) {
            Write-Host "In-policy meetings will be marked tentative and the meeting request will be sent to the Resource Delegates to be accepted or rejected. Default"
        } else {
            Write-Host -ForegroundColor Yellow "Warning: Only existing calendar items will be updated by the Calendar Attendant."
        }

        if ($RbaSettings.ForwardRequestsToDelegates -eq $true ) {
            if ($RbaSettings.AllBookInPolicy -eq $true) {
                Write-Host -ForegroundColor Yellow "Warning: Delegate will not receive any In Policy requests as they will be AutoApproved."
            } elseif ($RbaSettings.BookInPolicy.Count -gt 0 ) {
                Write-Host -ForegroundColor Yellow "Warning: Delegate will not receive from users in the BookInPolicy."
                foreach ($BIPUser in $RbaSettings.BookInPolicy) { Write-Host  -ForegroundColor Yellow " `t `t $BIPUser " }
            }

            if ($RbaSettings.AllRequestOutOfPolicy -eq $false) {
                if ($RbaSettings.RequestOutOfPolicy.Count -eq 0 ) {
                    Write-Host -ForegroundColor Yellow "Warning: Delegate will not receive any Out of Policy requests as they will all be AutoDenied."
                } else {
                    Write-Host -ForegroundColor Yellow "Warning: Delegate will only receive any Out of Policy requests from the below list of users."
                    foreach ($OutOfPolicyUser in $RbaSettings.RequestOutOfPolicy) { Write-Host "`t `t $OutOfPolicyUser" }
                }
            } else {
                Write-Host -ForegroundColor Yellow "Note: All users can send Out of Policy requests to be approved by the Resource Delegates."
            }
        }
    } elseif ($RbaSettings.ForwardRequestsToDelegates -eq $true `
            -and $RbaSettings.AllBookInPolicy -ne $true ) {
        Write-Host -ForegroundColor Red "Warning: ForwardRequestsToDelegates is true but there are no Delegates."
    }
}

# RBA PostProcessing Steps
function RBAPostProcessing {
    Write-Host -ForegroundColor Cyan "`r`n=====================";
    Write-Host -ForegroundColor Cyan "PostProcessing Steps";
    Write-Host -ForegroundColor Cyan "=====================`r`n";
    Write-Host -ForegroundColor Cyan "The RBA will format the meeting based on the following settings."

    #    Write-Host -ForegroundColor Cyan "`r`n`t RBA PostProcessing Steps";
    #    Write-Host -ForegroundColor Cyan "`t ------------------------------------   ---------------------------------";
    Write-Host -ForegroundColor Cyan "`t AddOrganizerToSubject:                "$RbaSettings.AddOrganizerToSubject
    Write-Host -ForegroundColor Cyan "`t DeleteSubject:                        "$RbaSettings.DeleteSubject
    Write-Host -ForegroundColor Cyan "`t DeleteComments (Meeting body):        "$RbaSettings.DeleteComments
    Write-Host -ForegroundColor Cyan "`t DeleteAttachments:                    "$RbaSettings.DeleteAttachments
    Write-Host -ForegroundColor Cyan "`t RemovePrivateProperty:                "$RbaSettings.RemovePrivateProperty
    Write-Host -ForegroundColor Cyan "`t DeleteNonCalendarItems:               "$RbaSettings.DeleteNonCalendarItems
    Write-Host -ForegroundColor Cyan "`t RemoveForwardedMeetingNotifications:  "$RbaSettings.RemoveForwardedMeetingNotifications
    Write-Host -ForegroundColor Cyan "`t RemoveCanceledMeetings:               "$RbaSettings.RemoveCanceledMeetings
    Write-Host -ForegroundColor Cyan "`t EnableAutoRelease:                    "$RbaSettings.EnableAutoRelease
    Write-Host -ForegroundColor Cyan "`t AddAdditionalResponse:                "$RbaSettings.AddAdditionalResponse
}

# RBA Verbose PostProcessing Steps
function VerbosePostProcessing {
    Write-Verbose -ForegroundColor Cyan "`t AdditionalResponse:                   "$RbaSettings.AdditionalResponse

    $RbaFormattingString = ""
    if ($RbaSettings.DeleteSubject -eq $true) {
        if ($RbaSettings.AddOrganizerToSubject -eq $true) {
            $RbaFormattingString += "The RBA will delete the subject and add the organizer to the subject. (Default)"
        } else {
            $RbaFormattingString += "The RBA will delete the subject. Consider adding the organizer to the subject with the AddOrganizerToSubject property."
        }
    } elseif ($RbaSettings.AddOrganizerToSubject -eq $true) {
        $RbaFormattingString += "The RBA will add the organizer to the subject."
    } else {
        $RbaFormattingString += "The RBA will not change the subject property."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.DeleteComments -eq $true) {
        $RbaFormattingString += "The RBA will remove the meeting body. (Default)"
    } else {
        $RbaFormattingString += "The RBA will not change the meeting body."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.DeleteAttachments -eq $true) {
        $RbaFormattingString += "The RBA will remove all Attachments. (Default)"
    } else {
        $RbaFormattingString += "The RBA will not change the Attachments."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.RemovePrivateProperty -eq $true) {
        $RbaFormattingString += "The RBA will remove the private property. (Default)"
    } else {
        $RbaFormattingString += "The RBA will not change the private property."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.DeleteNonCalendarItems -eq $true) {
        $RbaFormattingString += "The RBA will remove all non-calendar items sent to the resource mailbox. (Default)"
    } else {
        $RbaFormattingString += "The RBA will not remove the non-calendar items."
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.RemoveForwardedMeetingNotifications -eq $true) {
        $RbaFormattingString += "The RBA will remove all forwarded meeting notifications."
    } else {
        $RbaFormattingString += "The RBA will not change the forwarded meeting notifications. (Default)"
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.RemoveCanceledMeetings -eq $true) {
        $RbaFormattingString += "The RBA will remove all canceled meetings."
    } else {
        $RbaFormattingString += "The RBA will not change the canceled meetings. (Default)"
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.EnableAutoRelease -eq $true) {
        $RbaFormattingString += "The RBA will automatically release the meeting if the resource is available."
    } else {
        $RbaFormattingString += "The RBA will not automatically release the meeting. (Default)"
    }
    $RbaFormattingString += [environment]::Newline

    if ($RbaSettings.AddAdditionalResponse -eq $true -and $RbaSettings.AdditionalResponse.Length -gt 0) {
        $RbaFormattingString += "The RBA will add the following additional response to the meeting: " +
        $RbaSettings.AdditionalResponse + "."
    } else {
        $RbaFormattingString += "The RBA will not add the additional response."
    }
    $RbaFormattingString += [environment]::Newline

    Write-Verbose $RbaFormattingString
}

#Add information about RBA logs.
function RBAPostScript {
    Write-Host;
    Write-Host "If more information is needed about this resource mailbox, please look at the RBA logs to
        see how the system proceed the meeting request.";
    Write-Host -ForegroundColor Yellow "`t Export-MailboxDiagnosticLogs $Identity -ComponentName RBA";
    Write-Host;
    Write-Host "`n`rIf you found an error with this script or a misconfigured RBA cases that this should cover,
         send mail to Shanefe@microsoft.com";
}

# Call the Functions in this order:
ValidateMailbox
GetCalendarProcessing
EvaluateCalProcessing
ProcessingLogic
RBACriteria
RBACriteriaExtra
RBAProcessing
InPolicyProcessing
OutOfPolicyProcessing
RBADelegateSettings
RBAPostProcessing
VerbosePostProcessing
RBAPostScript
