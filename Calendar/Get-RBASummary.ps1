# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
    if ($null -eq $script:Mailbox) {
        Write-Host -ForegroundColor Red "Get-Mailbox returned null. Make sure you Import-Module ExchangeOnlineManagement and  Connect-ExchangeOnline. Exiting script.";
        exit;
    } else {
        if ($script:Mailbox.RecipientTypeDetails -ne "RoomMailbox" -and $script:Mailbox.RecipientTypeDetails -ne "EquipmentMailbox") {
            Write-Host -ForegroundColor Red "The mailbox is not a Room Mailbox / Equipment Mailbox. RBA will only work with these. Exiting script.";
            exit;
        }
        if ($script:Mailbox.ResourceType -eq "Workspace") {
            $script:Workspace = $true;
        }
        Write-Host -ForegroundColor Green "The mailbox is valid for RBA will work with."
    }

    # Get-Place does not cross forest boundaries so we will get an error here if we are not in the right forest.
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-Place -Identity $Identity"
    $script:Place = Get-Place $Identity

    if ($null -eq $script:Place) {
        Write-Error "Error: Get-Place returned Null for $Identity."
        Write-Host -ForegroundColor Red "Make sure you are running from the correct forest.  Get-Place does not cross forest boundaries."
        Write-Error "Exiting Script."
        exit;
    }

    Write-Host -ForegroundColor Yellow "For more information see https://learn.microsoft.com/en-us/powershell/module/exchange/get-mailbox?view=exchange-ps";
    Write-Host;
}

# Validate that there are not delegate rules that will block RBA functionality
function ValidateInboxRules {
    Write-Host "Checking for Delegate Rules that will block RBA functionality..."
    Write-Host -NoNewline "Running : "; Write-Host -ForegroundColor Cyan "Get-InboxRule -mailbox $Identity -IncludeHidden"
    $rules = Get-InboxRule -mailbox $Identity -IncludeHidden
    # Note as far as I can tell "Delegate Rule <GUID>" is not localized.
    if ($rules.Name -like "Delegate Rule*") {
        Write-Host -ForegroundColor Red "Error: There is a user style Delegate Rule setup on this resource mailbox. This will block RBA functionality. Please remove the rule via Remove-InboxRule cmdlet and re-run this script."
        Write-Host -NoNewline "Rule to look into: "
        Write-Host -ForegroundColor Red "$($rules.Name -like "Delegate Rule*")"
        Write-Host -ForegroundColor Red "Exiting script."
        exit;
    } elseif ($rules.Name -like "REDACTED-*") {
        Write-Host -ForegroundColor Yellow "Warning: No PII Access to MB so cannot check for Delegate Rules."
        Write-Host -ForegroundColor Red " --- Inbox Rules needs to be checked manually for any Delegate Rules. --"
        Write-Host -ForegroundColor Yellow "To gain PII access, Mailbox is located on $($mailbox.Database) on server $($mailbox.ServerName)"
        if ($rules.count -eq 1) {
            Write-Host -ForegroundColor Yellow "Warning: One rule has been found, which is likely the default Junk Mail rule."
            Write-Host -ForegroundColor Yellow "Warning: You should verify that this is not a Delegate Rule setup on this resource mailbox. Delegate rules will block RBA functionality. Please remove the rule via Remove-InboxRule cmdlet and re-run this script."
        } elseif ($rules.count -gt 1) {
            Write-Host -ForegroundColor Yellow "Warning: Multiple rules have been found on this resource mailbox. Only the Default Junk Mail rule is expected.  Depending on the rules setup, this may block RBA functionality."
            Write-Host -ForegroundColor Yellow "Warning: Please remove the rule(s) via Remove-InboxRule cmdlet and re-run this script."
        }
    } else {
        Write-Host -ForegroundColor Green "Delegate Rules check passes."
    }
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

    $RbaSettings | Format-List

    Write-Host -ForegroundColor Yellow "For more information on Set-CalendarProcessing see
                https://learn.microsoft.com/en-us/powershell/module/exchange/set-calendarprocessing?view=exchange-ps";
    Write-Host;
}

function EvaluateCalProcessing {

    if ($RbaSettings.AutomateProcessing -ne "AutoAccept") {
        Write-Host -ForegroundColor Red "Error: AutomateProcessing is not set to AutoAccept. RBA will not work as configured."
        Write-Host -ForegroundColor Red "Error: For RBA to do anything AutomateProcessing must be set to AutoAccept."
        Write-Host -ForegroundColor Red "Error: AutomateProcessing is set to $($RbaSettings.AutomateProcessing)."
        Write-Host -ForegroundColor Yellow "Use 'Set-CalendarProcessing -Identity $Identity -AutomateProcessing AutoAccept' to set AutomateProcessing to AutoAccept."
        Write-Host -ForegroundColor Red "Exiting script."
        exit;
    } else {
        Write-Host -ForegroundColor Green "AutomateProcessing is set to AutoAccept. RBA will analyze the meeting request."
    }
}

# RBA processing logic
function ProcessingLogic {
    Write-DashLineBoxColor @("RBA Processing Logic") -DashChar =
    @"
        The RBA first evaluates a request against all the policy configuration constraints assigned in the calendar
        processing object for the resource mailbox.

        This will result in the request either being in-policy or out-of-policy. The RBA then reads the recipient well
        values to determine where to send or handle in-policy requests and out-of-policy requests.

        Lastly if the Request is accepted, the PostProcessing steps will be performed.
"@
}

function RBACriteria {
    Write-DashLineBoxColor @("Policy Configuration") -Color Cyan -DashChar =

    Write-Host " The following criteria are used to determine if a meeting request is in-policy or out-of-policy. ";
    Write-Host -ForegroundColor Cyan @"
    `t Setting                          Value
    `t ------------------------------  -----------------------------
    `t AllowConflicts:                 $($RbaSettings.AllowConflicts)
    `t AllowDistributionGroup:         $($RbaSettings.AllowDistributionGroup)
    `t AllowMultipleResources:         $($RbaSettings.AllowMultipleResources)
    `t MaximumDurationInMinutes:       $($RbaSettings.MaximumDurationInMinutes)
    `t MinimumDurationInMinutes:       $($RbaSettings.MinimumDurationInMinutes)
    `t AllowRecurringMeetings:         $($RbaSettings.AllowRecurringMeetings)
    `t ScheduleOnlyDuringWorkHours:    $($RbaSettings.ScheduleOnlyDuringWorkHours)
    `t ProcessExternalMeetingMessages: $($RbaSettings.ProcessExternalMeetingMessages)
    `t BookingWindowInDays:            $($RbaSettings.BookingWindowInDays)
    `t ConflictPercentageAllowed:      $($RbaSettings.ConflictPercentageAllowed)
    `t MaximumConflictInstances:       $($RbaSettings.MaximumConflictInstances)
    `t MaximumConflictPercentage:      $($RbaSettings.MaximumConflictPercentage)
    `t EnforceSchedulingHorizon:       $($RbaSettings.EnforceSchedulingHorizon)
    `t SchedulingHorizonInDays:        $($RbaSettings.SchedulingHorizonInDays)
"@;
    Write-Host -NoNewline "`r`nIf all the above criteria are met, the request is "
    Write-Host -ForegroundColor Yellow -NoNewline "In-Policy."
    Write-Host -NoNewline "`r`nIf any of the above criteria are not met, the request is "
    Write-Host -ForegroundColor DarkYellow -NoNewline  "Out-of-Policy.";
    Write-Host;

    # RBA processing settings Verbose Output
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

# RBA processing settings
function RBAProcessingValidation {
    Write-DashLineBoxColor @("Policy Processing:") -DashChar =

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

function InPolicyProcessing {
    # In-policy request processing
    Write-DashLineBoxColor @("  In-Policy request processing:") -Color Yellow

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
    Write-DashLineBoxColor @("  Out-of-Policy request processing:") -Color DarkYellow
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
    Write-DashLineBoxColor @("Resource Delegate Settings") -Color White

    if ($RbaSettings.ResourceDelegates.Count -eq 0) {
        Write-Host "`t ResourceDelegates:               "$RbaSettings.ResourceDelegates
    } else {
        Write-Host "`t ResourceDelegates:               $($RbaSettings.ResourceDelegates.Count) Resource Delegate`(s`) have been configured."
        foreach ($RDUser in $RbaSettings.ResourceDelegates) { Write-Host " `t `t $RDUser" }
    }

    Write-Host "`t AddNewRequestsTentatively:       "$RbaSettings.AddNewRequestsTentatively
    Write-Host "`t ForwardRequestsToDelegates:      "$RbaSettings.ForwardRequestsToDelegates
    Write-Host

    # Check for known configuration issues to warn about:
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
    Write-DashLineBoxColor @("PostProcessing Setup") -Color Cyan -DashChar =
    Write-Host -ForegroundColor Cyan "The RBA will format the meeting based on the following settings."

    #    Write-Host -ForegroundColor Cyan "`r`n`t RBA PostProcessing Steps";
    #    Write-Host -ForegroundColor Cyan "`t ------------------------------------   ---------------------------------";
    Write-Host -ForegroundColor Cyan @"
    `t AddOrganizerToSubject:                $($RbaSettings.AddOrganizerToSubject)
    `t DeleteSubject:                        $($RbaSettings.DeleteSubject)
    `t DeleteComments (Meeting body):        $($RbaSettings.DeleteComments)
    `t DeleteAttachments:                    $($RbaSettings.DeleteAttachments)
    `t RemovePrivateProperty:                $($RbaSettings.RemovePrivateProperty)
    `t DeleteNonCalendarItems:               $($RbaSettings.DeleteNonCalendarItems)
    `t RemoveForwardedMeetingNotifications:  $($RbaSettings.RemoveForwardedMeetingNotifications)
    `t RemoveCanceledMeetings:               $($RbaSettings.RemoveCanceledMeetings)
    `t EnableAutoRelease:                    $($RbaSettings.EnableAutoRelease)
    `t AddAdditionalResponse:                $($RbaSettings.AddAdditionalResponse)
"@

    # Warning about the DeleteComments setting and Teams:
    if ($RbaSettings.DeleteComments -eq $true) {
        Write-Host -ForegroundColor Yellow "Warning: DeleteComments is set to true. This will remove the Teams information which is in the meeting body."
    }
}

# RBA Verbose PostProcessing Steps
function VerbosePostProcessing {
    Write-Verbose "`t`r`n AdditionalResponse:                   `r`n$($RbaSettings.AdditionalResponse)`r`n`r`n"

    $RbaFormattingString = "Description of the RBA Post Processing Steps:`r`n"
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
    Write-Host -ForegroundColor Yellow "`tExport-MailboxDiagnosticLogs $Identity -ComponentName RBA";
    Write-Host;
    Write-Host "`n`rIf you found an error with this script or a misconfigured RBA case that this should cover,
         send mail to Shanefe@microsoft.com";
}

function RBALogSummary {
    Write-DashLineBoxColor @("RBA Log Summary") -Color Blue -DashChar =

    $RBALog = (Export-MailboxDiagnosticLogs $Identity -ComponentName RBA).MailboxLog -split "`\n"

    Write-Host "`tFound $($RBALog.count) RBA Log entries in RBALog.  Summarizing Accepts, Declines, and Tentative meetings."

    if ($RBALog.count -gt 1) {
        $Starts = $RBALog | Select-String -Pattern "START -"

        if ($starts.count -gt 1) {
            $LastDate = ($Starts[0] -Split ",")[0].Trim()
            $FirstDate = ($starts[$($Starts.count) -1 ] -Split ",")[0].Trim();
            Write-Host "The RBA Log for $Identity shows the following:"
            Write-Host "`t $($starts.count) Processed events times between $FirstDate and $LastDate"
        }

        $AcceptLogs = $RBALog | Select-String -Pattern "Action:Accept"
        $DeclineLogs = $RBALog | Select-String -Pattern "Action:Decline"
        $TentativeLogs = $RBALog | Select-String -Pattern "Action:Tentative"

        if ($AcceptLogs.count -ne 0) {
            $LastAccept = ($AcceptLogs[0] -Split ",")[0].Trim()
            Write-Host "`t $($AcceptLogs.count) were Accepted between $FirstDate and $LastDate"
            Write-Host "`t`t with the last meeting Accepted on $LastAccept"
        }

        if ($TentativeLogs.count -ne 0) {
            $LastTentative = ($TentativeLogs[0] -Split ",")[0].Trim()
            Write-Host "`t $($TentativeLogs.count) Tentatively Accepted meetings between $FirstDate and $LastDate"
            Write-Host "`t`t with the last meeting Tentatively Accepted on $LastTentative"
        }

        if ($DeclineLogs.count -ne 0) {
            $LastDecline = ($DeclineLogs[0] -Split ",")[0].Trim()
            Write-Host "`t $($DeclineLogs.count) Declined meetings between $FirstDate and $LastDate"
            Write-Host "`t`t with the last meeting Declined on $LastDecline"
        }

        if ($AcceptLogs.count -eq 0 -and $TentativeLogs.count -eq 0 -and $DeclineLogs.count -eq 0) {
            Write-Host -ForegroundColor Red "`t No meetings were processed in the RBA Log."
        }
    } else {
        Write-Warning "No RBA Logs found.  Send a test meeting invite to the room and try again if this is a newly created room mailbox."
    }
}

#Validate Workspace settings
function ValidateWorkspace {
    Write-DashLineBoxColor @("Workspace Settings") -Color White
    Write-Host  -ForegroundColor White "`tIs Resource [$Identity] a Workspace: $(if ($script:Workspace) {"TRUE"} else {"False - Skipping additional Workspace Checks"})."

    if ($script:Workspace) {
        if ([string]::IsNullOrEmpty($script:Place.Capacity)) {
            Write-Host -ForegroundColor Red "`tError: Required Property 'Capacity' is not set for [$Identity]."
            Write-Host -ForegroundColor White "`tRun " -NoNewline
            Write-Host -ForegroundColor Yellow "Set-Place $Identity -Capacity <Value> " -NoNewline
            Write-Host -ForegroundColor White "to set the required properties on the resource."
        } else {
            Write-Host -ForegroundColor Green "`tRequired Property 'Capacity' is set to $($script:Place.Capacity)."
        }

        $requiredWorkspaceSettings = @("EnforceCapacity", "AllowConflicts")

        foreach ($prop in $requiredWorkspaceSettings) {
            if ($RbaSettings.$prop -ne $true) {
                $requiredWorkspaceSettingsMissing = $true
                Write-Host -ForegroundColor Red "`tError: Required Property '$prop' is not set to '$true' for $Identity."
                Write-Debug "[$Identity].[$prop] is set to: $($RbaSettings.$prop)."
            } else {
                Write-Host -ForegroundColor Green "`tRequired Property '$prop' is set to $($RbaSettings.$prop)."
            }
        }
        if ($requiredWorkspaceSettingsMissing) {
            Write-Host -ForegroundColor White "`tOne or more properties that are required to be true are not. Run the following cmdlet to set the required properties:"
            Write-Host -ForegroundColor White "`tRun " -NoNewline
            Write-Host -ForegroundColor Yellow "'Set-CalendarProcessing $Identity -EnforceCapacity `$True -AllowConflicts `$True' " -NoNewline
            Write-Host -ForegroundColor White "to set the properties to true."
        }

        Write-Host -ForegroundColor White "`tLearn more about configuring Workspaces at: " -NoNewline
        Write-Host -ForegroundColor Yellow "https://learn.microsoft.com/en-us/exchange/troubleshoot/outlook-issues/create-book-workspace-outlook"
    }
}

# Validate Setting for the New Room List functionality
function ValidateRoomListSettings {
    Write-DashLineBoxColor @("Room List Settings") -Color White
    Write-Host -ForegroundColor White "`tThe new Room Finder uses the City and other properties to help users find the right room for their meeting."
    Write-Host -ForegroundColor White "`tTags can be used to list features of this room (i.e. Projector, etc.) so that users can narrow down their search for conference rooms."

    Write-Host -ForegroundColor White "`tLearn more at " -NoNewline
    Write-Host -ForegroundColor Yellow "https://learn.microsoft.com/en-us/outlook/troubleshoot/calendaring/configure-room-finder-rooms-workspaces`n";

    if ([string]::IsNullOrEmpty($places.Localities)) {
        ## validate Localities
        Write-Host -ForegroundColor Yellow "`tWarning: Resource [$Identity] is not part of any Room Lists."
        Write-Host -ForegroundColor Yellow "`tWarning: Adding this resource to a Room Lists can take 24 hours to be fully propagated."
    }

    $requiredProperties = @("City", "Floor", "Capacity");

    foreach ($prop in $requiredProperties) {
        if ([string]::IsNullOrEmpty($script:Place.$prop)) {
            $requiredPropertiesMissing = $true
            Write-Host -ForegroundColor Red "`tError: Required Property '$prop' is not set for $Identity."
        } else {
            Write-Host -ForegroundColor Green "`tRequired Property '$prop' is set to $($script:Place.$prop)."
        }
    }

    if ($requiredPropertiesMissing) {
        Write-Host -ForegroundColor White "`tOne or more required properties are missing. Run the following cmdlet to set the required properties:"
        Write-Host -ForegroundColor White "`tRun " -NoNewline
        Write-Host -ForegroundColor Yellow "Set-Place $Identity -<prop> <Value> " -NoNewline
        Write-Host -ForegroundColor White "to set the required properties on the resource."
    }

    Write-Host -ForegroundColor White "`r`n`t New Room List commonly populated information:";
    Write-Host -ForegroundColor White "`t ----------------------------------------- ";
    Write-Host -ForegroundColor White @"
    `t Address Info
    `t Street:              $($script:Place.Street)
    `t City:                $($script:Place.City)
    `t State:               $($script:Place.State)
    `t PostalCode:          $($script:Place.PostalCode)
    `t CountryOrRegion:     $($script:Place.CountryOrRegion)
    `t Building Info
    `t Building:            $($script:Place.Building)
    `t Floor:               $($script:Place.Floor)
    `t Tags describing features and equipment in the Room
    `t Tags:                $($script:Place.Tags)

    `tTo update any of the above information, run 'Set-Place $Identity -<Property> <Value>'.
    `tFor more information on this command, see
"@
    Write-Host -ForegroundColor Yellow "`thttps://learn.microsoft.com/en-us/powershell/module/exchange/set-place?view=exchange-ps";
    Write-Host
}

function Get-DashLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length,
        [char] $DashChar = "-"
    )
    $dashLine = [string]::Empty
    1..$Length | ForEach-Object { $dashLine += $DashChar }
    return $dashLine
}

function Write-DashLineBoxColor {
    [CmdletBinding()]
    param(
        [string[]]$Line,
        [string] $Color = "White",
        [char] $DashChar = "-"
    )
    <#
        This is to simply create a quick and easy display around a line
        -------------------------------------
        Line                           Length
        Line                           Length
        -------------------------------------
        # Empty Line
    #>
    $highLineLength = 0
    $Line | ForEach-Object { if ($_.Length -gt $highLineLength) { $highLineLength = $_.Length } }
    $dashLine = Get-DashLine $highLineLength -DashChar $DashChar
    Write-Host
    Write-Host -ForegroundColor $Color $dashLine
    $Line | ForEach-Object { Write-Host -ForegroundColor $Color $_ }
    Write-Host -ForegroundColor $Color $dashLine
    Write-Host
}

# Call the Functions in this order:
ValidateMailbox
ValidateInboxRules
GetCalendarProcessing
EvaluateCalProcessing
ValidateWorkspace
ValidateRoomListSettings
ProcessingLogic
RBACriteria
RBAProcessingValidation
InPolicyProcessing
OutOfPolicyProcessing
RBADelegateSettings
RBAPostProcessing
VerbosePostProcessing
RBALogSummary
RBAPostScript
