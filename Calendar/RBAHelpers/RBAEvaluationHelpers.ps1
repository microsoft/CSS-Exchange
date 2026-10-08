# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-RbaCalendarProcessingEvaluation {

    if ($RbaSettings.AutomateProcessing -ne "AutoAccept") {
        Write-Host -ForegroundColor Red "Error: AutomateProcessing is not set to AutoAccept. RBA will not work as configured."
        Write-Host -ForegroundColor Red "Error: For RBA to do anything AutomateProcessing must be set to AutoAccept."
        Write-Host -ForegroundColor Red "Error: AutomateProcessing is set to $($RbaSettings.AutomateProcessing)."
        Write-Host -ForegroundColor Yellow "Use 'Set-CalendarProcessing -Identity $Identity -AutomateProcessing AutoAccept' to set AutomateProcessing to AutoAccept."
        Write-Host -ForegroundColor Red "Continuing collection and reporting."
    } else {
        Write-Host -ForegroundColor Green "AutomateProcessing is set to AutoAccept. RBA will analyze the meeting request."
    }
}

function Write-RbaProcessingLogic {
    Write-RbaDashLineBox @("RBA Processing Logic") -DashChar =
    @"
        The RBA first evaluates a request against all the policy configuration constraints assigned in the calendar
        processing object for the resource mailbox.

        This will result in the request either being in-policy or out-of-policy. The RBA then reads the recipient well
        values to determine where to send or handle in-policy requests and out-of-policy requests.

        Lastly if the Request is accepted, the PostProcessing steps will be performed.
"@
}

function Write-RbaPolicyCriteria {
    Write-RbaDashLineBox @("Policy Configuration") -Color Cyan -DashChar =

    Write-Host " The following criteria are used to determine if a meeting request is in-policy or out-of-policy. "
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
    `t EnforceSchedulingHorizon:       $($RbaSettings.EnforceSchedulingHorizon)
"@
    Write-Host -NoNewline "`r`nIf all the above criteria are met, the request is "
    Write-Host -ForegroundColor Yellow -NoNewline "In-Policy."
    Write-Host -NoNewline "`r`nIf any of the above criteria are not met, the request is "
    Write-Host -ForegroundColor DarkYellow -NoNewline  "Out-of-Policy."
    Write-Host

    # RBA processing settings Verbose Output
    $RBACriteriaExtra = ""

    if ($RbaSettings.AllowConflicts -eq $true) {
        $RBACriteriaExtra += "Conflicts are accepted without percentage or count limits. This is required for Workspaces.`r`n"
    } elseif ($RbaSettings.ConflictPercentageAllowed -eq 0 `
            -and $RbaSettings.MaximumConflictInstances -eq 0) {
        $RBACriteriaExtra += "No conflicts are allowed.`r`n"
    } else {
        $RBACriteriaExtra += "For recurring meetings, the series is declined when conflicts exceed either $($RbaSettings.ConflictPercentageAllowed)% of instances or $($RbaSettings.MaximumConflictInstances) instances; otherwise, the conflicting instances are declined.`r`n"
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

    if ($RbaSettings.EnforceSchedulingHorizon -eq $true) {
        $RBACriteriaExtra += "Recurring series that extend beyond the $($RbaSettings.BookingWindowInDays)-day booking window are declined.`r`n"
    } else {
        $RBACriteriaExtra += "Recurring series that start within the $($RbaSettings.BookingWindowInDays)-day booking window can be accepted, but occurrences beyond the window are removed.`r`n"
    }

    if ($RbaSettings.ProcessExternalMeetingMessages -eq $true) {
        $RBACriteriaExtra += "External meeting requests will be evaluated.`r`n"
    } else {
        $RBACriteriaExtra += "RBA will reject all External meeting requests.`r`n"
    }

    $RBACriteriaExtra += "The resource booking window is $($RbaSettings.BookingWindowInDays) days; 0 means today.`r`n"

    Write-Verbose $RBACriteriaExtra
}

function Write-RbaProcessingValidation {
    Write-RbaDashLineBox @("Policy Processing:") -DashChar =

    # check for False null False null False null - RBA is configured to do nothing.
    if ($RbaSettings.RequestOutOfPolicy.Count -eq 0 `
            -and $RbaSettings.AllRequestOutOfPolicy -eq $false `
            -and $RbaSettings.BookInPolicy.Count -eq 0 `
            -and $RbaSettings.AllBookInPolicy -eq $false `
            -and $RbaSettings.RequestInPolicy.Count -eq 0 `
            -and $RbaSettings.AllRequestInPolicy -eq $false ) {
        Write-Host -ForegroundColor Red "`r`n Error: The RBA isn't configured to process items. No RBA processing of Meeting Requests will occur."
        Write-Host -ForegroundColor Red "Consider configuring the properties below to process all requests.  (Default is null, True, null, False, null, True)."
        Write-Host
        Write-Host "`t RequestOutOfPolicy:            {$($RbaSettings.RequestOutOfPolicy)}"
        Write-Host "`t AllRequestOutOfPolicy:        "$RbaSettings.AllRequestOutOfPolicy
        Write-Host "`t BookInPolicy:                  {$($RbaSettings.BookInPolicy)}"
        Write-Host "`t AllBookInPolicy:              "$RbaSettings.AllBookInPolicy
        Write-Host "`t RequestInPolicy:               {$($RbaSettings.RequestInPolicy)}"
        Write-Host "`t AllRequestInPolicy:           "$RbaSettings.AllRequestInPolicy
        Write-Host -ForegroundColor Red "Continuing collection and reporting."
    }
}

function Write-RbaRecipientList {
    param (
        [Parameter(Mandatory)]
        [string[]]$MBList
    )
    foreach ($User in $MBList) {
        try {
            # MS Support will error as we need the Organization to process from CN
            $Org = $Identity.Split('@')[1]

            if ($null -ne $Org) {
                $recipient = Get-Recipient -Identity $User -Organization $Org -ErrorAction Stop
            } else {
                $recipient = Get-Recipient -Identity $User -ErrorAction Stop
            }
            Write-Host " `t `t [$($recipient.DisplayName)] -- $($recipient.PrimarySmtpAddress)"
        } catch {
            Write-Warning "Unable to resolve recipient '$User': $($_.Exception.Message)"
            Write-Host " `t `t [$User]"
        }
    }
}

function Write-RbaInPolicyProcessing {
    # In-policy request processing
    Write-RbaDashLineBox @("  In-Policy request processing:") -Color Yellow

    if ($RbaSettings.BookInPolicy.Count -eq 0) {
        Write-Host "`t BookInPolicy:                     {$($RbaSettings.BookInPolicy)}"
    } else {
        Write-Host "`t BookInPolicy:                     These $($RbaSettings.BookInPolicy.count) accounts do not require the delegate approval."
        Write-RbaRecipientList -MBList $RbaSettings.BookInPolicy
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
            Write-RbaRecipientList -MBList $RbaSettings.BookInPolicy
        }

        Write-Host "- RBA will forward all in-policy meetings to the resource delegates."

        if ($RbaSettings.AllRequestInPolicy -eq $true) {
            Write-Host "- All users are allowed to submit in-policy requests to the resource delegates."
        } else {
            Write-Host "- Users are not allowed to submit request for this resource. (Default)"
        }
    }
}

function Write-RbaOutOfPolicyProcessing {
    Write-RbaDashLineBox @("  Out-of-Policy request processing:") -Color DarkYellow
    if ($RbaSettings.RequestOutOfPolicy.Count -gt 0) {
        Write-Host "`t RequestOutOfPolicy:           These {$($RbaSettings.RequestOutOfPolicy.Count)} accounts are allowed to submit out-of-policy requests (that require approval by a resource delegate)."
        Write-RbaRecipientList -MBList $RbaSettings.RequestOutOfPolicy
    } else {
        Write-Host "`t RequestOutOfPolicy:               {$($RbaSettings.RequestOutOfPolicy)}"
    }
    Write-Host "`t AllRequestOutOfPolicy:           "$RbaSettings.AllRequestOutOfPolicy

    if ($RbaSettings.AllRequestOutOfPolicy -eq $true ) {
        Write-Host -ForegroundColor Yellow "Information: - All users are allowed to submit out-of-policy requests to the resource mailbox. Out-of-policy requests require approval by a resource mailbox delegate."

        if ($RbaSettings.RequestOutOfPolicy.count -gt 0) {
            Write-Host -ForegroundColor Magenta "Warning: The users that are listed in RequestOutOfPolicy are overridden by the AllRequestOutOfPolicy as everyone can submit out of policy requests."
        }
    } else {
        if ($RbaSettings.RequestOutOfPolicy.count -eq 0) {
            Write-Host "- No User can submit out-of-policy requests to this resource mailbox. (Default)"
        } else {
            Write-Host "- Only the users in the RequestOutOfPolicy list can submit out-of-policy requests to this resource mailbox."
        }
    }
}

function Write-RbaDelegateSettings {
    Write-RbaDashLineBox @("Resource Delegate Settings") -Color White

    if ($RbaSettings.ResourceDelegates.Count -eq 0) {
        Write-Host "`t ResourceDelegates:               "$RbaSettings.ResourceDelegates
    } else {
        Write-Host "`t ResourceDelegates:               $($RbaSettings.ResourceDelegates.Count) Resource Delegate`(s`) have been configured."
        Write-RbaRecipientList -MBList $RbaSettings.ResourceDelegates
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
                Write-Host -ForegroundColor White "Information: Delegate(s) will not receive any In Policy requests as they will be AutoApproved."
            } elseif ($RbaSettings.BookInPolicy.Count -gt 0 ) {
                Write-Host -ForegroundColor White "Information: Delegate(s) will not receive requests from users in the BookInPolicy as they will be AutoApproved."
                Write-RbaRecipientList -MBList $RbaSettings.BookInPolicy
            }

            if ($RbaSettings.AllRequestOutOfPolicy -eq $false) {
                if ($RbaSettings.RequestOutOfPolicy.Count -eq 0 ) {
                    Write-Host -ForegroundColor Yellow "Warning: Delegate(s) will not receive any Out of Policy requests as they will all be AutoDenied."
                } else {
                    Write-Host -ForegroundColor Yellow "Warning: Delegate(s) will only receive any Out of Policy requests from the below list of users."
                    Write-RbaRecipientList -MBList $RbaSettings.RequestOutOfPolicy
                }
            } else {
                Write-Host -ForegroundColor Yellow "Warning: All users can send Out of Policy requests to be approved by the Resource Delegates."
            }
        }
    } else {
        Write-Host -ForegroundColor Yellow "Warning: No Delegates are configured."
        if ($RbaSettings.ForwardRequestsToDelegates -eq $true -and
            $RbaSettings.AllBookInPolicy -ne $true ) {
            Write-Host -ForegroundColor Yellow "Warning: ForwardRequestsToDelegates is true but there are no Delegates."
        } if ($RbaSettings.RequestOutOfPolicy.Count -gt 0) {
            Write-Host -ForegroundColor Red "Error: Users are listed in RequestOutOfPolicy but there are no Delegates. - All Out of policy requests by these users will be Tentatively accepted."
        } if ($RbaSettings.AllRequestOutOfPolicy -eq $true) {
            Write-Host -ForegroundColor Red "Error: AllRequestOutOfPolicy is set but there are no Delegates. - All Out of policy requests will be Tentatively accepted."
        }
    }
}

function Write-RbaPostProcessing {
    Write-RbaDashLineBox @("PostProcessing Setup") -Color Cyan -DashChar =
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

function Write-RbaVerbosePostProcessing {
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

function Test-RbaWorkspace {
    Write-RbaDashLineBox @("Workspace Settings") -Color White
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

function Test-RbaRoomListSettings {
    Write-RbaDashLineBox @("Room List Settings") -Color White
    Write-Host -ForegroundColor White "`tThe new Room Finder uses the City and other properties to help users find the right room for their meeting."
    Write-Host -ForegroundColor White "`tTags can be used to list features of this room (i.e. Projector, etc.) so that users can narrow down their search for conference rooms."

    Write-Host -ForegroundColor White "`tLearn more at " -NoNewline
    Write-Host -ForegroundColor Yellow "https://learn.microsoft.com/en-us/outlook/troubleshoot/calendaring/configure-room-finder-rooms-workspaces`n"

    if ([string]::IsNullOrEmpty($Place.Localities)) {
        ## validate Localities
        Write-Host -ForegroundColor Yellow "`tWarning: Resource [$Identity] is not part of any Room Lists."
        Write-Host -ForegroundColor Yellow "`tWarning: Adding this resource to a Room Lists can take 24 hours to be fully propagated."
    }

    $requiredProperties = @("City", "Floor", "Capacity")

    foreach ($prop in $requiredProperties) {
        if ([string]::IsNullOrEmpty($script:Place.$prop)) {
            $requiredPropertiesMissing = $true
            Write-Host -ForegroundColor Magenta "`tWarning: Required Property '$prop' is not set for $Identity. RoomList functionality may not work as expected."
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

    Write-Host -ForegroundColor White "`r`n`t New Room List commonly populated information:"
    Write-Host -ForegroundColor White "`t ----------------------------------------- "
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
    `t --Tags describing features and equipment in the Room
    `t Tags:                $($script:Place.Tags)
    `t --This room belongs to the following Room Lists (Localities).
    `t Localities:          $($Place.Localities)

    `t To update any of the above information, run 'Set-Place $Identity -<Property> <Value>'.
    `t For more information on this command, see
"@
    Write-Host -ForegroundColor Yellow "`t https://learn.microsoft.com/en-us/powershell/module/exchange/set-place?view=exchange-ps"
    Write-Host
}

function Write-RbaDashLineBox {
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
    $dashLine = [string]::Empty
    1..$highLineLength | ForEach-Object { $dashLine += $DashChar }
    Write-Host
    Write-Host -ForegroundColor $Color $dashLine
    $Line | ForEach-Object { Write-Host -ForegroundColor $Color $_ }
    Write-Host -ForegroundColor $Color $dashLine
    Write-Host
}

function Invoke-RbaEvaluation {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ScriptBlock]$Action
    )

    try {
        & $Action
    } catch {
        $errorInfo = ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_
        $script:evaluationErrors.Add([PSCustomObject]@{
                evaluation            = $Name
                message               = $errorInfo.message
                exceptionType         = $errorInfo.exceptionType
                category              = $errorInfo.category
                fullyQualifiedErrorId = $errorInfo.fullyQualifiedErrorId
                innerExceptionMessage = $errorInfo.innerExceptionMessage
            })
        Write-Warning "$Name evaluation was skipped after an error: $($errorInfo.message)"
    }
}
