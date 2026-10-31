# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Receiver calendar correlation, sharing-model classification, and synchronization diagnostics.

<#
.SYNOPSIS
    Displays key information from the receiver of the shared Calendar.
.DESCRIPTION
    This function displays key Calendar Receiver information.
.PARAMETER Identity
    The SMTP Address for Receiver of the shared calendar.
#>
function GetReceiverInformation {
    param (
        [string]$Receiver
    )

    if ($null -ne $script:FatalPrerequisiteFailure) {
        return
    }
    if (($null -eq $script:ReceiverMB) -and
        (-not (Resolve-SharingMailboxPrerequisite -Role Receiver -Identity $Receiver))) {
        return
    }

    #Standard Receiver information
    Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
    Write-Host -ForegroundColor Cyan "Key Receiver MB Information: [$Receiver]"
    Write-Host -ForegroundColor Cyan "Using prerequisite result from: 'Get-Mailbox $Receiver'"

    $script:ReceiverMB | Format-List DisplayName, Database, LitigationHoldEnabled, CalendarVersionStoreDisabled, CalendarRepairDisabled, RecipientType*

    Initialize-SharingOrganizationScope
    if ($script:SharingType -eq "InternalSharing") {
        Write-Host -ForegroundColor Yellow "Owner and Receiver are in the same OU."
        Write-Host -ForegroundColor Yellow "Owner and Receiver will be using Internal Sharing."
    } elseif ($script:SharingType -eq "ExternalSharing") {
        Write-Host -ForegroundColor Yellow "Owner and Receiver are in different OUs."
        Write-Host -ForegroundColor Yellow "Owner and Receiver will be using External Sharing or Publishing."
    } else {
        Write-Host -ForegroundColor Yellow "Owner or Receiver organization evidence is unavailable; internal versus external sharing is undetermined."
    }

    $OwnerCalendarName = $($script:OwnerMB.DisplayName)
    $selectedOwnerCalendarName = if ($script:OwnerCalendarSubfolderSelected) {
        $script:RequestedOwnerCalendarLeafName
    } else {
        $OwnerCalendarName
    }
    Write-Host -ForegroundColor Cyan "Receiver Calendar Folders (look for a copy of [$selectedOwnerCalendarName] Calendar):"
    Write-Host -ForegroundColor Cyan "Running: 'Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar'"
    $receiverFolderStatsAvailable = $true
    try {
        $CalStats = @(Invoke-SharingCollector -Name "ReceiverFolderStatistics" -Action {
                @(Get-MailboxFolderStatistics -Identity $Receiver -FolderScope Calendar -ErrorAction Stop)
            } -AllowNull)
    } catch {
        Write-Warning "Failed to retrieve Receiver Calendar folder statistics for [$Receiver]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Receiver calendar folders" -Issue "The receiver local-folder checks were unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxFolderStatistics with sufficient access, then compare Get-CalendarEntries and invite/accept logs." -Incomplete
        $CalStats = @()
        $receiverFolderStatsAvailable = $false
    }
    $CalStats | Format-Table -a FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
    $script:ReceiverFolderStatistics = @($CalStats)
    $receiverDuplicateStyleFolders = Get-DuplicateStyleCalendarFolders -FolderStatistics $CalStats
    if ($receiverDuplicateStyleFolders.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "Warning: Receiver calendar folders ending in a one- or two-digit numeric suffix may be duplicate folders."
        $receiverDuplicateStyleFolders |
            Format-Table -AutoSize FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
        Add-SharingFinding -RuleId "SHR214" -Status Detected -Area "Receiver calendar naming" -Evidence @{
            folderCount = $receiverDuplicateStyleFolders.Count
            folderNames = @($receiverDuplicateStyleFolders.Name)
        }
    }
    $receiverCalendarFolderNamesRedacted = @($CalStats | Where-Object -FilterScript {
            ([string]$_.Name -match "^\s*REDACTED-") -or
            ([string]$_.FolderPath -match "^\s*[\\/]*\s*REDACTED-")
        }).Count -gt 0
    if ($receiverCalendarFolderNamesRedacted) {
        Write-Host -ForegroundColor Yellow "Cannot read [$selectedOwnerCalendarName] calendar folder names. Get more access."
        $script:PIIAccess = $false
        Add-SharingFinding -RuleId "SHR201" -Status Detected -Area "PII access" -Evidence @{
            reason = "Receiver calendar folder names are redacted."
        }
    }
    $receiverDefaultCalendar = $CalStats |
        Where-Object -Property FolderType -EQ "Calendar" |
        Select-Object -First 1
    $ReceiverCalendarName = $receiverDefaultCalendar.Name
    foreach ($receiverNamedCalendar in @($CalStats)) {
        if (($null -ne $receiverNamedCalendar) -and (Test-SharingOutboxFolderName -Name $receiverNamedCalendar.Name)) {
            Register-SharingOutboxCalendar -Role Receiver -FolderName ([string]$receiverNamedCalendar.Name)
        }
    }
    if ($receiverFolderStatsAvailable -and ($null -eq $receiverDefaultCalendar)) {
        Add-SharingFinding -RuleId "SHR201" -Status NotEvaluated -Evidence @{
            reason = "The receiver default calendar could not be identified."
        }
    }

    if ($script:OwnerCalendarSubfolderSelected) {
        $requestedRelativeFolderPath = if (-not [string]::IsNullOrWhiteSpace($script:NormalizedOwnerCalendarFolderPath)) {
            $requestedFolderSegments = @($script:NormalizedOwnerCalendarFolderPath.TrimStart("\").Split("\"))
            @($requestedFolderSegments | Select-Object -Skip 1) -join "\"
        } else {
            $selectedOwnerCalendarName
        }
        $expectedReceiverFolderPath = if ([string]::IsNullOrWhiteSpace($requestedRelativeFolderPath)) {
            "\$ReceiverCalendarName"
        } else {
            "\$ReceiverCalendarName\$requestedRelativeFolderPath"
        }
        $matchingOwnerCalendars = @($CalStats | Where-Object -FilterScript {
                $calendarName = [string]$_.Name
                $receiverStatisticsPath = if ((-not [string]::IsNullOrWhiteSpace($ReceiverCalendarName)) -and
                    ($null -ne $_.FolderPath)) {
                    $receiverStatisticsIdentity = Get-CanonicalMailboxFolderIdentity `
                        -Mailbox $Receiver `
                        -CalendarRootName $ReceiverCalendarName `
                        -FolderPath $_.FolderPath.ToString()
                    $receiverStatisticsIdentity.Substring($receiverStatisticsIdentity.IndexOf(":") + 1)
                } else {
                    $null
                }
                [string]::Equals(
                    $calendarName,
                    $selectedOwnerCalendarName,
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                [string]::Equals(
                    $receiverStatisticsPath,
                    $expectedReceiverFolderPath,
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                $calendarName -match "^$([regex]::Escape($selectedOwnerCalendarName))\s+\(\d{1,2}\)$"
            })
        $exactSelectedOwnerCalendars = @($matchingOwnerCalendars | Where-Object -FilterScript {
                $receiverStatisticsPath = if ((-not [string]::IsNullOrWhiteSpace($ReceiverCalendarName)) -and
                    ($null -ne $_.FolderPath)) {
                    $receiverStatisticsIdentity = Get-CanonicalMailboxFolderIdentity `
                        -Mailbox $Receiver `
                        -CalendarRootName $ReceiverCalendarName `
                        -FolderPath $_.FolderPath.ToString()
                    $receiverStatisticsIdentity.Substring($receiverStatisticsIdentity.IndexOf(":") + 1)
                } else {
                    $null
                }
                ([string]::Equals(
                    $_.Name,
                    $selectedOwnerCalendarName,
                    [System.StringComparison]::OrdinalIgnoreCase)) -or
                ([string]::Equals(
                    $receiverStatisticsPath,
                    $expectedReceiverFolderPath,
                    [System.StringComparison]::OrdinalIgnoreCase))
            })
    } else {
        $ownerNames = @($Owner, $script:OwnerMB.DisplayName) | Where-Object -FilterScript {
            -not [string]::IsNullOrWhiteSpace($_)
        }
        $matchingOwnerCalendars = @($CalStats | Where-Object -FilterScript {
                $calendarName = $_.Name
                foreach ($ownerName in $ownerNames) {
                    if ($calendarName -like "$([WildcardPattern]::Escape($ownerName))*") {
                        return $true
                    }
                }
                return $false
            })
        $exactSelectedOwnerCalendars = @()
    }
    $script:ReceiverCalendarCandidates = $matchingOwnerCalendars
    if ($exactSelectedOwnerCalendars.Count -eq 1) {
        $script:ReceiverMatchedCalendar = $exactSelectedOwnerCalendars[0]
    } elseif ($matchingOwnerCalendars.Count -eq 1) {
        $script:ReceiverMatchedCalendar = $matchingOwnerCalendars[0]
    }

    # Warning if there are multiple copies of the Owner Calendar in the Receiver Mailbox.
    if ($matchingOwnerCalendars.Count -gt 1) {
        if ($script:OwnerCalendarSubfolderSelected) {
            Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the selected Owner Calendar [$selectedOwnerCalendarName] in the Receiver Mailbox."
        } else {
            Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the Owner Calendar in the Receiver Mailbox."
        }
        Add-SharingFinding -Severity Warning -Area "Receiver calendar folders" -Issue "Multiple local folders may represent the owner's shared calendar." -Evidence "Matched [$($matchingOwnerCalendars.Count)] folders: [$($matchingOwnerCalendars.Name -join ', ')]." -RecommendedNextStep "Compare Get-CalendarEntries, folder identifiers, and invite/accept logs to identify the active pair-specific folder."
    }

    # Warning if the Receivers copy of the Calendar name is the default "Calendar".
    if (($CalStats.name -like "Calendar*").count -gt 1) {
        Write-Host -ForegroundColor Yellow "Warning: Receiver might have multiple Calendars named 'Calendar'."
        Write-Host -ForegroundColor Yellow "Warning: This can cause confusion with which calendar is being referenced."
        Add-SharingFinding -Severity Warning -Area "Receiver calendar naming" -Issue "The receiver has multiple calendars whose names begin with Calendar." -Evidence "Folder statistics returned more than one matching folder." -RecommendedNextStep "Use folder identifiers and Get-CalendarEntries to distinguish the shared folder during further diagnostics."
    }

    # Note $Owner has a * at the end in case we have had multiple setup for the same user, they will be appended with a " 1", etc.
    if ($matchingOwnerCalendars.Count -gt 0) {
        if ($script:OwnerCalendarSubfolderSelected) {
            Write-Host -ForegroundColor Green "Looks like we might have found a copy of the selected Owner Calendar [$selectedOwnerCalendarName] in the Receiver Mailbox."
        } else {
            Write-Host -ForegroundColor Green "Looks like we might have found a copy of the Owner Calendar in the Receiver Mailbox."
        }
        if ($script:SharingType -eq "InternalSharing") {
            Write-Host -ForegroundColor Green "This is a good indication the there is a Modern Sharing Relationship between these users."
            Write-Host -ForegroundColor Green "If the clients use the Modern Sharing or not is a up to the client."
            $script:ModernSharing = $true
        }

        $matchingOwnerCalendars | Format-Table -a FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
        if ($matchingOwnerCalendars.Count -gt 1) {
            Write-Host -ForegroundColor Yellow "Warning: Might have found more than one copy of the Owner Calendar in the Receiver Mailbox."
        }
    } else {
        if ($receiverCalendarFolderNamesRedacted) {
            Write-Verbose "Receiver calendar folder matching was skipped because folder names are redacted."
        } else {
            Write-Verbose "No receiver local folder was matched before calendar-entry evaluation."
        }
    }

    if ($script:SharingType -ne "ExternalSharing") {
        ProcessCalendarSharingAcceptLogs -Identity $Receiver
    } else {
        $script:CollectorStatuses["ReceiverAcceptLog"] = [PSCustomObject]@{ status = "NotApplicable"; error = $null }
    }
    if ($script:OwnerPublished) {
        ProcessInternetCalendarLogs -Identity $Receiver
    }
    if ($script:SharingType -eq "ExternalSharing") {
        Test-PublishedCalendarRelationship
    }

    if (($script:SharingType -like "InternalSharing") -or
        ($script:SharingType -like "ExternalSharing") -or
        ($script:SharingType -eq "Undetermined")) {
        # Validate Modern Sharing Status
        if ($script:PublishedSharing -or ($script:SharingType -eq "ExternalSharing")) {
            $script:CollectorStatuses["CalendarEntries"] = [PSCustomObject]@{ status = "NotApplicable"; error = $null }
        } elseif (Get-Command -Name Get-CalendarEntries -ErrorAction SilentlyContinue) {
            Write-Verbose "Found Get-CalendarEntries cmdlet. Running cmdlet: Get-CalendarEntries -Identity $Receiver"
            $calendarEntriesAvailable = $true
            try {
                $ReceiverCalEntries = @(Invoke-SharingCollector -Name "CalendarEntries" -Action {
                        @(Get-CalendarEntries -Identity $Receiver -ErrorAction Stop)
                    } -AllowNull)
            } catch {
                Write-Warning "Failed to retrieve calendar entries for [$Receiver]: $($_.Exception.Message)"
                Add-SharingFinding -Severity Warning -Area "Calendar entries" -Issue "The receiver calendar-entry check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-CalendarEntries with sufficient access and inspect the owner/receiver pair." -Incomplete
                $ReceiverCalEntries = @()
                $calendarEntriesAvailable = $false
            }

            Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
            $script:ReceiverCalendarEntries = @($ReceiverCalEntries)
            Write-Host "New Model Calendar Sharing Entries:"
            $ReceiverCalEntries | Where-Object SharingModelType -Like New | Format-Table CalendarGroupName, CalendarName, OwnerEmailAddress, SharingModelType, IsOrphanedEntry
            $pairNewEntries = @($ReceiverCalEntries | Where-Object -FilterScript {
                    ($_.SharingModelType -like "New") -and
                    (Test-SmtpAddressEqual -First $_.OwnerEmailAddress -Second $Owner) -and
                    ((-not $script:OwnerCalendarSubfolderSelected) -or
                    [string]::Equals(
                        $_.CalendarName,
                        $selectedOwnerCalendarName,
                        [System.StringComparison]::OrdinalIgnoreCase))
                })
            if ($pairNewEntries.Count -gt 0) {
                $pairCalendarNames = @($pairNewEntries.CalendarName | Where-Object -FilterScript {
                        -not [string]::IsNullOrWhiteSpace($_)
                    })
                $entryFolderMatches = @($CalStats | Where-Object -FilterScript {
                        $receiverFolderName = $_.Name
                        @($pairCalendarNames | Where-Object -FilterScript {
                                [string]::Equals(
                                    $receiverFolderName,
                                    $_,
                                    [System.StringComparison]::OrdinalIgnoreCase)
                            }).Count -gt 0
                    })
                if ($entryFolderMatches.Count -eq 1) {
                    $script:ReceiverMatchedCalendar = $entryFolderMatches[0]
                    $script:ReceiverCalendarCandidates = @($entryFolderMatches[0])
                    $script:ModernSharing = $script:SharingType -eq "InternalSharing"
                } elseif ($entryFolderMatches.Count -gt 1) {
                    $script:ReceiverCalendarCandidates = @($entryFolderMatches)
                }
            }
            foreach ($pairNewEntry in $pairNewEntries) {
                if ($pairNewEntry.IsOrphanedEntry -eq $true) {
                    Add-SharingFinding -Severity Error -Area "Calendar entries" -Issue "The pair-specific new-model calendar entry is orphaned." -Evidence "Calendar [$($pairNewEntry.CalendarName)] has IsOrphanedEntry=True." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics and inspect invite/accept processing."
                }
            }

            $pairOldEntries = @($ReceiverCalEntries | Where-Object -FilterScript {
                    ($_.SharingModelType -like "Old") -and
                    (Test-SmtpAddressEqual -First $_.OwnerEmailAddress -Second $Owner) -and
                    ((-not $script:OwnerCalendarSubfolderSelected) -or
                    [string]::Equals(
                        $_.CalendarName,
                        $selectedOwnerCalendarName,
                        [System.StringComparison]::OrdinalIgnoreCase))
                })
            $script:LegacyMapiSharing = (
                (-not $script:PublishedSharing) -and
                ($script:SharingType -eq "InternalSharing") -and
                $receiverFolderStatsAvailable -and
                (-not $receiverCalendarFolderNamesRedacted) -and
                $calendarEntriesAvailable -and
                ($pairNewEntries.Count -eq 0) -and
                ($pairOldEntries.Count -gt 0) -and
                ($script:ReceiverCalendarCandidates.Count -eq 0) -and
                ($null -eq $script:ReceiverMatchedCalendar))
            if ($script:LegacyMapiSharing) {
                $legacyEvidence = "A pair-specific Old calendar entry was found and no Modern local copy or New entry was identified."
                Write-Host -ForegroundColor Yellow "Warning: This internal relationship is using legacy MAPI calendar sharing."
                Write-Host -ForegroundColor Yellow "Microsoft recommends upgrading to Modern Calendar Sharing: https://support.microsoft.com/en-us/outlook/calendar-sharing-in-microsoft-365"
                Add-SharingFinding -RuleId "SHR324" -Status Detected -Area "Sharing model" -Evidence @{
                    reason             = $legacyEvidence
                    oldModelEntryCount = $pairOldEntries.Count
                }
            } elseif ($calendarEntriesAvailable -and ($pairNewEntries.Count -eq 0)) {
                Add-SharingFinding -Severity Error -Area "Calendar entries" -Issue "The pair-specific new-model calendar entry is missing." -Evidence "Get-CalendarEntries returned data but no New entry for owner [$Owner] and selected calendar [$selectedOwnerCalendarName]." -RecommendedNextStep "Inspect invite/accept logs and SharingPolicyAssistant or calendar-sharing validator diagnostics."
            }

            if ($pairOldEntries.Count -gt 0) {
                Write-Host -ForegroundColor Cyan "`r`r`r------------------------------------------------"
                Write-Host "Old Model Calendar Sharing Entries:"
                Write-Host "Consider upgrading these to the new model."
                $pairOldEntries | Format-Table CalendarGroupName, CalendarName, OwnerEmailAddress, SharingModelType, IsOrphanedEntry
            }
            if ($pairOldEntries.Count -gt 0) {
                Add-SharingFinding -Severity Warning -Area "Calendar entries" -Issue "A relevant old-model calendar entry exists for the expected owner." -Evidence "Get-CalendarEntries returned [$($pairOldEntries.Count)] Old entry(s) for [$Owner]." -RecommendedNextStep "Inspect invite/accept logs and SharingPolicyAssistant or calendar-sharing validator diagnostics before considering configuration changes."
            }
        } else {
            $script:CollectorStatuses["CalendarEntries"] = [PSCustomObject]@{ status = "Unavailable"; error = $null }
            Add-SharingFinding -Severity Warning -Area "Calendar entries" -Issue "Get-CalendarEntries is unavailable." -Evidence "The cmdlet was not found in the current session." -RecommendedNextStep "Run the check in a session where Get-CalendarEntries is available." -Incomplete
        }
        Test-PublishedCalendarRelationship

        if ($receiverFolderStatsAvailable -and
            ($null -eq $script:ReceiverMatchedCalendar)) {
            if ($receiverCalendarFolderNamesRedacted) {
                Add-SharingFinding -RuleId "SHR213" -Status NotEvaluated -Evidence @{
                    reason = "Receiver calendar folder names are redacted."
                }
            } elseif ($script:LegacyMapiSharing) {
                Write-Verbose "A local receiver folder is not expected for legacy MAPI calendar sharing."
            } elseif ($script:PublishedSharing) {
                Write-Verbose "Modern Sharing local-folder matching is not applicable to a published-calendar relationship."
            } elseif ($script:ReceiverCalendarCandidates.Count -gt 0) {
                Add-SharingFinding -RuleId "SHR213" -Status NotEvaluated -Evidence @{
                    reason         = "Candidate receiver folders were found, but the owner's local calendar could not be uniquely identified."
                    candidateCount = $script:ReceiverCalendarCandidates.Count
                }
            } else {
                if ($script:OwnerCalendarSubfolderSelected) {
                    Write-Host -ForegroundColor Yellow "Warning: Could not identify the selected Owner Calendar [$selectedOwnerCalendarName] in the Receiver Mailbox."
                } else {
                    Write-Host -ForegroundColor Yellow "Warning: Could not Identify the Owner's [$Owner] Calendar in the Receiver Mailbox."
                }
                Add-SharingFinding -Severity Error -Area "Receiver calendar folders" -Issue "A local folder for the expected owner was not found." -Evidence "Receiver calendar folder statistics and pair-specific calendar entries did not uniquely identify a folder for owner [$Owner]." -RecommendedNextStep "Inspect invite/accept logs and Get-CalendarEntries for the owner/receiver pair."
            }
        }

        if ((-not $script:LegacyMapiSharing) -and
            (-not $script:PublishedSharing)) {
            Compare-CalendarFolderStatistics `
                -OwnerFolderStatistics $script:OwnerSelectedCalendar `
                -ReceiverFolderStatistics $script:ReceiverMatchedCalendar
        }

        #Output key Modern Sharing information
        if (($script:PIIAccess) -and
            (-not $script:PublishedSharing) -and
            ($null -ne $script:OwnerMB) -and
            ($null -ne $script:ReceiverMatchedCalendar) -and
            (-not [string]::IsNullOrWhiteSpace($ReceiverCalendarName))) {
            if ($script:OwnerCalendarSubfolderSelected) {
                Write-Host "Checking selected Owner Calendar [$selectedOwnerCalendarName] in the Receiver Calendar:"
            } else {
                Write-Host "Checking for Owner copy Calendar in Receiver Calendar:"
            }
            Write-Host "Running cmdlet:"
            $receiverFolderIdentity = Get-ReceiverFolderIdentity -Receiver $Receiver -ReceiverCalendarName $ReceiverCalendarName -FolderPath $script:ReceiverMatchedCalendar.FolderPath.ToString()
            $script:ReceiverLocalCalendarFolderIdentity = $receiverFolderIdentity
            Write-Host -NoNewline -ForegroundColor Yellow "Get-MailboxCalendarFolder -Identity `"$receiverFolderIdentity`""
            $MBCalFolder = $null
            try {
                $MBCalFolder = Invoke-SharingCollector -Name "ReceiverLocalCalendarFolder" -Action {
                    Get-MailboxCalendarFolder -Identity $receiverFolderIdentity -ErrorAction Stop
                }
                $MBCalFolder | Format-List Identity, CreationTime, ExtendedFolderFlags, CalendarSharingFolderFlags, CalendarSharingOwnerSmtpAddress, CalendarSharingPermissionLevel, SharingLevelOfDetails, SharingPermissionFlags, LastAttemptedSyncTime, LastSuccessfulSyncTime, SharedCalendarSyncStartDate
                $script:ReceiverLocalCalendarFolder = $MBCalFolder
                Test-PublishedCalendarRelationship
                if ($script:PublishedSharing) { return }

                $receiverExtendedFolderFlags = ConvertTo-NormalizedFolderFlags -Flags @($MBCalFolder.ExtendedFolderFlags)
                if ($receiverExtendedFolderFlags -notcontains "SharedIn") {
                    Write-Host -ForegroundColor Yellow "Warning: The Receiver's copy of the Owner's Calendar is missing SharedIn."
                    Add-SharingFinding -Severity Error -Area "Receiver calendar flags" -Issue "The receiver local folder is missing SharedIn." -Evidence "ExtendedFolderFlags: [$($receiverExtendedFolderFlags -join ', ')]." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics for the pair."
                }
                if (($receiverExtendedFolderFlags -notcontains "ExchangeShareFolder") -and
                    ($null -eq (Get-SharingRuleNotApplicableReason -RuleId "SHR242"))) {
                    Write-Host -ForegroundColor Yellow "Warning: The Receiver's copy of the Owner's Calendar is missing ExchangeShareFolder."
                    Add-SharingFinding -Severity Error -Area "Receiver calendar flags" -Issue "The receiver local folder is missing ExchangeShareFolder." -Evidence "ExtendedFolderFlags: [$($receiverExtendedFolderFlags -join ', ')]." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics for the pair."
                }
                if (-not (Test-SmtpAddressEqual -First $MBCalFolder.CalendarSharingOwnerSmtpAddress -Second $Owner)) {
                    Write-Host -ForegroundColor Red "Warning: CalendarSharingOwnerSmtpAddress does not match the expected Owner."
                    Add-SharingFinding -Severity Error -Area "Receiver calendar owner" -Issue "CalendarSharingOwnerSmtpAddress does not match the expected owner." -Evidence "Expected [$Owner]; found [$($MBCalFolder.CalendarSharingOwnerSmtpAddress)]." -RecommendedNextStep "Compare Get-CalendarEntries and invite/accept logs, then run the calendar-sharing validator."
                }

                $lastAttemptedSyncTime = $MBCalFolder.LastAttemptedSyncTime -as [DateTime]
                $lastSuccessfulSyncTime = $MBCalFolder.LastSuccessfulSyncTime -as [DateTime]
                $attemptedSyncTimeUninitialized = Test-UninitializedCalendarDate -Value $lastAttemptedSyncTime
                $successfulSyncTimeUninitialized = Test-UninitializedCalendarDate -Value $lastSuccessfulSyncTime
                $syncStartDate = $MBCalFolder.SharedCalendarSyncStartDate -as [DateTime]
                $syncStartDateUninitialized = Test-UninitializedCalendarDate -Value $syncStartDate
                $neverSynchronized = $successfulSyncTimeUninitialized
                if ($null -eq $lastSuccessfulSyncTime) {
                    Add-SharingFinding -RuleId "SHR403" -Status NotEvaluated -Evidence @{
                        reason = "LastSuccessfulSyncTime is unavailable or could not be interpreted as a date."
                    }
                }

                if ($neverSynchronized) {
                    if ($attemptedSyncTimeUninitialized) {
                        Write-Host -ForegroundColor Red "The selected receiver calendar appears never to have synchronized. LastAttemptedSyncTime and LastSuccessfulSyncTime contain uninitialized year-1 values."
                    } else {
                        Write-Host -ForegroundColor Red "This calendar has never successfully synchronized (LastSuccessfulSyncTime is uninitialized). The most recent attempt was at [$lastAttemptedSyncTime]."
                    }
                    Add-SharingFinding -RuleId "SHR403" -Status Detected -Area "Periodic synchronization" -Evidence @{
                        attemptedSyncTimeUninitialized  = $attemptedSyncTimeUninitialized
                        lastAttemptedSyncTime           = $(if ($attemptedSyncTimeUninitialized -or ($null -eq $lastAttemptedSyncTime)) { $null } else { $lastAttemptedSyncTime.ToString("o") })
                        successfulSyncTimeUninitialized = $successfulSyncTimeUninitialized
                        syncStartDateUninitialized      = $syncStartDateUninitialized
                    }
                    foreach ($ruleId in @("SHR400", "SHR402", "SHR410", "SHR411", "SHR412")) {
                        Add-SharingFinding -RuleId $ruleId -Status NotApplicable -Evidence @{
                            reason = "The selected receiver calendar has never successfully synchronized."
                        }
                    }
                } else {
                    if ($attemptedSyncTimeUninitialized) {
                        $lastAttemptedSyncTime = $null
                    }
                    $bothSyncTimesStale = ($null -ne $lastAttemptedSyncTime) -and
                    ($null -ne $lastSuccessfulSyncTime) -and
                    ($lastAttemptedSyncTime -lt (Get-Date).AddHours(-24)) -and
                    ($lastSuccessfulSyncTime -lt (Get-Date).AddHours(-24))
                    if ($bothSyncTimesStale) {
                        Write-Host -ForegroundColor Yellow "Warning: Periodic calendar synchronization is stale; both sync timestamps are older than 24 hours."
                        Add-SharingFinding -Severity Warning -Area "Periodic synchronization" -Issue "Periodic synchronization is stale and the assistant may not be running." -Evidence "LastAttemptedSyncTime=[$lastAttemptedSyncTime]; LastSuccessfulSyncTime=[$lastSuccessfulSyncTime]." -RecommendedNextStep "Inspect SharingSyncAssistant logs for the receiver."
                    } elseif (($null -ne $lastAttemptedSyncTime) -and
                        ($null -ne $lastSuccessfulSyncTime) -and
                        ($lastAttemptedSyncTime -eq $lastSuccessfulSyncTime)) {
                        Write-Host -ForegroundColor Green "The Receiver's copy of the Owner's Calendar appears to be syncing properly (LastAttemptedSyncTime = LastSuccessfulSyncTime)."
                    } elseif (($null -eq $lastAttemptedSyncTime) -or ($null -eq $lastSuccessfulSyncTime)) {
                        Write-Host -ForegroundColor Yellow "Warning: Periodic synchronization timestamps are incomplete, so sync state is indeterminate."
                        Add-SharingFinding -Severity Warning -Area "Periodic synchronization" -Issue "Periodic synchronization timestamps are incomplete." -Evidence "LastAttemptedSyncTime=[$($MBCalFolder.LastAttemptedSyncTime)]; LastSuccessfulSyncTime=[$($MBCalFolder.LastSuccessfulSyncTime)]." -RecommendedNextStep "Inspect SharingSyncAssistant logs and rerun the folder diagnostics." -Incomplete
                    } elseif ($lastAttemptedSyncTime -ne $lastSuccessfulSyncTime) {
                        Write-Host -ForegroundColor Red "Warning: The most recent periodic synchronization attempt was not successful (LastAttemptedSyncTime differs from LastSuccessfulSyncTime)."
                        Add-SharingFinding -Severity Error -Area "Periodic synchronization" -Issue "A recent periodic synchronization attempt failed." -Evidence "LastAttemptedSyncTime=[$lastAttemptedSyncTime]; LastSuccessfulSyncTime=[$lastSuccessfulSyncTime]." -RecommendedNextStep "Inspect SharingSyncAssistant logs; use CDL only if meeting-level synchronization requires investigation."
                    }
                }

                if ($null -ne (Get-SharingRuleNotApplicableReason -RuleId "SHR413")) {
                    Write-Verbose "Internal REST synchronization start-date checks do not apply to this relationship."
                } elseif (($null -eq $MBCalFolder.SharedCalendarSyncStartDate) -or $syncStartDateUninitialized) {
                    Write-Host -ForegroundColor Yellow "Warning: The Receiver's copy of the Owner's Calendar does not have an initialized SharedCalendarSyncStartDate."
                    Add-SharingFinding -RuleId "SHR413" -Status Detected -Area "Synchronization start date" -Evidence @{
                        syncStartDateUninitialized = $syncStartDateUninitialized
                    }
                } elseif (-not $neverSynchronized) {
                    $creationTime = $MBCalFolder.CreationTime -as [DateTime]
                    if ($null -ne $syncStartDate) {
                        Write-Host -ForegroundColor Green "The Receiver's copy of the Owner's Calendar should have data back to: $($syncStartDate.ToShortDateString())."
                    } else {
                        Write-Host -ForegroundColor Green "The Receiver's copy of the Owner's Calendar should have data back to: $($MBCalFolder.SharedCalendarSyncStartDate)."
                        Add-SharingFinding -Severity Warning -Area "Synchronization start date" -Issue "SharedCalendarSyncStartDate could not be interpreted as a date." -Evidence "Value: [$($MBCalFolder.SharedCalendarSyncStartDate)]." -RecommendedNextStep "Inspect the raw folder data and SharingSyncAssistant logs." -Incomplete
                    }
                    Write-Host "`t This can be changed with the Set-MailboxCalendarFolder cmdlet."
                    if (($null -ne $syncStartDate) -and
                        ($null -ne $creationTime) -and
                        ($syncStartDate -gt $creationTime)) {
                        Add-SharingFinding -Severity Warning -Area "Synchronization start date" -Issue "SharedCalendarSyncStartDate is later than the local folder CreationTime." -Evidence "SharedCalendarSyncStartDate=[$syncStartDate]; CreationTime=[$creationTime]." -RecommendedNextStep "Inspect invite/accept and SharingSyncAssistant logs to determine whether backfill was restarted."
                    } elseif (($null -ne $syncStartDate) -and ($null -eq $creationTime)) {
                        Add-SharingFinding -RuleId "SHR411" -Status NotEvaluated -Evidence @{
                            reason = "The receiver folder creation time could not be interpreted as a date."
                        }
                    }
                    if (($null -ne $syncStartDate) -and ($syncStartDate -gt (Get-Date).AddHours(-24))) {
                        Add-SharingFinding -Severity Information -Area "Synchronization start date" -Issue "SharedCalendarSyncStartDate is very recent and may reflect backfill or folder recreation context." -Evidence "SharedCalendarSyncStartDate=[$syncStartDate]." -RecommendedNextStep "Correlate invite/accept and SharingSyncAssistant logs before concluding that synchronization failed."
                    }
                }

                $ownerPermission = Get-PermissionEntriesForIdentity `
                    -PermissionEntries $script:OwnerCalendarPerms `
                    -Identity $Receiver -Mailbox $script:ReceiverMB |
                    Select-Object -First 1
                if ($script:OwnerCalendarPermsAvailable -and
                    ($null -ne $script:OwnerActiveReceiver) -and
                    ($null -eq $ownerPermission)) {
                    Add-SharingFinding -Severity Error -Area "Pair permission configuration" -Issue "The expected active relationship has no matching owner calendar permission." -Evidence "Active sharing contains [$Receiver], but owner calendar permissions do not." -RecommendedNextStep "Run SharingPolicyAssistant or calendar-sharing validator diagnostics and compare invite/accept logs."
                } elseif ($script:OwnerActiveSharingAvailable -and
                    ($null -ne $ownerPermission) -and
                    ($null -eq $script:OwnerActiveReceiver)) {
                    Add-SharingFinding -Severity Error -Area "Pair permission configuration" -Issue "The owner calendar permission exists but the expected active relationship is absent." -Evidence "Owner permission was found for [$Receiver], but active-sharing information did not contain the receiver." -RecommendedNextStep "Inspect invite/accept logs and run SharingPolicyAssistant or calendar-sharing validator diagnostics."
                }
                $ownerSharingFlags = @($ownerPermission.SharingPermissionFlags) | Where-Object -FilterScript {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
                $receiverSharingFlags = @($MBCalFolder.SharingPermissionFlags) | Where-Object -FilterScript {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
                $activeSharingFlags = @($script:OwnerActiveReceiver.SharingPermissionFlags) | Where-Object -FilterScript {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
                if (($null -ne $ownerPermission) -and
                    ($ownerSharingFlags.Count -gt 0) -and
                    ($receiverSharingFlags.Count -gt 0) -and
                    (Test-SharingPermissionFlagsDiffer -FirstFlags $ownerSharingFlags -SecondFlags $receiverSharingFlags)) {
                    Add-SharingFinding -Severity Warning -Area "Pair permission configuration" -Issue "Owner and receiver sharing permission flags differ." -Evidence "Owner flags=[$($ownerSharingFlags -join ', ')]; receiver flags=[$($receiverSharingFlags -join ', ')]." -RecommendedNextStep "Compare the pair configuration with SharingPolicyAssistant or calendar-sharing validator diagnostics."
                }
                if (($null -ne $script:OwnerActiveReceiver) -and
                    ($activeSharingFlags.Count -gt 0) -and
                    ($receiverSharingFlags.Count -gt 0) -and
                    (Test-SharingPermissionFlagsDiffer -FirstFlags $activeSharingFlags -SecondFlags $receiverSharingFlags)) {
                    Add-SharingFinding -Severity Warning -Area "Pair permission configuration" -Issue "Active-sharing and receiver-folder permission flags differ." -Evidence "Active relationship flags=[$($activeSharingFlags -join ', ')]; receiver flags=[$($receiverSharingFlags -join ', ')]." -RecommendedNextStep "Compare the pair configuration with SharingPolicyAssistant or calendar-sharing validator diagnostics."
                }
            } catch {
                Write-Error "Failed to get the Owner's Calendar from the Receiver's Mailbox.  This is fine if not using Modern Sharing."
                Add-SharingFinding -Severity Error -Area "Receiver calendar folder" -Issue "The matched receiver calendar folder could not be queried." -Evidence $_.Exception.Message -RecommendedNextStep "Verify the folder identity from folder statistics and inspect Get-CalendarEntries plus invite/accept logs." -Incomplete
            }

            # Collect Sharing related logs for further analysis if needed
            # Need to Document what to look for in these logs before exposing this functionality
            # $SharingLog =  Export-MailboxDiagnosticLogs $Receiver -ComponentName Sharing
            # $SSA = Export-MailboxDiagnosticLogs $Receiver -ComponentName SharingSyncAssistant
            # $SharingValidator = Export-MailboxDiagnosticLogs $Receiver -ComponentName CalendarSharingInconsistencyValidator
            # $SharingRepair = Export-MailboxDiagnosticLogs $Receiver -ComponentName CalendarSharingInconsistencyRepair
        } else {
            if ($script:PublishedSharing) {
                $script:CollectorStatuses["ReceiverLocalCalendarFolder"] = [PSCustomObject]@{ status = "NotApplicable"; error = $null }
                Write-Host -ForegroundColor Yellow "Published calendar subscriptions use their InternetCalendar local folder and do not use Modern Sharing local-folder checks."
            } elseif ($script:LegacyMapiSharing) {
                $script:CollectorStatuses["ReceiverLocalCalendarFolder"] = [PSCustomObject]@{ status = "NotApplicable"; error = $null }
                Write-Host -ForegroundColor Yellow "Legacy MAPI access uses the owner calendar permissions and does not create a Modern Sharing local folder in the receiver mailbox."
            } else {
                $script:CollectorStatuses["ReceiverLocalCalendarFolder"] = [PSCustomObject]@{ status = "NotEvaluated"; error = $null }
            }
            if ((-not $receiverCalendarFolderNamesRedacted) -and
                (-not $script:LegacyMapiSharing) -and
                (-not $script:PublishedSharing)) {
                if ($script:PIIAccess) {
                    Write-Host -ForegroundColor Yellow "A uniquely matched Modern Sharing local folder was not identified, so receiver local-folder checks cannot run."
                } else {
                    Write-Host "Do Not have PII information for the Owner, so can not check the Receivers Copy of the Owner Calendar."
                    Write-Host "Get PII Access for both mailboxes and try again."
                }
            }
            if ((-not $script:LegacyMapiSharing) -and
                (-not $script:PublishedSharing)) {
                $receiverLocalFolderReason = if ($script:PIIAccess) {
                    "A uniquely matched owner folder was unavailable."
                } else {
                    "PII access was unavailable."
                }
                Add-SharingFinding -Severity Warning -Area "Receiver calendar folder" -Issue "The receiver local-folder detail check could not be completed." -Evidence $receiverLocalFolderReason -RecommendedNextStep "Confirm the folder using Get-CalendarEntries and rerun the pair diagnostics." -Incomplete
            }
        }
    }
}
