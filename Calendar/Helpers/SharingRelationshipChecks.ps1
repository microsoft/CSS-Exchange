# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Pair-specific calendar statistics and explicit delegate permission checks.

function Initialize-SharingOrganizationScope {
    $ownerOrganization = [string]$script:OwnerMB.OrganizationalUnitRoot
    $receiverOrganization = [string]$script:ReceiverMB.OrganizationalUnitRoot
    $script:SharingType = if ([string]::IsNullOrWhiteSpace($ownerOrganization) -or
        [string]::IsNullOrWhiteSpace($receiverOrganization)) {
        "Undetermined"
    } elseif ($ownerOrganization -eq $receiverOrganization) {
        "InternalSharing"
    } else {
        "ExternalSharing"
    }
}

function Get-SharingRelationshipKind {
    if ($script:PublishedSharing) {
        return "External: Publishing"
    }
    if ($script:ExternalSharing) {
        return "External: External Sharing"
    }
    if ($script:SharingType -eq "InternalSharing") {
        if ($script:LegacyMapiSharing) { return "Internal: MAPI (old Model)" }
        if ($script:ModernSharing) { return "Internal: REST (New Model)" }
    }
    return "Undetermined"
}

function Test-SharingReceiverAddress {
    param(
        [AllowNull()]
        [object]$Address
    )

    $receiverAddresses = Get-SharingMailboxSmtpAddresses -Identity $Receiver -Mailbox $script:ReceiverMB
    return @($receiverAddresses | Where-Object {
            Test-SmtpAddressEqual -First $Address -Second $_
        }).Count -gt 0
}

function Test-SharingReceiverFolderMissing {
    return ($script:CollectorStatuses["ReceiverFolderStatistics"].status -eq "Success") -and
    ($null -eq $script:ReceiverMatchedCalendar) -and
    ($null -eq $script:ReceiverLocalCalendarFolder) -and
    ($script:CollectorStatuses["ReceiverLocalCalendarFolder"].status -ne "Failed") -and
    ($script:ReceiverCalendarCandidates.Count -eq 0) -and
    (@($script:SharingFindings | Where-Object {
            $_.ruleId -eq "SHR213" -and $_.status -eq "NotEvaluated"
        }).Count -eq 0)
}

function Get-SharingRelationshipAssessment {
    if ((-not $script:OwnerCalendarSubfolderSelected) -or ($null -ne $script:FatalPrerequisiteFailure)) {
        return $null
    }

    $ownerAddresses = Get-SharingMailboxSmtpAddresses -Identity $Owner -Mailbox $script:OwnerMB
    $mailboxInvites = @(Get-DatedSharingLogEntries -Entry @($script:OwnerInviteData | Where-Object {
                Test-SharingReceiverAddress -Address $_.Recipient
            }) -ReferenceTimeUtc $script:RunStartedAt.ToUniversalTime())
    $evidence = [ordered]@{
        mailboxInviteCount           = $(if ($script:OwnerInviteCheckAvailable) { $mailboxInvites.Count } else { $null })
        latestMailboxInviteTimestamp = $(if ($script:OwnerInviteCheckAvailable -and $mailboxInvites.Count -gt 0) { $mailboxInvites[0].Entry.Timestamp } else { $null })
        mailboxInvitesIdentifyFolder = $false
        individualPermissionFound    = $null
        activeRelationshipFound      = $null
        calendarEntryFound           = $null
        localFolderFound             = $null
        acceptanceFound              = $null
        synchronizationRequestFound  = $null
    }
    if ($script:OwnerCalendarPermsAvailable) {
        $permissions = @(Get-PermissionEntriesForIdentity -PermissionEntries $script:OwnerCalendarPerms `
                -Identity $Receiver -Mailbox $script:ReceiverMB)
        $rights = @(ConvertTo-NormalizedFolderFlags -Flags @($permissions.AccessRights))
        $evidence.individualPermissionFound = @($rights | Where-Object { $_ -ne "None" }).Count -gt 0
    }
    if ($script:CollectorStatuses["ActiveSharing"].status -eq "Success") {
        $evidence.activeRelationshipFound = $null -ne $script:OwnerActiveReceiver
    }
    if ($script:CollectorStatuses["CalendarEntries"].status -eq "Success") {
        $evidence.calendarEntryFound = @($script:ReceiverCalendarEntries | Where-Object {
                $entryOwner = $_.OwnerEmailAddress
                @($ownerAddresses | Where-Object { Test-SmtpAddressEqual -First $entryOwner -Second $_ }).Count -gt 0 -and
                [string]::Equals($_.CalendarName, $script:RequestedOwnerCalendarLeafName, [System.StringComparison]::OrdinalIgnoreCase)
            }).Count -gt 0
    }
    if ($null -ne $script:ReceiverMatchedCalendar) {
        $evidence.localFolderFound = $true
    } elseif (Test-SharingReceiverFolderMissing) {
        $evidence.localFolderFound = $false
    }
    if ($script:CollectorStatuses["ReceiverAcceptLog"].status -eq "Success") {
        $evidence.acceptanceFound = @($script:ReceiverAcceptLogEntries | Where-Object {
                $acceptOwner = $_.SharedCalendarOwner
                @($ownerAddresses | Where-Object { Test-SmtpAddressEqual -First $acceptOwner -Second $_ }).Count -gt 0 -and
                [string]::Equals($_.FolderName, $script:RequestedOwnerCalendarLeafName, [System.StringComparison]::OrdinalIgnoreCase)
            }).Count -gt 0
    }
    $syncLog = $script:SharingDiagnosticLogs["receiver_SharingSyncAssistantLog"]
    $ownerGuid = [Guid]::Empty
    if (($syncLog.status -in @("Collected", "NoData")) -and
        [Guid]::TryParse([string]$script:OwnerMB.ExchangeGuid, [ref]$ownerGuid) -and ($ownerGuid -ne [Guid]::Empty)) {
        $evidence.synchronizationRequestFound = @(Get-ReceiverSharingSyncRequestEntries `
                -Line $syncLog.data -OwnerMailbox $script:OwnerMB `
                -CalendarName $script:RequestedOwnerCalendarLeafName).Count -gt 0
    }

    # A mailbox-wide invitation and a similarly named local folder alone cannot identify the shared sub-calendar.
    $folderEvidenceFound = @(
        $evidence.individualPermissionFound, $evidence.activeRelationshipFound,
        $evidence.calendarEntryFound, $evidence.acceptanceFound, $evidence.synchronizationRequestFound
    ) -contains $true
    $unavailableEvidence = @(
        @("mailboxInviteCount", "individualPermissionFound", "activeRelationshipFound", "calendarEntryFound",
            "localFolderFound", "acceptanceFound", "synchronizationRequestFound") |
            Where-Object { $null -eq $evidence[$_] }
    )
    $message = if ($folderEvidenceFound) {
        "Folder-specific relationship evidence was found for the selected calendar and receiver. This does not establish synchronization health or prove delivery of a particular invitation."
    } else {
        "Sharing of the selected calendar to this receiver could not be confirmed from the collected evidence."
    }
    if (($evidence.mailboxInviteCount -gt 0) -and (-not $folderEvidenceFound)) {
        $message += " A mailbox-level invitation exists, but its calendar folder is unknown."
    }
    if (-not $folderEvidenceFound) {
        $message += " Verify that this specific calendar was shared with the receiver before investigating synchronization. This is not proof that the calendar was never shared."
    }
    if ($unavailableEvidence.Count -gt 0) {
        $message += " Some evidence sources were unavailable."
    }
    return [PSCustomObject]@{
        status              = $(if ($folderEvidenceFound) { "EvidenceFound" } else { "NotConfirmed" })
        message             = $message
        evidence            = $evidence
        unavailableEvidence = $unavailableEvidence
    }
}

function Get-PairSharingInvite {
    $invites = @($script:OwnerInviteData | Where-Object {
            (Test-SharingReceiverAddress -Address $_.Recipient) -and
            ((-not $script:OwnerCalendarSubfolderSelected) -or
            [string]::Equals([string]$_.CalendarName, $script:RequestedOwnerCalendarLeafName,
                [System.StringComparison]::OrdinalIgnoreCase))
        })
    if ($invites.Count -le 1) { return $invites | Select-Object -First 1 }
    if (@($invites.SharingType | Select-Object -Unique).Count -eq 1) {
        return $invites | Select-Object -First 1
    }
    # Conflicting invitation types require a reliable ordering; undated history cannot establish the current model.
    $datedInvites = @(Get-DatedSharingLogEntries -Entry $invites -ReferenceTimeUtc $script:RunStartedAt.ToUniversalTime())
    if (@($datedInvites | Where-Object { $null -eq $_.Date }).Count -gt 0) { return }
    $latestInvite = $datedInvites | Sort-Object -Property Date -Descending | Select-Object -First 1
    if (@($datedInvites | Where-Object { $_.Date -eq $latestInvite.Date } |
                ForEach-Object { $_.Entry.SharingType } | Select-Object -Unique).Count -gt 1) { return }
    return $latestInvite.Entry
}

function Test-PublishedCalendarUrlEqual {
    param(
        [AllowNull()]
        [string]$First,

        [AllowNull()]
        [string]$Second
    )

    if ([string]::IsNullOrWhiteSpace($First) -or [string]::IsNullOrWhiteSpace($Second)) {
        return $false
    }
    $firstUri = $null
    $secondUri = $null
    if ((-not [System.Uri]::TryCreate($First.Trim(), [System.UriKind]::Absolute, [ref]$firstUri)) -or
        (-not [System.Uri]::TryCreate($Second.Trim(), [System.UriKind]::Absolute, [ref]$secondUri))) {
        Write-Verbose "Publishing URL evidence is not an absolute URL and cannot establish a subscription match."
        return $false
    }

    # Uri normalizes the scheme, host, and default port without ignoring case in paths or tokens.
    return [string]::Equals($firstUri.AbsoluteUri, $secondUri.AbsoluteUri, [System.StringComparison]::Ordinal)
}

function Test-PublishedCalendarRelationship {
    $pairInvite = Get-PairSharingInvite
    $publishedPermission = @($script:OwnerCalendarPerms | Where-Object {
            $permissionIdentities = @([string]$_.User,
                (Get-CalendarDiagnosticPermissionIdentity -PermissionUser $_.User))
            @($permissionIdentities | Where-Object {
                    ([string]$_ -match "^ExchangePublishedUser\.(?<Address>.+)$") -and
                    (Test-SharingReceiverAddress -Address $Matches.Address)
                }).Count -gt 0
        }).Count -gt 0
    $localFlags = ConvertTo-NormalizedFolderFlags -Flags @($script:ReceiverLocalCalendarFolder.ExtendedFolderFlags)
    $publishedFolder = ($localFlags -contains "WebCalFolder") -and
    (Test-SmtpAddressEqual -First $script:ReceiverLocalCalendarFolder.CalendarSharingOwnerSmtpAddress -Second $Owner)
    $pairNewEntries = @($script:ReceiverCalendarEntries | Where-Object {
            ($_.SharingModelType -eq "New") -and
            (Test-SmtpAddressEqual -First $_.OwnerEmailAddress -Second $Owner) -and
            ((-not $script:OwnerCalendarSubfolderSelected) -or
            [string]::Equals($_.CalendarName, $script:RequestedOwnerCalendarLeafName,
                [System.StringComparison]::OrdinalIgnoreCase))
        })
    $matchingPublishedEntries = @($script:ReceiverInternetCalendarEntries | Where-Object {
            Test-PublishedCalendarUrlEqual -First $_.PublishingUrl -Second $script:OwnerPublishedICalUrl
        })
    $publishingEvidence = ($pairInvite.SharingType -eq "publish") -or
    ($publishedPermission -and $pairInvite.SharingType -ne "external") -or
    $publishedFolder -or ($matchingPublishedEntries.Count -gt 0)
    $script:PublishedSharing = $publishingEvidence -and (($pairNewEntries.Count -eq 0) -or $publishedFolder)
    $script:ExternalSharing = (-not $script:PublishedSharing) -and
    ($script:SharingType -eq "ExternalSharing") -and
    (($pairInvite.SharingType -eq "external") -or ($localFlags -contains "ExchangeCrossOrgShareFolder"))
    if (-not $script:PublishedSharing) { return }

    $script:ModernSharing = $false
    $script:LegacyMapiSharing = $false
    if ($script:SharingFindingRuleIds.Contains("SHR424")) { return }
    $publishingProperty = if ($null -ne $script:OwnerCalendarFolder) {
        $script:OwnerCalendarFolder.PSObject.Properties["PublishEnabled"]
    } else { $null }
    if ($script:OwnerPublished) {
        Add-SharingFinding -RuleId "SHR424" -Status NotDetected -Evidence @{ publishEnabled = $true }
    } elseif (($null -ne $publishingProperty) -and ($publishingProperty.Value -eq $false)) {
        Write-Host -ForegroundColor Red "Error: The receiver uses publishing, but publishing is disabled on the selected owner calendar."
        Add-SharingFinding -RuleId "SHR424" -Status Detected -Evidence @{
            publishEnabled      = $false
            publishInviteFound  = $pairInvite.SharingType -eq "publish"
            publishedPermission = $publishedPermission
            webCalFolder        = $publishedFolder
        }
        return
    } else {
        Add-SharingFinding -RuleId "SHR424" -Status NotEvaluated -Evidence @{
            reason = "The owner's PublishEnabled value is unavailable."
        }
        return
    }
    if ([string]::IsNullOrWhiteSpace($script:OwnerPublishedICalUrl)) {
        Add-SharingFinding -RuleId "SHR423" -Status Detected -Evidence @{
            reason = "PublishEnabled is true, but PublishedICalUrl is unavailable."
        }
        foreach ($ruleId in @("SHR421", "SHR422")) {
            Add-SharingFinding -RuleId $ruleId -Status NotApplicable -Evidence @{ reason = "The owner PublishedICalUrl is unavailable." }
        }
        return
    }
    if ($script:CollectorStatuses["InternetCalendar"].status -eq "NotRun") {
        ProcessInternetCalendarLogs -Identity $Receiver
        $matchingPublishedEntries = @($script:ReceiverInternetCalendarEntries | Where-Object {
                Test-PublishedCalendarUrlEqual -First $_.PublishingUrl -Second $script:OwnerPublishedICalUrl
            })
    }
    if ($matchingPublishedEntries.Count -eq 0) {
        $subscriptionAvailable = $script:CollectorStatuses["InternetCalendar"].status -in @("Success", "NoData")
        Add-SharingFinding -RuleId "SHR421" -Status $(if ($subscriptionAvailable) { "Detected" } else { "NotEvaluated" }) -Evidence @{
            reason = "No matching InternetCalendar subscription was found; collection status: $($script:CollectorStatuses['InternetCalendar'].status)."
        }
        Add-SharingFinding -RuleId "SHR422" -Status $(if ($subscriptionAvailable) { "NotApplicable" } else { "NotEvaluated" }) -Evidence @{
            reason = "A matching receiver subscription was not available."
        }
        return
    }
    $matchingPublishedEntries = @($matchingPublishedEntries | Sort-Object -Property @{
            Expression = { ConvertTo-CalendarDiagnosticLogDateTime -Text $_.Timestamp }
            Descending = $true
        })
    $script:ReceiverPublishedCalendarEntry = $matchingPublishedEntries | Select-Object -First 1
    if ($script:CollectorStatuses["ReceiverFolderStatistics"].status -ne "Success") {
        Add-SharingFinding -RuleId "SHR422" -Status NotEvaluated -Evidence @{ reason = "Receiver calendar folder statistics are unavailable." }
        return
    }
    foreach ($publishedEntry in $matchingPublishedEntries) {
        $publishedFolderName = if (-not [string]::IsNullOrWhiteSpace([string]$publishedEntry.Folder)) {
            ([string]$publishedEntry.Folder).Trim().TrimStart("\", "/")
        } else {
            ([string]$publishedEntry.RemoteFolderName).Trim().TrimStart("\", "/")
        }
        $publishedCalendarFolder = $script:ReceiverFolderStatistics | Where-Object {
            if (-not [string]::IsNullOrWhiteSpace([string]$publishedEntry.LocalFolderId)) {
                return [string]::Equals([string]$_.FolderId, [string]$publishedEntry.LocalFolderId,
                    [System.StringComparison]::OrdinalIgnoreCase)
            }
            return (-not [string]::IsNullOrWhiteSpace($publishedFolderName)) -and
            ([string]::Equals([string]$_.Name, $publishedFolderName, [System.StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals(([string]$_.FolderPath).Trim().TrimStart("\", "/"), $publishedFolderName,
                [System.StringComparison]::OrdinalIgnoreCase))
        } | Select-Object -First 1
        if ($null -ne $publishedCalendarFolder) {
            $script:ReceiverPublishedCalendarEntry = $publishedEntry
            $script:ReceiverPublishedCalendarFolder = $publishedCalendarFolder
            Write-Host -ForegroundColor Green "Receiver published-calendar local folder: [$($script:ReceiverPublishedCalendarFolder.FolderPath)]."
            return
        }
    }
    Add-SharingFinding -RuleId "SHR422" -Status Detected -Evidence @{
        subscriptionCount = $matchingPublishedEntries.Count
        reason            = "None of the matching InternetCalendar subscriptions has a matching receiver calendar folder."
    }
}

function Compare-CalendarFolderStatistics {
    param(
        [AllowNull()]
        [object]$OwnerFolderStatistics,

        [AllowNull()]
        [object]$ReceiverFolderStatistics
    )

    $script:CalendarStatisticsComparisonPerformed = $true
    Write-Host -ForegroundColor Cyan "`r`rSelected Owner and Receiver Calendar Statistics Comparison:"

    if ($null -eq $OwnerFolderStatistics) {
        Write-Host -ForegroundColor Yellow "Owner calendar statistics are unavailable, so the comparison cannot be evaluated."
        Add-SharingFinding -RuleId "SHR432" -Status NotEvaluated -Evidence @{
            reason = "Selected owner calendar statistics are unavailable."
        }
        return
    }
    if ($null -eq $ReceiverFolderStatistics) {
        $receiverStatisticsAvailable = (
            $script:CollectorStatuses["ReceiverFolderStatistics"].status -eq "Success")
        $status = if ($receiverStatisticsAvailable) {
            "NotApplicable"
        } else {
            "NotEvaluated"
        }
        $reason = if ($receiverStatisticsAvailable) {
            "A unique receiver calendar folder was not identified."
        } else {
            "Receiver calendar folder statistics are unavailable."
        }
        Write-Host -ForegroundColor Yellow "$reason The comparison cannot be evaluated."
        Add-SharingFinding -RuleId "SHR432" -Status $status -Evidence @{
            reason = $reason
        }
        return
    }

    $ownerCount = [int64]0
    $receiverCount = [int64]0
    $ownerCountAvailable = [int64]::TryParse(
        [string]$OwnerFolderStatistics.VisibleItemsInFolder,
        [ref]$ownerCount)
    $receiverCountAvailable = [int64]::TryParse(
        [string]$ReceiverFolderStatistics.VisibleItemsInFolder,
        [ref]$receiverCount)

    $countDelta = if ($ownerCountAvailable -and $receiverCountAvailable) {
        $receiverCount - $ownerCount
    } else {
        $null
    }
    $countRatio = if ($ownerCountAvailable -and
        $receiverCountAvailable -and
        ($ownerCount -gt 0)) {
        [math]::Round(($receiverCount / $ownerCount), 2)
    } else {
        $null
    }

    $script:CalendarStatisticsComparison = [PSCustomObject]@{
        ownerCount    = $(if ($ownerCountAvailable) { $ownerCount } else { $null })
        receiverCount = $(if ($receiverCountAvailable) { $receiverCount } else { $null })
        countDelta    = $countDelta
        countRatio    = $countRatio
    }

    [PSCustomObject]@{
        Metric             = "VisibleItemsInFolder"
        Owner              = $(if ($ownerCountAvailable) { $ownerCount } else { "Unavailable" })
        Receiver           = $(if ($receiverCountAvailable) { $receiverCount } else { "Unavailable" })
        ReceiverMinusOwner = $(if ($null -ne $countDelta) { $countDelta } else { "Unavailable" })
        ReceiverOwnerRatio = $(if ($null -ne $countRatio) { $countRatio } else { "Unavailable" })
    } | Format-Table -AutoSize

    if (-not ($ownerCountAvailable -and $receiverCountAvailable)) {
        Add-SharingFinding -RuleId "SHR432" -Status NotEvaluated -Evidence @{
            reason = "Owner or receiver visible item count could not be converted to an integer."
        }
    } else {
        $countMultiplierMet = if ($ownerCount -eq 0) {
            $receiverCount -gt 0
        } else {
            $receiverCount -ge (2 * $ownerCount)
        }
        if (($receiverCount -gt $ownerCount) -and
            $countMultiplierMet -and
            ($countDelta -ge 100)) {
            Add-SharingFinding -RuleId "SHR432" -Status Detected -Evidence @{
                ownerCount          = $ownerCount
                receiverCount       = $receiverCount
                delta               = $countDelta
                ratio               = $countRatio
                multiplierThreshold = 2
                absoluteThreshold   = 100
            }
        }
    }
}

function Test-ReceiverDelegatePermissions {
    if ($script:PublishedSharing -or ($script:SharingType -eq "ExternalSharing")) {
        Add-SharingFinding -RuleId "SHR325" -Status NotApplicable -Evidence @{
            reason = "Internal calendar delegation does not apply to external sharing or a published subscription."
        }
        return
    }
    if (-not $script:OwnerCalendarPermsAvailable) {
        Add-SharingFinding -RuleId "SHR325" -Status NotEvaluated -Evidence @{
            reason = "Owner calendar permissions are unavailable."
        }
        return
    }

    $individualPermissions = @(Get-PermissionEntriesForIdentity `
            -PermissionEntries $script:OwnerCalendarPerms -Identity $Receiver -Mailbox $script:ReceiverMB)
    $permissionFlags = ConvertTo-NormalizedFolderFlags -Flags @($individualPermissions.SharingPermissionFlags)
    $activeFlags = ConvertTo-NormalizedFolderFlags -Flags @($script:OwnerActiveReceiver.SharingPermissionFlags)
    $localFolderFlags = ConvertTo-NormalizedFolderFlags -Flags @($script:ReceiverLocalCalendarFolder.SharingPermissionFlags)
    $isDelegate = (@($permissionFlags) -contains "Delegate") -or
    (@($activeFlags) -contains "Delegate") -or
    (@($localFolderFlags) -contains "Delegate")

    if (-not $isDelegate) {
        $delegateEvidenceAvailable = $script:LegacyMapiSharing -or
        (($script:CollectorStatuses["ActiveSharing"].status -eq "Success") -and
        (($script:CollectorStatuses["ReceiverLocalCalendarFolder"].status -eq "Success") -or
        (Test-SharingReceiverFolderMissing)))
        $status = if ($delegateEvidenceAvailable) { "NotApplicable" } else { "NotEvaluated" }
        $reason = if ($delegateEvidenceAvailable) {
            "The receiver is not identified as a delegate."
        } else {
            "Active-sharing or receiver-folder evidence is unavailable to determine whether the receiver is a delegate."
        }
        Add-SharingFinding -RuleId "SHR325" -Status $status -Evidence @{ reason = $reason }
        return
    }

    $validDelegatePermissions = @($individualPermissions | Where-Object -FilterScript {
            $rights = ConvertTo-NormalizedFolderFlags -Flags @($_.AccessRights)
            $flags = ConvertTo-NormalizedFolderFlags -Flags @($_.SharingPermissionFlags)
            (@($rights) -contains "Editor") -and (@($flags) -contains "Delegate")
        })
    $status = if ($validDelegatePermissions.Count -gt 0) { "NotDetected" } else { "Detected" }
    if ($status -eq "Detected") {
        Write-Host -ForegroundColor Red "Receiver [$Receiver] is a delegate but lacks an individual Editor permission entry with SharingPermissionFlags Delegate on the selected owner calendar. Group or Default permissions and mailbox FullAccess do not satisfy delegation."
    }
    Add-SharingFinding -RuleId "SHR325" -Status $status -Area "Receiver delegate permissions" -Evidence @{
        receiver                  = $Receiver
        individualPermissionFound = $individualPermissions.Count -gt 0
        delegatePermissionFound   = $validDelegatePermissions.Count -gt 0
    }
}
