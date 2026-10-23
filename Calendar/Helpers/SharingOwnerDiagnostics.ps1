# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Owner calendar permissions, flags, and active-sharing diagnostics.

<#
.SYNOPSIS
    Display Calendar Owner information.
.DESCRIPTION
    This function displays key Calendar Owner information.
.PARAMETER Identity
    The SMTP Address for Owner of the shared calendar.
#>
function GetOwnerInformation {
    param (
        [string]$Owner
    )

    if ($null -ne $script:FatalPrerequisiteFailure) {
        return
    }
    if (($null -eq $script:OwnerMB) -and
        (-not (Resolve-SharingMailboxPrerequisite -Role Owner -Identity $Owner))) {
        return
    }
    if ((($null -eq $script:OwnerSelectedCalendar) -or
            ($null -eq $script:OwnerCalendarFolder)) -and
        (-not (Resolve-OwnerCalendarPrerequisite))) {
        return
    }
    if ($null -ne $script:ReceiverMB) {
        Initialize-SharingOrganizationScope
    }

    #Standard Owner information
    Write-Host -ForegroundColor DarkYellow "------------------------------------------------"
    Write-Host -ForegroundColor DarkYellow "Key Owner Mailbox Information:"
    Write-Host -ForegroundColor DarkYellow "`t Using prerequisite result from 'Get-Mailbox $Owner'"

    $script:OwnerMB | Format-List DisplayName, Database, ServerName, LitigationHoldEnabled, CalendarVersionStoreDisabled, CalendarRepairDisabled, RecipientType*

    Write-Host -ForegroundColor DarkYellow "Send on Behalf Granted to :"
    foreach ($del in $($script:OwnerMB.GrantSendOnBehalfTo)) {
        Write-Host -ForegroundColor Blue "`t$($del)"
    }
    Write-Host "`n`n`n"

    if ($script:OwnerMB.DisplayName -like "Redacted*") {
        Write-Host -ForegroundColor Yellow "Do Not have PII information for the Owner."
        Write-Host -ForegroundColor Yellow "Get PII Access for $($script:OwnerMB.Database)."
        $script:PIIAccess = $false
        Add-SharingFinding -Severity Warning -Area "PII access" -Issue "Owner PII was redacted, limiting pair-specific checks." -Evidence "The owner DisplayName begins with Redacted." -RecommendedNextStep "Obtain PII access for the owner mailbox database and rerun the pair diagnostics." -Incomplete
    }

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Folder Statistics:"
    $OwnerCalendarStats = @($script:OwnerCalendarStats)
    $ownerCalendarStat = $script:OwnerSelectedCalendar

    $OwnerCalendarStats | Format-Table -a FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
    $ownerDuplicateStyleFolders = Get-DuplicateStyleCalendarFolders -FolderStatistics $OwnerCalendarStats
    if ($ownerDuplicateStyleFolders.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "Warning: Owner calendar folders ending in a one- or two-digit numeric suffix may be duplicate folders."
        $ownerDuplicateStyleFolders |
            Format-Table -AutoSize FolderPath, VisibleItemsInFolder, FolderAndSubfolderSize
        Add-SharingFinding -RuleId "SHR112" -Status Detected -Area "Owner calendar naming" -Evidence @{
            folderCount = $ownerDuplicateStyleFolders.Count
            folderNames = @($ownerDuplicateStyleFolders.Name)
        }
    }

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxFolderPermission `"$($script:OwnerCalendarFolderIdentity)`" | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    try {
        $script:OwnerCalendarPerms = @(Invoke-SharingCollector -Name "OwnerCalendarPermissions" -Action {
                @(Get-MailboxFolderPermission -Identity $script:OwnerCalendarFolderIdentity -ErrorAction Stop)
            } -AllowNull)
        $script:OwnerCalendarPermsAvailable = $true
    } catch {
        $script:OwnerCalendarPerms = @()
        $script:OwnerCalendarPermsAvailable = $false
        Write-Warning "Failed to retrieve Owner Calendar permissions for [$Owner]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Owner calendar permissions" -Issue "The pair-specific permission check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxFolderPermission with sufficient access and compare the result with active-sharing and receiver-folder data." -Incomplete
    }
    $script:OwnerCalendarPerms | Format-Table -a User, AccessRights, SharingPermissionFlags

    # Warn if the size is greater than 1 GB.
    $folderSizeBytes = $null
    try {
        if ($null -ne $ownerCalendarStat.FolderSize.Value -and
            $null -ne $ownerCalendarStat.FolderSize.Value.PSObject.Methods["ToBytes"]) {
            $folderSizeBytes = [int64]$ownerCalendarStat.FolderSize.Value.ToBytes()
        } elseif ([string]$ownerCalendarStat.FolderSize -match "\((?<Bytes>[\d,\.\s]+)\s+bytes\)") {
            $numericBytes = $Matches["Bytes"] -replace "\D", ""
            $parsedBytes = [int64]0
            if ([int64]::TryParse($numericBytes, [ref]$parsedBytes)) {
                $folderSizeBytes = $parsedBytes
            }
        }
    } catch {
        Write-Verbose "Owner calendar size could not be converted to bytes."
    }
    if ($null -eq $folderSizeBytes) {
        Add-SharingFinding -RuleId "SHR430" -Status NotEvaluated -Evidence @{
            reason = "Folder size could not be converted to bytes."
        }
    } elseif ($folderSizeBytes -gt 1000000000) {
        Write-Host -ForegroundColor Yellow "Warning: Owner Calendar size is greater than 1 GB. This can impact calendar performance."
        Write-Host -ForegroundColor Yellow "`t Consider archiving old calendar items or reducing the size of attachments in calendar items."
        Add-SharingFinding -RuleId "SHR430" -Status Detected -Evidence @{
            folderSizeBytes = $folderSizeBytes
            thresholdBytes  = 1000000000
        }
    }

    # Warn if the Calendar count is greater than 100,000 items
    $visibleItemCount = [int64]0
    $visibleItemCountAvailable = [int64]::TryParse(
        [string]$ownerCalendarStat.VisibleItemsInFolder,
        [ref]$visibleItemCount)
    if (-not $visibleItemCountAvailable) {
        Add-SharingFinding -RuleId "SHR431" -Status NotEvaluated -Evidence @{
            reason = "Visible item count could not be converted to an integer."
        }
    } elseif ($visibleItemCount -gt 100000) {
        Write-Host -ForegroundColor Yellow "Warning: Owner Calendar has more than 100,000 items. This can impact calendar performance."
        Write-Host -ForegroundColor Yellow "`t Consider archiving old calendar items."
        Add-SharingFinding -RuleId "SHR431" -Status Detected -Evidence @{
            visibleItemCount = $visibleItemCount
            thresholdCount   = 100000
        }
    }

    Write-Host -ForegroundColor DarkYellow "Owner Root Mailbox Permissions:"
    Write-Host -ForegroundColor DarkYellow "`t Running 'Get-MailboxPermission $Owner | Format-Table -a User, AccessRights, SharingPermissionFlags'"
    try {
        $script:OwnerMailboxPerms = @(Invoke-SharingCollector -Name "OwnerMailboxPermissions" -Action {
                @(Get-MailboxPermission -Identity $Owner -ErrorAction Stop)
            } -AllowNull)
        $script:OwnerMailboxPermsAvailable = $true
        $script:OwnerMailboxPerms | Format-Table -a User, AccessRights, SharingPermissionFlags
    } catch {
        $script:OwnerMailboxPerms = @()
        $script:OwnerMailboxPermsAvailable = $false
        Write-Warning "Failed to retrieve Owner mailbox permissions for [$Owner]: $($_.Exception.Message)"
        Add-SharingFinding -Severity Warning -Area "Owner mailbox permissions" -Issue "The owner mailbox-permission check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-MailboxPermission with sufficient access." -Incomplete
    }
    Write-OwnerReceiverPermissionSummary -Receiver $Receiver

    Write-Host -ForegroundColor DarkYellow "Owner Modern Sharing Sent Invites"
    ProcessCalendarSharingInviteLogs -Identity $Owner

    Write-Host -ForegroundColor DarkYellow "Owner Calendar Folder Information:"
    Write-Host -ForegroundColor DarkYellow "`t Using prerequisite result from 'Get-MailboxCalendarFolder `"$($script:OwnerCalendarFolderIdentity)`"'"
    $OwnerCalendarFolder = $script:OwnerCalendarFolder
    $OwnerCalendarFolder |
        Format-List Identity, CreationTime, PublishEnabled, PublishedCalendarUrl, PublishedICalUrl, ExtendedFolderFlags
    if ($OwnerCalendarFolder.PublishEnabled) {
        Write-Host -ForegroundColor Green "Owner Calendar is Published."
        $script:OwnerPublished = $true
        $script:OwnerPublishedICalUrl = [string]$OwnerCalendarFolder.PublishedICalUrl
    } else {
        Write-Host -ForegroundColor Yellow "Owner Calendar is not Published."
        $script:OwnerPublished = $false
        $script:OwnerPublishedICalUrl = $null
    }

    $ownerExtendedFolderFlags = ConvertTo-NormalizedFolderFlags -Flags @($OwnerCalendarFolder.ExtendedFolderFlags)
    Write-Host -ForegroundColor DarkYellow "`t ExtendedFolderFlags: $($ownerExtendedFolderFlags)"
    if ($script:SharingType -eq "ExternalSharing") {
        $script:OwnerModernSharing = $false
        Write-Verbose "Internal REST owner-folder flag checks do not apply to external sharing or publishing."
    } elseif ($ownerExtendedFolderFlags -contains "SharedOut") {
        Write-Host -ForegroundColor Green "Owner Calendar is Shared Out using Modern Sharing."
        $script:OwnerModernSharing = $true
    } else {
        Write-Host -ForegroundColor Yellow "Owner Calendar is not Shared Out."
        $script:OwnerModernSharing = $false
        Add-SharingFinding -Severity Error -Area "Owner calendar flags" -Issue "The owner calendar is missing SharedOut." -Evidence "ExtendedFolderFlags: [$($ownerExtendedFolderFlags -join ', ')]." -RecommendedNextStep "Run the SharingPolicyAssistant or calendar-sharing validator diagnostics and inspect invite processing."
    }
    if (($ownerExtendedFolderFlags -notcontains "ExchangeShareFolder") -and
        ($null -eq (Get-SharingRuleNotApplicableReason -RuleId "SHR122"))) {
        Write-Host -ForegroundColor Yellow "Owner Calendar is missing the ExchangeShareFolder flag."
        Add-SharingFinding -Severity Error -Area "Owner calendar flags" -Issue "The owner calendar is missing ExchangeShareFolder." -Evidence "ExtendedFolderFlags: [$($ownerExtendedFolderFlags -join ', ')]." -RecommendedNextStep "Run the SharingPolicyAssistant or calendar-sharing validator diagnostics and inspect invite processing."
    }

    if ($null -ne (Get-SharingRuleNotApplicableReason -RuleId "SHR310")) {
        $script:CollectorStatuses["ActiveSharing"] = [PSCustomObject]@{ status = "NotApplicable"; error = $null }
        return
    }

    # cSpell:ignore Sharee Sharees
    if (Get-Command -Name Get-CalendarActiveSharingInformation -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor DarkYellow "`t Running 'Get-CalendarActiveSharingInformation -Identity `"$($script:OwnerCalendarFolderIdentity)`"'"
        try {
            $OwnerActiveSharingInfo = Invoke-SharingCollector -Name "ActiveSharing" -Action {
                Get-CalendarActiveSharingInformation -Identity $script:OwnerCalendarFolderIdentity -ErrorAction Stop
            }
        } catch {
            Write-Warning "Failed to retrieve active sharing information for [$Owner]: $($_.Exception.Message)"
            Add-SharingFinding -Severity Warning -Area "Active sharing information" -Issue "The active-sharing relationship check was unavailable." -Evidence $_.Exception.Message -RecommendedNextStep "Rerun Get-CalendarActiveSharingInformation and inspect SharingPolicyAssistant or validator diagnostics." -Incomplete
            $OwnerActiveSharingInfo = $null
        }
        if ($null -eq $OwnerActiveSharingInfo) {
            $script:CollectorStatuses["ActiveSharing"] = [PSCustomObject]@{ status = "NoData"; error = $null }
            Add-SharingFinding -Severity Warning -Area "Active sharing information" -Issue "The active-sharing relationship check returned no data." -Evidence "Get-CalendarActiveSharingInformation returned no object for [$Owner]." -RecommendedNextStep "Rerun Get-CalendarActiveSharingInformation and inspect SharingPolicyAssistant or validator diagnostics." -Incomplete
            Write-Host -ForegroundColor DarkYellow "`n`n`n------------------------------------------------"
            return
        }
        $script:OwnerActiveSharingAvailable = $true
        $script:OwnerActiveSharees = @($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees)
        if ($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees.count -gt 0) {
            Write-Host -ForegroundColor Green "`t Calendar has [$($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees.count)] Active Receivers."
            $receivers = $OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees | ForEach-Object {
                [PSCustomObject]@{
                    EmailAddress          = $_.EmailAddress
                    SharingPermissionFlag = ($_.SharingPermissionFlags -join ",")
                    ActiveShareeFlags     = ($_.ActiveShareeFlags -join ",")
                    LastSyncTime          = $_.LastSyncTime
                }
            }
            Write-Host -ForegroundColor DarkYellow "Look for the Receiver [$Receiver] in the list of Active Receivers."

            $receivers | Format-Table -AutoSize EmailAddress, SharingPermissionFlag, ActiveShareeFlags, LastSyncTime
        } else {
            Write-Host -ForegroundColor Yellow "`t Calendar has no Active Receivers according to Get-CalendarActiveSharingInformation."
        }
        $script:OwnerActiveReceiver = @($OwnerActiveSharingInfo.ActiveShareesDataSet.Sharees | Where-Object -FilterScript {
                Test-SmtpAddressEqual -First $_.EmailAddress -Second $Receiver
            }) | Select-Object -First 1
        if ($null -eq $script:OwnerActiveReceiver) {
            Add-SharingFinding -Severity Error -Area "Active sharing information" -Issue "The expected receiver is absent from the owner's active-sharing relationships." -Evidence "Get-CalendarActiveSharingInformation did not contain [$Receiver]." -RecommendedNextStep "Inspect invite/accept logs and run SharingPolicyAssistant or calendar-sharing validator diagnostics."
        } else {
            $activeShareeFlags = @($script:OwnerActiveReceiver.ActiveShareeFlags)
            $nonDefaultActiveShareeFlags = @($activeShareeFlags | Where-Object -FilterScript {
                    (-not [string]::IsNullOrWhiteSpace($_)) -and ($_ -ne "None")
                })
            if ($nonDefaultActiveShareeFlags.Count -gt 0) {
                Add-SharingFinding -Severity Warning -Area "Active sharing information" -Issue "The expected receiver has non-None ActiveShareeFlags." -Evidence "ActiveShareeFlags: [$($activeShareeFlags -join ', ')]." -RecommendedNextStep "Inspect SharingPolicyAssistant and calendar-sharing validator diagnostics for the pair."
            }
        }
    } else {
        $script:CollectorStatuses["ActiveSharing"] = [PSCustomObject]@{ status = "Unavailable"; error = $null }
        Add-SharingFinding -Severity Warning -Area "Active sharing information" -Issue "Get-CalendarActiveSharingInformation is unavailable." -Evidence "The cmdlet was not found in the current session." -RecommendedNextStep "Run the check in a session where Get-CalendarActiveSharingInformation is available." -Incomplete
    }
    Write-Host -ForegroundColor DarkYellow "`n`n`n------------------------------------------------"
}
