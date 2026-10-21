# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Pair-specific calendar statistics and explicit delegate permission checks.

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
    if ($script:PublishedSharing) {
        Add-SharingFinding -RuleId "SHR325" -Status NotApplicable -Evidence @{
            reason = "Calendar delegation does not apply to a published calendar subscription."
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
            -PermissionEntries $script:OwnerCalendarPerms -Identity $Receiver)
    $permissionFlags = ConvertTo-NormalizedFolderFlags -Flags @($individualPermissions.SharingPermissionFlags)
    $activeFlags = ConvertTo-NormalizedFolderFlags -Flags @($script:OwnerActiveReceiver.SharingPermissionFlags)
    $localFolderFlags = ConvertTo-NormalizedFolderFlags -Flags @($script:ReceiverLocalCalendarFolder.SharingPermissionFlags)
    $isDelegate = (@($permissionFlags) -contains "Delegate") -or
    (@($activeFlags) -contains "Delegate") -or
    (@($localFolderFlags) -contains "Delegate")

    if (-not $isDelegate) {
        $delegateEvidenceAvailable = $script:LegacyMapiSharing -or
        (($script:CollectorStatuses["ActiveSharing"].status -eq "Success") -and
        ($script:CollectorStatuses["ReceiverLocalCalendarFolder"].status -eq "Success"))
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
