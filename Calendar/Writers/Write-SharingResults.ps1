# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# .DESCRIPTION
# Sharing diagnostic output and reporting functions.

. $PSScriptRoot\..\Helpers\SharingIdentityUtilities.ps1

function Write-SharingFindingDetails {
    param(
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [hashtable]$SeverityOrder
    )

    $displayFindings = @($Findings |
            ForEach-Object {
                [PSCustomObject]@{
                    severity            = $_.severity
                    ruleId              = $_.ruleId
                    title               = $_.title
                    evidence            = $script:ConsoleFindingEvidence[$_.ruleId]
                    recommendedNextStep = $_.recommendedNextStep
                }
            } |
            Sort-Object -Property @{ Expression = { $SeverityOrder[$_.severity] } }, ruleId)

    $displayFindings |
        Format-Table -AutoSize -Wrap -Property @{
            Label      = "Severity"
            Expression = { $_.severity }
        }, @{
            Label      = "RuleId"
            Expression = { $_.ruleId }
        }, @{
            Label      = "Title"
            Expression = { $_.title }
        }, @{
            Label      = "Evidence"
            Expression = { $_.evidence }
        }
    Write-Host -ForegroundColor Blue "`rRecommended Next Steps:"
    foreach ($finding in $displayFindings) {
        Write-Host -ForegroundColor Yellow "[$($finding.ruleId)] $($finding.recommendedNextStep)"
    }
}

function Write-OwnerReceiverPermissionSummary {
    param(
        [Parameter(Mandatory)]
        [string]$Receiver
    )

    $receiverCalendarPermissions = Get-PermissionEntriesForIdentity `
        -PermissionEntries $script:OwnerCalendarPerms `
        -Identity $Receiver
    $receiverMailboxPermissions = Get-PermissionEntriesForIdentity `
        -PermissionEntries $script:OwnerMailboxPerms `
        -Identity $Receiver
    $calendarRights = if ($receiverCalendarPermissions.Count -gt 0) {
        Get-PermissionRightsText `
            -PermissionEntries $receiverCalendarPermissions `
            -IncludeSharingFlags
    } else {
        $null
    }
    $mailboxRights = if ($receiverMailboxPermissions.Count -gt 0) {
        Get-PermissionRightsText -PermissionEntries $receiverMailboxPermissions
    } else {
        $null
    }

    Write-Host -ForegroundColor DarkYellow "Owner-to-Receiver Permission Summary:"
    if (($null -ne $calendarRights) -and ($null -ne $mailboxRights)) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] has [$calendarRights] on the owner Calendar folder and [$mailboxRights] on the owner Mailbox."
    } elseif ($null -ne $calendarRights) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] is using [$calendarRights] on the owner Calendar folder."
    } elseif ($null -ne $mailboxRights) {
        Write-Host -ForegroundColor Green "Receiver [$Receiver] has [$mailboxRights] on the owner Mailbox."
    } elseif ($script:OwnerCalendarPermsAvailable -and $script:OwnerMailboxPermsAvailable) {
        Write-Host -ForegroundColor Yellow "Receiver [$Receiver] does not have an individual permission entry on the owner Calendar folder or Mailbox; access may come from Default or a group permission."
    } else {
        Write-Host -ForegroundColor Yellow "Receiver-specific permissions could not be fully evaluated because the owner Calendar folder or Mailbox permission query was unavailable."
    }
}
