# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetStaffMembershipLogs {
    param(
        [Parameter(Mandatory=$true)]
        [string]$identity
    )
    Write-Verbose "Checking Membership logs for $identity"
    $log = Export-MailboxDiagnosticLogs  -Identity $identity  -ComponentName BookingStaffMembershipLog -ErrorAction SilentlyContinue
    return $log
}

function GetMembershipLogArray {
    Write-Verbose "Reading Membership logs for $identity and converting as array"
    $MembershipLogArray = Export-MailboxDiagnosticLogs  -Identity $identity  -ComponentName BookingStaffMembershipLog -ErrorAction SilentlyContinue
    $MembershipLogArray = createArrayFromStaffLog -log $log.MailboxLog
    return $MembershipLogArray
}

function createArrayFromStaffLog {
    param([string]$log)
    #A sample line from the log array is a single string with the following format:
    #2/19/2024 7:49:37 PM:StaffId:LU37rKfE1kKgCZy/qlYLtQ==,Name:external test,MailboxGuid:fba85c5f-8a4f-45f5-8749-8385d0fea4cb,MembershipStatus:Active,Action:Deleted
    #The log is split by new line and then each line is split by comma to get the values
    $logArray = $log -split [Environment]::NewLine

    $aRetVal = @()
    $logArray | ForEach-Object {
        if (-not $_.Trim().Length -eq 0) {
            $line = $_.Split(",")
            $aRetVal += [PSCustomObject]@{
                Date             = $line[0]
                StaffID          = $line[1]
                Name             = $line[2]
                MailboxGuid      = $line[3]
                MemberShipStatus = $line[4]
            }
        }
    }
    return $aRetVal
}

function export-BookingStaffMembershipLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$identity
    )

    $ArrayFromStaffLog = createArrayFromStaffLog -log $script:BookingStaffMembershipLog.MailboxLog

    $MBStaffMembershipLogArray = @()
    foreach ($log in $script:BookingStaffMembershipLog.MailboxLog.Split("`r`n")) {
        $MBStaffMembershipLogArray += [PSCustomObject]@{
            log = $log
        }
    }
    $ArrayFromStaffLog | Export-Excel -Path  $path -WorksheetName "Membership Log Array" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize  -Title "Staff Membership Log"
}
