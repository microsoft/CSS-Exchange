# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetStaffMembershipLogs {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity
    )
    Write-Verbose "Checking Membership logs for $Identity"
    $Log = Export-MailboxDiagnosticLogs  -Identity $Identity  -ComponentName BookingStaffMembershipLog -ErrorAction SilentlyContinue
    return $Log
}

function GetMembershipLogArray {
    Write-Verbose "Reading Membership logs for $Identity and converting as array"
    $MembershipLogArray = Export-MailboxDiagnosticLogs  -Identity $Identity  -ComponentName BookingStaffMembershipLog -ErrorAction SilentlyContinue
    $MembershipLogArray = createArrayFromStaffLog -log $Log.MailboxLog
    return $MembershipLogArray
}

function createArrayFromStaffLog {
    param([string]$Log)
    #A sample line from the log array is a single string with the following format:
    #2/19/2024 7:49:37 PM:StaffId:LU37rKfE1kKgCZy/qlYLtQ==,Name:external test,MailboxGuid:fba85c5f-8a4f-45f5-8749-8385d0fea4cb,MembershipStatus:Active,Action:Deleted
    #The log is split by new line and then each line is split by comma to get the values
    $LogArray = $Log -split [Environment]::NewLine

    $ARetVal = @()
    $LogArray | ForEach-Object {
        if (-not $_.Trim().Length -eq 0) {
            $Line = $_.Split(",")
            $ARetVal += [PSCustomObject]@{
                Date             = $Line[0]
                StaffID          = $Line[1]
                Name             = $Line[2]
                MailboxGuid      = $Line[3]
                MemberShipStatus = $Line[4]
            }
        }
    }
    return $ARetVal
}

function export-BookingStaffMembershipLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    $ArrayFromStaffLog = createArrayFromStaffLog -log $script:BookingStaffMembershipLog.MailboxLog

    $MBStaffMembershipLogArray = @()
    foreach ($Log in $script:BookingStaffMembershipLog.MailboxLog.Split("`r`n")) {
        $MBStaffMembershipLogArray += [PSCustomObject]@{
            log = $Log
        }
    }
    $ArrayFromStaffLog | Export-Excel -Path  $Path -WorksheetName "Membership Log Array" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize  -Title "Staff Membership Log"
}
