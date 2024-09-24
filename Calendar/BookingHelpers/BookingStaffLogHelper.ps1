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
    $log = Export-MailboxDiagnosticLogs  -Identity $identity  -ComponentName BookingStaffMembershipLog -ErrorAction SilentlyContinue
    $alog = createArrayFromStaffLog -log $log.MailboxLog
    #$alog | Format-Table
    return $alog
}

function createArrayFromStaffLog {
    param([string]$log)
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