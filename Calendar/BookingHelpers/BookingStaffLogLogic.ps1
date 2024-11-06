# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function RunMBStaffLogValidation {
    [ref]$ErrorMessage = $null
    [ref]$WriteMessageAlways = $true
    $TestResult = $true

    Write-DashLineBoxColor "Running Staff Membership Log collection" -Color Blue

    $ErrorMessage = ""
    $TestResult = CheckBMBStaffMemberShipLog -errorMessage $ErrorMessage
    WriteTestResult "Get Mailbox Staff membership logs" -success $TestResult -errorMessage $ErrorMessage -writeMessageAlways $WriteMessageAlways
}

function CheckBMBStaffMemberShipLog {
    param([ref]$ErrorMessage)
    Write-Verbose "Checking Membership Staff Log for $Identity"
    if ($null -eq $script:BookingStaffMembershipLog) {
        $ErrorMessage.Value = "Staff Membership log not found."
        return $false
    }

    $ErrorMessage.Value = "Membership logs has " + $script:BookingStaffMembershipLogArray.Count + " entries"
    return $true
}
