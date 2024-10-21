# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function RunMBStaffLogValidation {
    [ref]$errorMessage = $null
    [ref]$writeMessageAlways = $true
    $testResult = $true

    Write-DashLineBoxColor "Running Staff Membership Log collection" -Color Blue

    $errorMessage = ""
    $testResult = CheckBMBStaffMemberShipLog -errorMessage $errorMessage
    WriteTestResult "Get Mailbox Staff membership logs" -success $testResult -errorMessage $errorMessage -writeMessageAlways $writeMessageAlways
}

function CheckBMBStaffMemberShipLog {
    param([ref]$errorMessage)
    Write-Verbose "Checking Membership Staff Log for $identity"
    if ($null -eq $script:BookingStaffMembershipLog) {
        $errorMessage.Value = "Staff Membership log not found."
        return $false
    }

    $errorMessage.Value = "Membership logs has " + $script:BookingStaffMembershipLogArray.Count + " entries"
    return $true
}
