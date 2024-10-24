# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function RunMBTests {
    [ref]$ErrorMessage = $null
    [ref]$WriteMessageAlways = $true
    $TestResult = $true

    Write-DashLineBoxColor "Running Mailbox Tests" -Color Blue

    $ErrorMessage = ""
    $TestResult = CheckIdentityIsBookingsMB -errorMessage $ErrorMessage
    WriteTestResult "Mailbox is Scheduling type " -success $TestResult -errorMessage $ErrorMessage

    $TestResult = CheckIfMBIsHiddenInGAL
    WriteTestResult "Is MB Hidden in GAL" -success $TestResult -errorMessage $ErrorMessage

    $TestResult = CheckBookingsMBEmailAddresses -errorMessage $ErrorMessage
    WriteTestResult "Check MB Email Addresses" -success $TestResult -errorMessage $ErrorMessage -writeMessageAlways $WriteMessageAlways
    WriteBookingsMBEmailAddresses
}

function CheckIdentityIsBookingsMB {
    param([ref]$ErrorMessage)
    Write-Verbose "Checking if mailbox $Identity is Bookings mailbox"
    if ($script:BookingMBData.RecipientTypeDetails -ne "SchedulingMailbox") {
        $ErrorMessage.Value ="Mailbox $Identity is not a Bookings mailbox " + $script:BookingMBData.RecipientTypeDetails
        return $false
    }
    return $true
}
function CheckIfMBIsHiddenInGAL {
    Write-Verbose "Checking if a MB is Hidden in the GAL"
    if ($script:BookingMBData.HiddenFromAddressListsEnabled -eq $true) {
        $ErrorMessage.Value = "Mailbox $Identity is Hidden in the GAL."
        return $false
    }
    return $true
}

function CheckBookingsMBEmailAddresses {
    param([ref]$ErrorMessage)
    Write-Verbose "Checking if mailbox $Identity has more than 1 alias"
    if ($script:BookingMBData.EmailAddresses.Count -gt 1) {
        $ErrorMessage.Value = "Mailbox $Identity has more than one email address"
        return $true
    }
    return $true
}

function WriteBookingsMBEmailAddresses {
    Write-Verbose "Checking if mailbox $Identity has the correct email addresses"

    $script:BookingMBData.EmailAddresses | ForEach-Object { Write-Output "$Script:indent$_" }
}
