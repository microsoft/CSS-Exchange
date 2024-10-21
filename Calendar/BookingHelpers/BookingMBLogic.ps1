# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function RunMBTests {
    [ref]$errorMessage = $null
    [ref]$writeMessageAlways = $true
    $testResult = $true

    Write-DashLineBoxColor "Running Mailbox Tests" -Color Blue

    $errorMessage = ""
    $testResult = CheckIdentityIsBookingsMB -errorMessage $errorMessage
    WriteTestResult "Mailbox is Scheduling type " -success $testResult -errorMessage $errorMessage

    $testResult = CheckIfMBIsHiddenInGAL
    WriteTestResult "Is MB Hidden in GAL" -success $testResult -errorMessage $errorMessage

    $testResult = CheckBookingsMBEmailAddresses -errorMessage $errorMessage
    WriteTestResult "Check MB Email Addresses" -success $testResult -errorMessage $errorMessage -writeMessageAlways $writeMessageAlways
    writeBookingsMBEmailAddresses
}

function CheckIdentityIsBookingsMB {
    param([ref]$errorMessage)
    Write-Verbose "Checking if mailbox $Identity is Bookings mailbox"
    if ($script:bookingMBData.RecipientTypeDetails -ne "SchedulingMailbox") {
        $errorMessage.Value ="Mailbox $Identity is not a Bookings mailbox " + $script:bookingMBData.RecipientTypeDetails
        return $false
    }
    return $true
}
function CheckIfMBIsHiddenInGAL {
    Write-Verbose "Checking if a MB is Hidden in the GAL"
    if ($script:bookingMBData.HiddenFromAddressListsEnabled -eq $true) {
        $errorMessage.Value = "Mailbox $Identity is Hidden in the GAL."
        return $false
    }
    return $true
}

function CheckBookingsMBEmailAddresses {
    param([ref]$errorMessage)
    Write-Verbose "Checking if mailbox $Identity has more than 1 alias"
    if ($script:bookingMBData.EmailAddresses.Count -gt 1) {
        $errorMessage.Value = "Mailbox $Identity has more than one email address"
        return $true
    }
    return $true
}

function writeBookingsMBEmailAddresses {
    Write-Verbose "Checking if mailbox $Identity has the correct email addresses"

    $script:bookingMBData.EmailAddresses | ForEach-Object { Write-Output "$Script:indent$_" }
}
