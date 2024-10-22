# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function RunTenantTests {
    [ref]$errorMessage = $null
    [ref]$writeMessageAlways = $false
    $testResult = $true

    Write-DashLineBoxColor "Running Tenant Tests" -Color Blue

    $errorMessage = ""
    $testResult = CheckBookingsEnabled -errorMessage $errorMessage
    WriteTestResult "Bookings is enabled" -success $testResult -errorMessage $errorMessage

    $testResult = CheckAcceptedDomainIsManaged -errorMessage $errorMessage
    WriteTestResult "Is Default domain Managed" -success $testResult -errorMessage $errorMessage

    $testResult = CheckEWSEnabled -errorMessage $errorMessage
    WriteTestResult -title "Check EWS Enabled" -success $testResult -errorMessage $errorMessage -writeMessageAlways $writeMessageAlways

    $testResult = CheckEWSAccessPolicy -errorMessage $errorMessage -writeMessageAlways $writeMessageAlways
    WriteTestResult -title "Check EWS Access Policy" -success $testResult -errorMessage $errorMessage -writeMessageAlways $true
    #dump allow/block list data below, indented
    WriteEWSAllowList
    WriteEWSBlockList

    $testResult = CheckOWAMailboxPolicyMailboxCreationEnabled -errorMessage $errorMessage
    WriteTestResult "Mailbox Creation is enabled" -success $testResult -errorMessage $errorMessage

    $testResult = CheckBookingsMBDomain -errorMessage $errorMessage
    WriteTestResult "BookingsMailboxDomain in the correct domain" -success $testResult -errorMessage $errorMessage

    $testResult = CheckDomainSuffix -errorMessage $errorMessage -writeMessageAlways $writeMessageAlways
    WriteTestResult "DomainSuffix test for invalid chars" -success $testResult -errorMessage $errorMessage -writeMessageAlways $writeMessageAlways
    return
}

function CheckAcceptedDomainIsManaged {
    param([ref]$errorMessage)

    Write-Verbose "Checking if accepted domain is managed"
    $acceptedDomains = $script:TenantSettings.AcceptedDomains
    if ($null -eq $acceptedDomains) {
        $errorMessage.Value = "Accepted domains is null."
        return $false
    }

    if (@($acceptedDomains | Where-Object { $_.AuthenticationType -EQ "Managed" -and $_.DomainName -EQ $script:Domain -and $_.Default -EQ $true } ).Count -EQ 0 ) {
        $errorMessage.Value = "There is no Default Accepted domain, with Authentication type Managed. "
        return $false
    }

    if (@($acceptedDomains | Where-Object { $_.Default -EQ $true } ).Count -gt 1 ) {
        $errorMessage.Value = "There is more than 1 Default Domain,  make sure there is only one and AuthenticationType is Managed."
        return $false
    }
    return $true
}

function CheckBookingsEnabled {
    param([ref]$errorMessage)

    Write-Verbose "Checking if Bookings is enabled for the tenant"
    if ($script:TenantSettings.BookingsSettings.BookingsEnabled -ne $true) {
        $errorMessage.Value = "Bookings is not enabled for the Tenant - Check Get-OrganizationConfig."
        return $false
    }
    return $true
}

function CheckEWSEnabled {
    param([ref]$errorMessage, [ref]$writeMessageAlways)

    Write-Verbose "Checking if EWS is enabled for the tenant"
    if ($script:TenantSettings.EwsEnabled -ne $true -and $null -ne $script:TenantSettings.EwsEnabled) {
        $errorMessage.Value = "EWS is not enabled for the Tenant - Check Get-OrganizationConfig."
        return $false
    }
    return $true
}

function CheckEWSAccessPolicy {
    param([ref]$errorMessage, [ref]$writeMessageAlways)

    Write-Verbose "Checking if EWS Access Policy is set"

    if ($null -eq $script:TenantSettings.EwsApplicationAccessPolicy) {
        $errorMessage.Value = "EWS Application Access Policy is not set."
        $writeMessageAlways.Value = $true
        return $true
    }
    if ($script:TenantSettings.EwsApplicationAccessPolicy -eq "EnforceAllowList" -or $script:TenantSettings.EwsApplicationAccessPolicy -eq "EnforceBlockList") {
        $errorMessage.Value = "EWS Application Access Policy is set to " + $script:TenantSettings.EwsApplicationAccessPolicy
        $writeMessageAlways.Value = $true
    }

    return $true
}

function WriteEWSAllowList {
    $indent = "         "
    if ($script:TenantSettings.EwsApplicationAccessPolicy -eq "EnforceAllowList") {
        $script:TenantSettings.EwsAllowList | ForEach-Object { Write-Output "$indent$_" }
    }
}

function WriteEWSBlockList {
    $indent = "         "
    if ($script:TenantSettings.EwsApplicationAccessPolicy -eq "EnforceBlockList") {
        $script:TenantSettings.EwsBlockList | ForEach-Object { Write-Output "$indent$_" }
    }
}

function CheckOWAMailboxPolicyMailboxCreationEnabled {
    param([ref]$errorMessage)

    Write-Verbose "Checking if Mailbox Creation is enabled for the tenant"
    if ($script:TenantSettings.OWAMBPolicy.BookingsMailboxCreationEnabled -ne $true) {
        $errorMessage.Value = "Check Get-OwaMailboxPolicy"
        return $false
    }
    return $true
}

function CheckBookingsMBDomain {
    param([ref]$errorMessage)

    Write-Verbose "Checking if Bookings Mailbox is in the correct domain"
    if ($script:Domain -ne $script:OWAMBPolicy.BookingsMailboxDomain) {
        $errorMessage.Value = "Get-OWAMailboxPolicy BookingsMailboxDomain is " + $script:OWAMBPolicy.BookingsMailboxDomain
        return $false
    }
    return $true
}

function CheckDomainSuffix {
    param([ref]$errorMessage, [ref]$writeMessageAlways)

    Write-Verbose "Checking if domain suffix is correct"
    if ($script:OWAMBPolicy.DomainSuffix -match '[^a-zA-Z0-9]') {
        $errorMessage.Value = "OWAMBPolicy Bookings DomainSuffix may have invalid chars " + $script:OWAMBPolicy.DomainSuffix
        return $false
    }
    $errorMessage.Value="No invalid characters were found."
    $writeMessageAlways.Value = $true
    return $true
}

function CheckSharingPolicy {
    param([ref]$errorMessage)

    Write-Verbose "Checking if Sharing Policy is set"
    if ($null -eq $script:TenantSettings.BookingsSettings.BookingsSocialSharingRestricted) {
        $errorMessage.Value = "Bookings Social Sharing Policy is not set."
        return $false
    }
    return $true
}
