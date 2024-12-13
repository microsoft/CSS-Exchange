# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function RunTenantTests {
    [ref]$ErrorMessage = $null
    [ref]$WriteMessageAlways = $false
    $TestResult = $true

    Write-DashLineBoxColor "Running Tenant Tests" -Color Blue

    $ErrorMessage = ""
    $TestResult = CheckBookingsEnabled -errorMessage $ErrorMessage
    WriteTestResult "Bookings is enabled" -success $TestResult -errorMessage $ErrorMessage

    $TestResult = CheckAcceptedDomainIsManaged -errorMessage $ErrorMessage
    WriteTestResult "Is Default domain Managed" -success $TestResult -errorMessage $ErrorMessage

    $TestResult = CheckEWSEnabled -errorMessage $ErrorMessage
    WriteTestResult -title "Check EWS Enabled" -success $TestResult -errorMessage $ErrorMessage -writeMessageAlways $WriteMessageAlways

    $TestResult = CheckEWSAccessPolicy -errorMessage $ErrorMessage -writeMessageAlways $WriteMessageAlways
    WriteTestResult -title "Check EWS Access Policy" -success $TestResult -errorMessage $ErrorMessage -writeMessageAlways $true
    #dump allow/block list data below, indented
    WriteEWSAllowList
    WriteEWSBlockList

    $TestResult = CheckOWAMailboxPolicyMailboxCreationEnabled -errorMessage $ErrorMessage
    WriteTestResult "Mailbox Creation is enabled" -success $TestResult -errorMessage $ErrorMessage

    $TestResult = CheckBookingsMBDomain -errorMessage $ErrorMessage
    WriteTestResult "BookingsMailboxDomain in the correct domain" -success $TestResult -errorMessage $ErrorMessage

    $TestResult = CheckDomainSuffix -errorMessage $ErrorMessage -writeMessageAlways $WriteMessageAlways
    WriteTestResult "DomainSuffix test for invalid chars" -success $TestResult -errorMessage $ErrorMessage -writeMessageAlways $WriteMessageAlways
    return
}

function CheckAcceptedDomainIsManaged {
    param([ref]$ErrorMessage)

    Write-Verbose "Checking if accepted domain is managed"
    $AcceptedDomains = $script:TenantSettings.AcceptedDomains
    if ($null -eq $AcceptedDomains) {
        $ErrorMessage.Value = "Accepted domains is null."
        return $false
    }

    if (@($AcceptedDomains | Where-Object { $_.AuthenticationType -eq "Managed" -and $_.DomainName -eq $script:Domain -and $_.Default -eq $true } ).Count -eq 0 ) {
        $ErrorMessage.Value = "There is no Default Accepted domain, with Authentication type Managed. "
        return $false
    }

    if (@($AcceptedDomains | Where-Object { $_.Default -eq $true } ).Count -gt 1 ) {
        $ErrorMessage.Value = "There is more than 1 Default Domain,  make sure there is only one and AuthenticationType is Managed."
        return $false
    }
    return $true
}

function CheckBookingsEnabled {
    param([ref]$ErrorMessage)

    Write-Verbose "Checking if Bookings is enabled for the tenant"
    if ($script:TenantSettings.BookingsSettings.BookingsEnabled -ne $true) {
        $ErrorMessage.Value = "Bookings is not enabled for the Tenant - Check Get-OrganizationConfig."
        return $false
    }
    return $true
}

function CheckEWSEnabled {
    param([ref]$ErrorMessage, [ref]$WriteMessageAlways)

    Write-Verbose "Checking if EWS is enabled for the tenant"
    if ($script:TenantSettings.EwsEnabled -ne $true -and $null -ne $script:TenantSettings.EwsEnabled) {
        $ErrorMessage.Value = "EWS is not enabled for the Tenant - Check Get-OrganizationConfig."
        return $false
    }
    return $true
}

function CheckEWSAccessPolicy {
    param([ref]$ErrorMessage, [ref]$WriteMessageAlways)

    Write-Verbose "Checking if EWS Access Policy is set"

    if ($null -eq $script:TenantSettings.EwsApplicationAccessPolicy) {
        $ErrorMessage.Value = "EWS Application Access Policy is not set."
        $WriteMessageAlways.Value = $true
        return $true
    }
    if ($script:TenantSettings.EwsApplicationAccessPolicy -eq "EnforceAllowList" -or $script:TenantSettings.EwsApplicationAccessPolicy -eq "EnforceBlockList") {
        $ErrorMessage.Value = "EWS Application Access Policy is set to " + $script:TenantSettings.EwsApplicationAccessPolicy
        $WriteMessageAlways.Value = $true
    }

    return $true
}

function WriteEWSAllowList {
    if ($script:TenantSettings.EwsApplicationAccessPolicy -eq "EnforceAllowList") {
        $script:TenantSettings.EwsAllowList | ForEach-Object { Write-Output "$script:indent$_" }
    }
}

function WriteEWSBlockList {
    if ($script:TenantSettings.EwsApplicationAccessPolicy -eq "EnforceBlockList") {
        $script:TenantSettings.EwsBlockList | ForEach-Object { Write-Output "$script:indent$_" }
    }
}

function CheckOWAMailboxPolicyMailboxCreationEnabled {
    param([ref]$ErrorMessage)

    Write-Verbose "Checking if Mailbox Creation is enabled for the tenant"
    if ($script:TenantSettings.OwaMailboxPolicy.BookingsMailboxCreationEnabled -ne $true) {
        $ErrorMessage.Value = "Check Get-OwaMailboxPolicy"
        return $false
    }
    return $true
}

function CheckBookingsMBDomain {
    param([ref]$ErrorMessage)

    Write-Verbose "Checking if Bookings Mailbox is in the correct domain"
    if ($script:Domain -ne $script:OwaMailboxPolicy.BookingsMailboxDomain) {
        $ErrorMessage.Value = "Get-OWAMailboxPolicy BookingsMailboxDomain is " + $script:OwaMailboxPolicy.BookingsMailboxDomain
        return $false
    }
    return $true
}

function CheckDomainSuffix {
    param([ref]$ErrorMessage, [ref]$WriteMessageAlways)

    Write-Verbose "Checking if domain suffix is correct"
    if ($script:OwaMailboxPolicy.DomainSuffix -match '[^a-zA-Z0-9]') {
        $ErrorMessage.Value = "OwaMailboxPolicy Bookings DomainSuffix may have invalid chars " + $script:OwaMailboxPolicy.DomainSuffix
        return $false
    }
    $ErrorMessage.Value="No invalid characters were found."
    $WriteMessageAlways.Value = $true
    return $true
}

function CheckSharingPolicy {
    param([ref]$ErrorMessage)

    Write-Verbose "Checking if Sharing Policy is set"
    if ($null -eq $script:TenantSettings.BookingsSettings.BookingsSocialSharingRestricted) {
        $ErrorMessage.Value = "Bookings Social Sharing Policy is not set."
        return $false
    }
    return $true
}
