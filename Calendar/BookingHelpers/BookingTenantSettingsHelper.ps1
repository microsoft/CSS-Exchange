# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetBookingTenantSettings {
    param([string] $domain)

    if ($script:MSSupport) {
        $script:OrgConfig = Get-OrganizationConfig -Organization $domain
        $script:OWAMBPolicy = Get-OwaMailboxPolicy -Organization $domain
        $script:AcceptedDomains = Get-AcceptedDomain -Organization $domain
    } else {
        $script:OrgConfig = Get-OrganizationConfig
        $script:OWAMBPolicy = Get-OwaMailboxPolicy
        $script:AcceptedDomains = Get-AcceptedDomain
    }
    $ewsSettings = GetEWSSettings $script:OrgConfig
    $bookingsSettings =  $script:OrgConfig
    $OWAMBPolicy =  $script:OWAMBPolicy
    $acceptedDomains = GetAcceptedDomains $script:AcceptedDomains
    # Define the structure of the tenant settings
    $TenantSettings = [PSCustomObject]@{
        Identity         = $org.Identity
        Guid             = $org.Guid
        DisplayName      = $org.DisplayName
        IsDeHydrated     = $org.IsDeHydrated
        EWSSettings      = $ewsSettings
        BookingsSettings = $bookingsSettings
        OWAMBPolicy      = $OWAMBPolicy
        AcceptedDomains  = $acceptedDomains
    }

    # Return the tenant settings
    return $TenantSettings
}

function GetEWSSettings {
    param($org)
    # Define the structure of the EWS settings
    $EwsSettings = [PSCustomObject]@{
        EwsAllowList               =$org.EwsAllowList
        EwsApplicationAccessPolicy =$org.EwsApplicationAccessPolicy
        EwsBlockList               =$org.EwsBlockList
        EwsEnabled                 =$org.EwsEnabled
    }

    # Return the EWS settings
    return $EwsSettings
}

function GetBookingsSettings {
    param($OrgConfig)
    # Define the structure of the Bookings settings
    $BookingsSettings = [PSCustomObject]@{
        BookingsEnabled                             =$OrgConfig.BookingsEnabled
        BookingsEnabledLastUpdateTime               =$OrgConfig.BookingsEnabledLastUpdateTime
        BookingsPaymentsEnabled                     =$OrgConfig.BookingsPaymentsEnabled
        BookingsSocialSharingRestricted             =$OrgConfig.BookingsSocialSharingRestricted
        BookingsAddressEntryRestricted              =$OrgConfig.BookingsAddressEntryRestricted
        BookingsAuthEnabled                         =$OrgConfig.BookingsAuthEnabled
        BookingsCreationOfCustomQuestionsRestricted =$OrgConfig.BookingsCreationOfCustomQuestionsRestricted
        BookingsExposureOfStaffDetailsRestricted    =$OrgConfig.BookingsExposureOfStaffDetailsRestricted
        BookingsNotesEntryRestricted                =$OrgConfig.BookingsNotesEntryRestricted
        BookingsPhoneNumberEntryRestricted          =$OrgConfig.BookingsPhoneNumberEntryRestricted
        BookingsMembershipApprovalRequired          =$OrgConfig.BookingsMembershipApprovalRequired
        BookingsSmsMicrosoftEnabled                 =$OrgConfig.BookingsSmsMicrosoftEnabled
        BookingsNamingPolicyEnabled                 =$OrgConfig.BookingsNamingPolicyEnabled
        BookingsBlockedWordsEnabled                 =$OrgConfig.BookingsBlockedWordsEnabled
        BookingsNamingPolicyPrefixEnabled           =$OrgConfig.BookingsNamingPolicyPrefixEnabled
        BookingsNamingPolicyPrefix                  =$OrgConfig.BookingsNamingPolicyPrefix
        BookingsNamingPolicySuffixEnabled           =$OrgConfig.BookingsNamingPolicySuffixEnabled
        BookingsNamingPolicySuffix                  =$OrgConfig.BookingsNamingPolicySuffix
        BookingsSearchEngineIndexDisabled           =$OrgConfig.BookingsSearchEngineIndexDisabled
        IsTenantInGracePeriod                       =$OrgConfig.IsTenantInGracePeriod
        IsTenantAccessBlocked                       =$OrgConfig.IsTenantAccessBlocked
        IsDehydrated                                =$OrgConfig.IsDehydrated
        ServicePlan                                 =$OrgConfig.ServicePlan #check doc for serviceplans accepting Bookings4
    }

    # Return the Bookings settings
    return $BookingsSettings
}

function GetOWAMBPolicy {
    param($policy)
    # Define the structure of the OWA mailbox policy
    $OWAMBPolicy = [PSCustomObject]@{
        BookingsMailboxCreationEnabled = $policy.BookingsMailboxCreationEnabled
        BookingsMailboxDomain          = $policy.BookingsMailboxDomain
    }

    # Return the OWA mailbox policy
    return $OWAMBPolicy
}

function GetAcceptedDomains {
    param($domains)

    # Define the structure of the accepted domains
    $AcceptedDomains = [PSCustomObject]@{
        DomainName         = $domains.DomainName
        Default            = $domains.Default
        AuthenticationType = $domains.AuthenticationType
    }

    # Return the accepted domains
    return $AcceptedDomains
}
