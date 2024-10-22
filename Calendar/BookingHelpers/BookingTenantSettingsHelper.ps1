# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetBookingTenantSettings {
    param([string] $Domain)

    if ($script:MSSupport) {
        $script:OrgConfig = Get-OrganizationConfig -Organization $Domain
        $script:OwaMailboxPolicy = Get-OwaMailboxPolicy -Organization $Domain
        $script:AcceptedDomains = Get-AcceptedDomain -Organization $Domain
    } else {
        $script:OrgConfig = Get-OrganizationConfig
        $script:OwaMailboxPolicy = Get-OwaMailboxPolicy
        $script:AcceptedDomains = Get-AcceptedDomain
    }
    $EwsSettings = GetEWSSettings $script:OrgConfig
    $BookingsSettings =  $script:OrgConfig
    $OwaMailboxPolicy =  $script:OwaMailboxPolicy
    $AcceptedDomains = GetAcceptedDomains $script:AcceptedDomains
    # Define the structure of the tenant settings
    $TenantSettings = [PSCustomObject]@{
        Identity         = $Org.Identity
        Guid             = $Org.Guid
        DisplayName      = $Org.DisplayName
        IsDeHydrated     = $Org.IsDeHydrated
        EWSSettings      = $EwsSettings
        BookingsSettings = $BookingsSettings
        OwaMailboxPolicy = $OwaMailboxPolicy
        AcceptedDomains  = $AcceptedDomains
    }

    # Return the tenant settings
    return $TenantSettings
}

function GetEWSSettings {
    param($Org)
    # Define the structure of the EWS settings
    $EwsSettings = [PSCustomObject]@{
        EwsAllowList               =$Org.EwsAllowList
        EwsApplicationAccessPolicy =$Org.EwsApplicationAccessPolicy
        EwsBlockList               =$Org.EwsBlockList
        EwsEnabled                 =$Org.EwsEnabled
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
        ServicePlan                                 =$OrgConfig.ServicePlan #check doc for service plans accepting Bookings4
    }

    # Return the Bookings settings
    return $BookingsSettings
}

function GetOwaMailboxPolicy {
    param($Policy)
    # Define the structure of the OWA mailbox policy
    $OwaMailboxPolicy = [PSCustomObject]@{
        BookingsMailboxCreationEnabled = $Policy.BookingsMailboxCreationEnabled
        BookingsMailboxDomain          = $Policy.BookingsMailboxDomain
    }

    # Return the OWA mailbox policy
    return $OwaMailboxPolicy
}

function GetAcceptedDomains {
    param($Domains)

    # Define the structure of the accepted domains
    $AcceptedDomains = [PSCustomObject]@{
        DomainName         = $Domains.DomainName
        Default            = $Domains.Default
        AuthenticationType = $Domains.AuthenticationType
    }

    # Return the accepted domains
    return $AcceptedDomains
}
