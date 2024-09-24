function Get-BookingTenantSettings {
    param([string] $domain)

    if ($Script:MSSupport) {
        $script:OrgConfig = Get-OrganizationConfig -Organization $domain
        $script:OWAMBPolicy = Get-OwaMailboxPolicy -Organization $domain
        $script:AcceptedDomains = Get-AcceptedDomain -Organization $domain
    } else {
        $script:OrgConfig = Get-OrganizationConfig
        $script:OWAMBPolicy = Get-OwaMailboxPolicy
        $script:AcceptedDomains = Get-AcceptedDomain
    }
    $ewsSettings = Get-EWSSettings $script:OrgConfig
    $bookingsSettings = Get-BookingsSettings $script:OrgConfig
    $OWAMBPolicy = Get-OwaMBPolicy $script:OWAMBPolicy
    $acceptedDomains = Get-AcceptedDomains $script:AcceptedDomains
    # Define the structure of the tenant settings
    $tenantSettings = [PSCustomObject]@{
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
    return $tenantSettings
}

function Get-EWSSettings {
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

function Get-BookingsSettings {
    param($org)
    # Define the structure of the Bookings settings
    $BookingsSettings = [PSCustomObject]@{
        BookingsEnabled                             =$org.BookingsEnabled
        BookingsEnabledLastUpdateTime               =$org.BookingsEnabledLastUpdateTime
        BookingsPaymentsEnabled                     =$org.BookingsPaymentsEnabled
        BookingsSocialSharingRestricted             =$org.BookingsSocialSharingRestricted
        BookingsAddressEntryRestricted              =$org.BookingsAddressEntryRestricted
        BookingsAuthEnabled                         =$org.BookingsAuthEnabled
        BookingsCreationOfCustomQuestionsRestricted =$org.BookingsCreationOfCustomQuestionsRestricted
        BookingsExposureOfStaffDetailsRestricted    =$org.BookingsExposureOfStaffDetailsRestricted
        BookingsNotesEntryRestricted                =$org.BookingsNotesEntryRestricted
        BookingsPhoneNumberEntryRestricted          =$org.BookingsPhoneNumberEntryRestricted
        BookingsMembershipApprovalRequired          =$org.BookingsMembershipApprovalRequired
        BookingsSmsMicrosoftEnabled                 =$org.BookingsSmsMicrosoftEnabled
        BookingsNamingPolicyEnabled                 =$org.BookingsNamingPolicyEnabled
        BookingsBlockedWordsEnabled                 =$org.BookingsBlockedWordsEnabled
        BookingsNamingPolicyPrefixEnabled           =$org.BookingsNamingPolicyPrefixEnabled
        BookingsNamingPolicyPrefix                  =$org.BookingsNamingPolicyPrefix
        BookingsNamingPolicySuffixEnabled           =$org.BookingsNamingPolicySuffixEnabled
        BookingsNamingPolicySuffix                  =$org.BookingsNamingPolicySuffix
        BookingsSearchEngineIndexDisabled           =$org.BookingsSearchEngineIndexDisabled
        IsTenantInGracePeriod                       =$org.IsTenantInGracePeriod
        IsTenantAccessBlocked                       =$org.IsTenantAccessBlocked
        IsDehydrated                                =$org.IsDehydrated
        ServicePlan                                 =$org.ServicePlan #check doc for serviceplans accepting Bookings4
    }

    # Return the Bookings settings
    return $BookingsSettings
}

function Get-OwaMBPolicy {
    param($policy)
    # Define the structure of the OWA mailbox policy
    $OwaMBPolicy = [PSCustomObject]@{
        BookingsMailboxCreationEnabled = $policy.BookingsMailboxCreationEnabled
        BookingsMailboxDomain          = $policy.BookingsMailboxDomain
    }

    # Return the OWA mailbox policy
    return $OwaMBPolicy
}


function Get-AcceptedDomains{
    param($domains)


    # Define the structure of the accepted domains
    $acceptedDomains = [PSCustomObject]@{
        DomainName         = $domains.DomainName
        Default            = $domains.Default
        AuthenticationType = $domains.AuthenticationType
    }

    # Return the accepted domains
    return $acceptedDomains
}