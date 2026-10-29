# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\XtapHelpers\XtapAnalysisHelpers.ps1
    . $Script:parentPath\XtapHelpers\XtapCollectionHelpers.ps1
    . $Script:parentPath\XtapHelpers\XtapCommandHelpers.ps1
    . $Script:parentPath\XtapHelpers\XtapReportHelpers.ps1
    . $Script:parentPath\XtapHelpers\Invoke-CrossTenantAccessPolicyCalendarValidation.ps1
    . $Script:parentPath\CalendarHelpers\CalendarDiagnosticHelpers.ps1

    $Script:TenantA = "11111111-1111-1111-1111-111111111111"
    $Script:TenantB = "22222222-2222-2222-2222-222222222222"

    function Script:Get-TestRelationship {
        param(
            [string]$Name = "Partner",
            [string[]]$DomainNames = @("partner.com"),
            [bool]$Enabled = $true,
            [bool]$FreeBusy = $true,
            [string]$FreeBusyLevel = "AvailabilityOnly",
            [bool]$MailTips = $false,
            [string]$MailTipsLevel = "None",
            [string]$FreeBusyScope = "",
            [bool]$MailboxMove = $false,
            [string]$MailboxMoveCapability = "None",
            [string[]]$AdditionalFeature = @(),
            [string]$IdentityMoveCapability = "None",
            [string]$ApplicationUri = "outlook.com",
            [string]$AutodiscoverEpr = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc/WSSecurity"
        )

        [PSCustomObject]@{
            Name                   = $Name
            DomainNames            = $DomainNames
            Enabled                = $Enabled
            FreeBusyAccessEnabled  = $FreeBusy
            FreeBusyAccessLevel    = $FreeBusyLevel
            FreeBusyAccessScope    = $FreeBusyScope
            MailTipsAccessEnabled  = $MailTips
            MailTipsAccessLevel    = $MailTipsLevel
            MailTipsAccessScope    = ""
            MailboxMoveEnabled     = $MailboxMove
            MailboxMoveCapability  = $MailboxMoveCapability
            IdentityMoveEnabled    = "IdentityMove" -in $AdditionalFeature
            IdentityMoveCapability = $IdentityMoveCapability
            PeopleSearchEnabled    = "PeopleSearch" -in $AdditionalFeature
            ArchiveAccessEnabled   = "ArchiveAccess" -in $AdditionalFeature
            DeliveryReportEnabled  = "DeliveryReport" -in $AdditionalFeature
            PhotosEnabled          = "Photos" -in $AdditionalFeature
            TargetApplicationUri   = $ApplicationUri
            TargetSharingEpr       = ""
            TargetAutodiscoverEpr  = $AutodiscoverEpr
        }
    }
}

Describe "Endpoint and scenario detection" {
    It "Recognizes Microsoft 365 endpoints" {
        Test-IsMicrosoft365Endpoint -Value "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc/WSSecurity" | Should -BeTrue
        Test-IsMicrosoft365Endpoint -Value "outlook.com" | Should -BeTrue
    }

    It "Recognizes on-premises endpoints" {
        Test-IsMicrosoft365Endpoint -Value "https://autodiscover.contoso.com/autodiscover/autodiscover.svc/WSSecurity" | Should -BeFalse
    }

    It "Returns null for empty values" {
        Test-IsMicrosoft365Endpoint -Value "" | Should -BeNullOrEmpty
    }

    It "Treats the FYDIBOHF25SPDLT application URI as on-premises" {
        Get-XtapTargetScenario -Name "Partner" -Endpoint @("FYDIBOHF25SPDLT.contoso.com") | Should -Be "OnPremisesOrHybrid"
    }

    It "Treats a hybrid-style name as on-premises even with Microsoft 365 endpoints" {
        Get-XtapTargetScenario -Name "O365 to On-premises - 5d61d7ca" -Endpoint @("outlook.com", "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc/WSSecurity") | Should -Be "OnPremisesOrHybrid"
    }

    It "Returns Unknown when there are no endpoints" {
        Get-XtapTargetScenario -Name "Partner" -Endpoint @("", $null) | Should -Be "Unknown"
    }

    It "Rejects an invalid domain without a lookup" {
        Resolve-XtapDomainTenantId -Domain "bad/domain" | Should -BeNullOrEmpty
    }
}

Describe "Tenant resolution diagnostics" {
    BeforeEach {
        $Script:XtapDomainTenantCache = @{}
        $Script:XtapDomainTenantErrors = @{}
        $Script:XtapOfflineData = $false
        $Script:XtapEntraLoginHost = "login.microsoftonline.com"
    }

    Describe "Entra login host validation" {
        It "Rejects invalid lookup host <HostName> before collecting data" -TestCases @(
            @{ HostName = "127.0.0.1" }
            @{ HostName = "login..example.com" }
            @{ HostName = "https://login.microsoftonline.com" }
            @{ HostName = "login.microsoftonline.com:443" }
        ) {
            param($HostName)
            Mock Get-XtapSharingConfiguration { throw "Must not collect data" }
            { Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -EntraLoginHost $HostName } |
                Should -Throw -ExpectedMessage "*isn't a valid host name*"
            Should -Invoke -CommandName Get-XtapSharingConfiguration -Times 0 -Exactly
        }
    }

    It "Caches successful lookups across domain casing and whitespace" {
        Mock Invoke-RestMethod { [PSCustomObject]@{ issuer = "https://login.microsoftonline.com/$Script:TenantA/v2.0" } }
        (Get-XtapDomainTenantResolution -Domain " Partner.com ").TenantId | Should -Be $Script:TenantA
        $result = Get-XtapDomainTenantResolution -Domain "PARTNER.COM"
        $result.Domain | Should -Be "partner.com"
        $result.Status | Should -Be "Resolved"
        $result.Error | Should -BeNullOrEmpty
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly
    }

    It "Caches the specific failure alongside the failed domain" {
        Mock Invoke-RestMethod { throw "Synthetic lookup failure" }
        $first = Get-XtapDomainTenantResolution -Domain "partner.com"
        $second = Get-XtapDomainTenantResolution -Domain "PARTNER.COM"
        $first.Status | Should -Be "Unresolved"
        $first.Error | Should -Be "Synthetic lookup failure"
        $second.Error | Should -Be $first.Error
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly
    }

    It "Reports invalid OpenID issuer metadata" {
        Mock Invoke-RestMethod { [PSCustomObject]@{ issuer = "https://login.microsoftonline.com/common/v2.0" } }
        $result = Get-XtapDomainTenantResolution -Domain "partner.com"
        $result.Status | Should -Be "Unresolved"
        $result.Error | Should -Match "issuer did not contain a valid"
    }

    It "Reports an invalid domain without making a request" {
        Mock Invoke-RestMethod { throw "Must not be called" }
        $result = Get-XtapDomainTenantResolution -Domain "bad/domain"
        $result.Error | Should -Match "not a valid DNS"
        Should -Invoke -CommandName Invoke-RestMethod -Times 0 -Exactly
    }

    It "Explains missing offline lookup data without making a request" {
        $Script:XtapOfflineData = $true
        Mock Invoke-RestMethod { throw "Must not be called" }
        $result = Get-XtapDomainTenantResolution -Domain "missing.com"
        $result.Status | Should -Be "Unresolved"
        $result.Error | Should -Match "No saved tenant resolution"
        Should -Invoke -CommandName Invoke-RestMethod -Times 0 -Exactly
    }

    It "Explains legacy cached failures without inventing a detailed error" {
        $Script:XtapOfflineData = $true
        $Script:XtapDomainTenantCache["partner.com"] = $null
        (Get-XtapDomainTenantResolution -Domain "partner.com").Error | Should -Match "no detailed lookup error was saved"
    }
}

Describe "Get-XtapOrganizationRelationshipAnalysis" {
    BeforeAll {
        Mock Resolve-XtapDomainTenantId { if ($Domain -like "*b.com") { $Script:TenantB } else { $Script:TenantA } }
    }

    It "Marks an availability-only Free/Busy relationship eligible" {
        $result = @(Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship))
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be "Eligible"
        $result[0].FreeBusyCapability | Should -Be "crossTenantCalendarAvailabilityBasic"
    }

    It "Maps LimitedDetails and MailTips levels" {
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -FreeBusyLevel "LimitedDetails" -MailTips $true -MailTipsLevel "Limited")
        $result.FreeBusyCapability | Should -Be "crossTenantCalendarAvailabilityLimitedDetails"
        $result.MailTipsCapability | Should -Be "crossTenantMailTipsLimited"
    }

    It "Marks hybrid relationships not eligible and clears the capability" {
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -Name "O365 to On-premises - abc")
        $result.Status | Should -Be "NotEligible"
        $result.FreeBusyCapability | Should -BeNullOrEmpty
    }

    It "Marks on-premises endpoints not eligible" {
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -ApplicationUri "FYDIBOHF25SPDLT.contoso.com" -AutodiscoverEpr "https://autodiscover.contoso.com/autodiscover/autodiscover.svc/WSSecurity")
        $result.Status | Should -Be "NotEligible"
    }

    It "Marks disabled relationships as Disabled" {
        (Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -Enabled $false)).Status | Should -Be "Disabled"
    }

    It "Marks mailbox-move-only relationships" {
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -FreeBusy $false -MailboxMove $true -MailboxMoveCapability "RemoteOutbound")
        $result.Status | Should -Be "MailboxMoveOnly"
    }

    It "Flags relationships that also move mailboxes" {
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -MailboxMove $true -MailboxMoveCapability "RemoteOutbound")
        $result.Status | Should -Be "Eligible"
        $result.HasMailboxMoveAndSharing | Should -BeTrue
    }

    It "Flags a scoped Free/Busy relationship" {
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -FreeBusyScope "SomeGroup")
        $result.FreeBusyScoped | Should -BeTrue
        $result.Notes | Should -Match "security group"
    }

    It "Resolves tenant IDs and detects multiple tenants" {
        $result = Get-XtapOrganizationRelationshipAnalysis -ResolveTenantId -OrganizationRelationship (Get-TestRelationship -DomainNames @("a.com", "b.com"))
        $result.MultipleTenants | Should -BeTrue
        $result.PartnerTenantIds | Should -Be "$($Script:TenantA);$($Script:TenantB)"
    }

    It "Needs review when no domain resolves" {
        Mock Resolve-XtapDomainTenantId { $null }
        (Get-XtapOrganizationRelationshipAnalysis -ResolveTenantId -OrganizationRelationship (Get-TestRelationship)).Status | Should -Be "Review"
    }

    It "Detects and preserves additional <Feature> functionality" -TestCases @(
        @{ Feature = "IdentityMove" }
        @{ Feature = "PeopleSearch" }
        @{ Feature = "ArchiveAccess" }
        @{ Feature = "DeliveryReport" }
        @{ Feature = "Photos" }
    ) {
        param($Feature)
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -AdditionalFeature $Feature)
        $result.Status | Should -Be "Eligible"
        $result.HasAdditionalEnabledFunctionalities | Should -BeTrue
        $result.HasAdditionalFunctionalitiesAndSharing | Should -BeTrue
        $result.AdditionalEnabledFunctionalities | Should -Be $Feature
        $result.AdditionalFunctionalitiesRecommendation | Should -Match "Preserve this Organization Relationship"
    }

    It "Detects IdentityMove from its capability without its enabled flag" {
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship -IdentityMoveCapability "RemoteOutbound")
        $result.AdditionalEnabledFunctionalities | Should -Be "IdentityMove"
    }

    It "Lists every additional feature and preserves relationships with no sharing" {
        $result = Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (
            Get-TestRelationship -FreeBusy $false -MailboxMove $true -AdditionalFeature @("IdentityMove", "PeopleSearch", "ArchiveAccess", "DeliveryReport", "Photos"))
        $result.Status | Should -Be "MailboxMoveOnly"
        $result.AdditionalEnabledFunctionalities | Should -Be "MailboxMove;IdentityMove;PeopleSearch;ArchiveAccess;DeliveryReport;Photos"
        $result.HasAdditionalFunctionalitiesAndSharing | Should -BeFalse
        $result.DomainTenantResolution.Count | Should -Be 0
    }

    It "Requires review when only some domains resolve" {
        Mock Resolve-XtapDomainTenantId { if ($Domain -eq "good.com") { $Script:TenantA } }
        $result = Get-XtapOrganizationRelationshipAnalysis -ResolveTenantId -OrganizationRelationship (
            Get-TestRelationship -DomainNames @("good.com", "missing.com"))
        $result.Status | Should -Be "Review"
        $result.PartnerTenantIds | Should -Be $Script:TenantA
        $result.UnresolvedDomains | Should -Be "missing.com"
        $result.DomainTenantResolution.Count | Should -Be 2
        $result.DomainTenantResolution[1].Status | Should -Be "Unresolved"
        $result.Notes | Should -Match "Every relationship domain must resolve"
        $result.SharingCapabilityWouldBeEligibleIfEnabled | Should -BeFalse
    }

    It "Requires domains even when ResolveTenantId is <Resolve>" -TestCases @(
        @{ Resolve = $true }
        @{ Resolve = $false }
    ) {
        param($Resolve)
        $result = Get-XtapOrganizationRelationshipAnalysis -ResolveTenantId:$Resolve -OrganizationRelationship (
            Get-TestRelationship -DomainNames @())
        $result.Status | Should -Be "Review"
        $result.Notes | Should -Match "no domain names"
    }

    It "Assesses disabled relationships without making them command eligible" {
        $result = Get-XtapOrganizationRelationshipAnalysis -ResolveTenantId -OrganizationRelationship (
            Get-TestRelationship -Enabled $false -MailTips $true -MailTipsLevel "All" -FreeBusyScope "SomeGroup")
        $result.Status | Should -Be "Disabled"
        $result.PartnerTenantIds | Should -Be $Script:TenantA
        $result.SharingCapabilityWouldBeEligibleIfEnabled | Should -BeTrue
        $result.FreeBusyCapabilityIfEnabled | Should -Be "crossTenantCalendarAvailabilityBasic"
        $result.MailTipsCapabilityIfEnabled | Should -Be "crossTenantMailTipsAll"
        $result.FreeBusyCapability | Should -BeNullOrEmpty
        $result.MailTipsCapability | Should -BeNullOrEmpty
        $result.Notes | Should -Match "If enabled"
    }

    It "Does not recommend disabled hybrid or unresolved relationships" {
        Mock Resolve-XtapDomainTenantId { $null }
        foreach ($relationship in @(
                (Get-TestRelationship -Enabled $false -Name "Hybrid"),
                (Get-TestRelationship -Enabled $false)
            )) {
            $result = Get-XtapOrganizationRelationshipAnalysis -ResolveTenantId -OrganizationRelationship $relationship
            $result.Status | Should -Be "Disabled"
            $result.SharingCapabilityWouldBeEligibleIfEnabled | Should -BeFalse
            $result.FreeBusyCapabilityIfEnabled | Should -BeNullOrEmpty
        }
    }
}

Describe "Get-XtapAvailabilityAddressSpaceAnalysis" {
    It "Marks OrgWideFBToken with a tenant ID eligible" {
        $space = [PSCustomObject]@{ Name = "contoso.com"; ForestName = "contoso.com"; AccessMethod = "OrgWideFBToken"; TargetTenantId = $Script:TenantA; TargetAutodiscoverEpr = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" }
        $result = Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space
        $result.Status | Should -Be "Eligible"
        $result.TargetTenantId | Should -Be $Script:TenantA
    }

    It "Marks other access methods not eligible" {
        $space = [PSCustomObject]@{ Name = "contoso.com"; ForestName = "contoso.com"; AccessMethod = "OrgWideFB"; TargetAutodiscoverEpr = "https://autodiscover.contoso.com/autodiscover/autodiscover.svc" }
        (Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space).Status | Should -Be "NotEligible"
    }

    It "Marks Google Workspace not eligible" {
        $space = [PSCustomObject]@{ Name = "g.com"; ForestName = "g.com"; AccessMethod = "OrgWideFBToken"; TargetAutodiscoverEpr = "https://calendar.google.com/x" }
        (Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space).Status | Should -Be "NotEligible"
    }

    It "Gives the hybrid marker precedence over a valid tenant ID in <Endpoint>" -TestCases @(
        @{ Endpoint = "TargetServiceEpr" }
        @{ Endpoint = "TargetAutodiscoverEpr" }
        @{ Endpoint = "ProxyUrl" }
    ) {
        param($Endpoint)
        $space = [PSCustomObject]@{ Name = "Hybrid"; ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetTenantId = $Script:TenantA }
        $space | Add-Member -NotePropertyName $Endpoint -NotePropertyValue "https://FYDIBOHF25SPDLT.contoso.com/ews"
        $result = Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space
        $result.Status | Should -Be "NotEligible"
        $result.Scenario | Should -Be "OnPremisesOrHybrid"
        $result.RecommendedCapability | Should -BeNullOrEmpty
    }

    It "Distinguishes an invalid configured tenant ID from a missing one" {
        Mock Resolve-XtapDomainTenantId { $Script:TenantA }
        $space = [PSCustomObject]@{ Name = "Invalid"; ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetTenantId = "not-a-guid"; TargetServiceEpr = "https://outlook.office365.com/ews" }
        $result = Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space -ResolveTenantId
        $result.Status | Should -Be "Review"
        $result.ConfiguredTargetTenantId | Should -Be "not-a-guid"
        $result.TargetTenantIdValid | Should -BeFalse
        $result.TargetTenantId | Should -BeNullOrEmpty
        $result.TenantResolutionStatus | Should -Be "Invalid"
        $result.TenantResolutionError | Should -Match "not a valid GUID"
        Should -Invoke -CommandName Resolve-XtapDomainTenantId -Times 0 -Exactly
    }

    It "Resolves missing tenant IDs and retains the original configured value" {
        Mock Resolve-XtapDomainTenantId { $Script:TenantA }
        $space = [PSCustomObject]@{ Name = "Missing"; ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetServiceEpr = "https://outlook.office365.com/ews" }
        $result = Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space -ResolveTenantId
        $result.Status | Should -Be "Eligible"
        $result.ConfiguredTargetTenantId | Should -BeNullOrEmpty
        $result.ResolvedEntraTenantId | Should -Be $Script:TenantA
        $result.TenantResolutionStatus | Should -Be "Resolved"
        $result.MigrationRecommendation | Should -Match "not required because of EWS"
    }

    It "Normalizes valid GUID representations for <TenantId>" -TestCases @(
        @{ TenantId = "{11111111-1111-1111-1111-111111111111}" }
        @{ TenantId = "11111111111111111111111111111111" }
    ) {
        param($TenantId)
        $space = [PSCustomObject]@{ Name = "Partner"; ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetTenantId = $TenantId }
        $result = Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space
        $result.Status | Should -Be "Eligible"
        $result.TargetTenantIdValid | Should -BeTrue
        $result.ConfiguredTargetTenantId | Should -Be $TenantId
        $result.TargetTenantId | Should -Be $Script:TenantA
        $result.TenantResolutionStatus | Should -Be "Provided"
    }

    It "Does not let a valid tenant ID override Google Workspace endpoints" {
        $space = [PSCustomObject]@{ Name = "Google"; ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetTenantId = $Script:TenantA; TargetServiceEpr = "https://calendar.google.com/ews" }
        $result = Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space
        $result.Status | Should -Be "NotEligible"
        $result.Scenario | Should -Be "GoogleWorkspace"
    }
}

Describe "Get-XtapSharingPolicyAnalysis" {
    BeforeAll {
        Mock Resolve-XtapDomainTenantId { $Script:TenantA }
    }

    It "Maps wildcard and anonymous calendar rules" {
        $policy = [PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple", "Anonymous:CalendarSharingFreeBusyReviewer") }
        $result = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy)
        $result.Count | Should -Be 2
        $result[0].RecommendedCapability | Should -Be "CrossTenantCalendarSharingFreeBusySimple"
        $result[1].RecommendedCapability | Should -Be "AnonymousCalendarSharingFreeBusyReviewer"
        $result[0].Status | Should -Be "Eligible"
    }

    It "Splits multiple actions into rows and rejects ContactsSharing" {
        $policy = [PSCustomObject]@{ Name = "P"; Enabled = $true; Default = $false; Domains = @("*:CalendarSharingFreeBusySimple,ContactsSharing") }
        $result = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy)
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.AccessLevel -eq "ContactsSharing" }).Status | Should -Be "NotEligible"
    }

    It "Needs review for domain rules when tenant lookup is skipped" {
        $policy = [PSCustomObject]@{ Name = "P"; Enabled = $true; Default = $false; Domains = @("partner.com:CalendarSharingFreeBusyDetail") }
        (Get-XtapSharingPolicyAnalysis -SharingPolicy $policy).Status | Should -Be "Review"
    }

    It "Resolves domain rules to a tenant ID" {
        $policy = [PSCustomObject]@{ Name = "P"; Enabled = $true; Default = $false; Domains = @("partner.com:CalendarSharingFreeBusyDetail") }
        $result = Get-XtapSharingPolicyAnalysis -SharingPolicy $policy -ResolveTenantId
        $result.Status | Should -Be "Eligible"
        $result.PartnerTenantId | Should -Be $Script:TenantA
    }

    It "Rejects domains that belong to hybrid relationships" {
        $policy = [PSCustomObject]@{ Name = "P"; Enabled = $true; Default = $false; Domains = @("Hybrid.com:CalendarSharingFreeBusySimple") }
        (Get-XtapSharingPolicyAnalysis -SharingPolicy $policy -HybridDomain @("hybrid.com") -ResolveTenantId).Status | Should -Be "NotEligible"
    }

    It "Marks rules of a disabled policy as Disabled" {
        $policy = [PSCustomObject]@{ Name = "P"; Enabled = $false; Default = $false; Domains = @("*:CalendarSharingFreeBusySimple") }
        (Get-XtapSharingPolicyAnalysis -SharingPolicy $policy).Status | Should -Be "Disabled"
    }

    It "Reports the assigned mailbox count" {
        $policy = [PSCustomObject]@{ Name = "P"; Enabled = $true; Default = $false; Domains = @("*:CalendarSharingFreeBusySimple") }
        $assignment = [PSCustomObject]@{ Name = "P"; Count = 7 }
        (Get-XtapSharingPolicyAnalysis -SharingPolicy $policy -SharingPolicyAssignment $assignment).AssignedMailboxCount | Should -Be 7
    }

    It "Counts implicit assignments only for the default policy with <AssignmentName> names" -TestCases @(
        @{ AssignmentName = "" }
        @{ AssignmentName = $null }
    ) {
        param($AssignmentName)
        $policies = @(
            [PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") },
            [PSCustomObject]@{ Name = "Other"; Enabled = $true; Default = $false; Domains = @("*:CalendarSharingFreeBusyReviewer") })
        $assignments = @(
            [PSCustomObject]@{ Name = "Default"; Count = 2 },
            [PSCustomObject]@{ Name = $AssignmentName; Count = 5 },
            [PSCustomObject]@{ Name = "Other"; Count = 3 })

        $analysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policies -SharingPolicyAssignment $assignments)

        $analysis[0].AssignedMailboxCount | Should -Be 7
        $analysis[1].AssignedMailboxCount | Should -Be 3
    }

    It "Distinguishes implicit-only, empty, and uncollected assignments" {
        $policy = [PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") }
        $assignments = @([PSCustomObject]@{ Name = ""; Count = 5 })

        (Get-XtapSharingPolicyAnalysis -SharingPolicy $policy -SharingPolicyAssignment $assignments).AssignedMailboxCount | Should -Be 5
        (Get-XtapSharingPolicyAnalysis -SharingPolicy $policy -SharingPolicyAssignment @()).AssignedMailboxCount | Should -Be 0
        (Get-XtapSharingPolicyAnalysis -SharingPolicy $policy).AssignedMailboxCount | Should -BeNullOrEmpty
    }

    It "Preserves ContactsSharing on the entire combined rule" {
        $policy = [PSCustomObject]@{ Name = "P"; Enabled = $true; Default = $false; Domains = @("*:CalendarSharingFreeBusySimple,ContactsSharing") }
        $result = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy)
        $result[0].Status | Should -Be "Eligible"
        foreach ($row in $result) {
            $row.HasContactsSharing | Should -BeTrue
            $row.LegacyRuleCanBeRetired | Should -BeFalse
            $row.ContactsSharingAssessment | Should -Match "Preserve this legacy rule"
        }
    }

    It "Only allows retiring fully supported eligible rules" {
        foreach ($entry in @("*:CalendarSharingFreeBusySimple", "*:CalendarSharingFreeBusySimple,UnknownAction")) {
            $policy = [PSCustomObject]@{ Name = "P"; Enabled = $true; Default = $true; Domains = @($entry) }
            $result = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy)
            $result[0].LegacyRuleCanBeRetired | Should -Be ($entry -notmatch "UnknownAction")
        }
    }

    It "Assesses disabled domain rules and keeps active capabilities empty" {
        $policy = [PSCustomObject]@{ Name = "P"; Enabled = $false; Default = $false; Domains = @("partner.com:CalendarSharingFreeBusyDetail,ContactsSharing") }
        $result = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy -ResolveTenantId)
        $result[0].Status | Should -Be "Disabled"
        $result[0].CalendarCapabilityWouldBeEligibleIfEnabled | Should -BeTrue
        $result[0].RecommendedCapabilityIfEnabled | Should -Be "CrossTenantCalendarSharingFreeBusyDetail"
        $result[0].RecommendedCapability | Should -BeNullOrEmpty
        $result[0].LegacyRuleCanBeRetired | Should -BeFalse
        $result[1].CalendarCapabilityWouldBeEligibleIfEnabled | Should -BeFalse
    }
}

Describe "Get-XtapCommandScript" {
    BeforeAll {
        Mock Resolve-XtapDomainTenantId { $Script:TenantA }
        $relationships = @(
            (Get-TestRelationship -Name "Contoso's Partner" -DomainNames @("partner.com")),
            (Get-TestRelationship -Name "Split" -DomainNames @("split.com") -MailboxMove $true -MailboxMoveCapability "RemoteOutbound"),
            (Get-TestRelationship -Name "O365 to On-premises - abc" -DomainNames @("onprem.com"))
        )
        $Script:orgAnalysis = @(Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship $relationships -ResolveTenantId)
        $Script:sharingAnalysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy ([PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") }))
        $Script:scripts = Get-XtapCommandScript -OrganizationRelationshipAnalysis $Script:orgAnalysis -AvailabilityAddressSpaceAnalysis @() -SharingPolicyAnalysis $Script:sharingAnalysis -RunName "BeforeMigration"
    }

    It "Returns the four scripts" {
        @($Script:scripts.Keys) | Should -Be @("XTAP_Part2_CreatePolicies.ps1", "XTAP_Part3_DisableForTesting.ps1", "XTAP_Part3_Rollback.ps1", "XTAP_Part4_Cleanup.ps1")
    }

    It "Generates Part 2 for a standalone <RuleType> sharing rule" -TestCases @(
        @{ RuleType = "Wildcard"; Domain = "*"; Capability = "CrossTenantCalendarSharingFreeBusySimple" }
        @{ RuleType = "Anonymous"; Domain = "Anonymous"; Capability = "AnonymousCalendarSharingFreeBusySimple" }
    ) {
        param($RuleType, $Domain, $Capability)
        $policy = [PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("${Domain}:CalendarSharingFreeBusySimple") }
        $analysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy)

        $generated = Get-XtapCommandScript -SharingPolicyAnalysis $analysis

        @($generated.Keys) | Should -Be @("XTAP_Part2_CreatePolicies.ps1", "XTAP_Part3_DisableForTesting.ps1", "XTAP_Part3_Rollback.ps1", "XTAP_Part4_Cleanup.ps1")
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "(?m)^Add-XtapCapability -Capability '$Capability' -ResourceType group -ResourceId '<SecurityGroupObjectId for Sharing Policy Default>'"
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Not -Match "(?m)^Set-XtapPartnerTrust -PartnerTenantId"
        foreach ($name in $generated.Keys) {
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($generated[$name], [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0 -Because $name
        }
    }

    It "Excludes a confirmed-unused higher-access policy from every generated script" {
        $policies = @(
            [PSCustomObject]@{ Name = "Basic"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") },
            [PSCustomObject]@{ Name = "Reviewer"; Enabled = $true; Default = $false; Domains = @("*:CalendarSharingFreeBusyReviewer") })
        $analysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policies -SharingPolicyAssignment @(
                [PSCustomObject]@{ Name = ""; Count = 5 }))

        $generated = Get-XtapCommandScript -SharingPolicyAnalysis $analysis

        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "CrossTenantCalendarSharingFreeBusySimple"
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "<SecurityGroupObjectId for Sharing Policy Basic>"
        foreach ($name in $generated.Keys) {
            $generated[$name] | Should -Not -Match "Reviewer"
        }
    }

    It "Generates no Sharing Policy commands when collected assignments are empty" {
        $analysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy (
                [PSCustomObject]@{ Name = "Unused"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") }) -SharingPolicyAssignment @())

        (Get-XtapCommandScript -SharingPolicyAnalysis $analysis).Count | Should -Be 0
    }

    It "Guards Sharing Policy scopes with <Counts> mailbox counts" -TestCases @(
        @{ Counts = "uncollected"; Assignments = $null }
        @{ Counts = "one policy"; Assignments = @([PSCustomObject]@{ Name = "Basic"; Count = 5 }) }
        @{ Counts = "multiple policies"; Assignments = @([PSCustomObject]@{ Name = "Basic"; Count = 5 }, [PSCustomObject]@{ Name = "Reviewer"; Count = 3 }) }
    ) {
        param($Counts, $Assignments)
        $policies = @(
            [PSCustomObject]@{ Name = "Basic"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") },
            [PSCustomObject]@{ Name = "Reviewer"; Enabled = $true; Default = $false; Domains = @("*:CalendarSharingFreeBusyReviewer") })
        $analysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policies -SharingPolicyAssignment $Assignments)

        $generated = Get-XtapCommandScript -SharingPolicyAnalysis $analysis
        $part2 = $generated["XTAP_Part2_CreatePolicies.ps1"]
        $part2 | Should -Match "<SecurityGroupObjectId for Sharing Policy Basic>"
        $part2 | Should -Not -Match "(?m)^Add-XtapCapability .* -ResourceId 'All'"

        $ast = [System.Management.Automation.Language.Parser]::ParseInput($part2, [ref]$null, [ref]$null)
        $helpers = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @("Assert-XtapInput", "Add-XtapCapability")
            }, $true)
        foreach ($helper in $helpers) {
            . ([ScriptBlock]::Create($helper.Extent.Text))
        }
        { Add-XtapCapability -Capability "CrossTenantCalendarSharingFreeBusySimple" -ResourceType "group" -ResourceId "<SecurityGroupObjectId for Sharing Policy Basic>" -ODataPrefix "#microsoft.graph." } |
            Should -Throw -ExpectedMessage "*Replace the security group placeholder*"
    }

    It "Generates scripts that parse without errors" {
        foreach ($name in $Script:scripts.Keys) {
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($Script:scripts[$name], [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0 -Because $name
        }
    }

    It "Uses the resolved tenant ID in Part 2" {
        $Script:scripts["XTAP_Part2_CreatePolicies.ps1"] | Should -Match $Script:TenantA
    }

    It "Escapes single quotes in names" {
        $Script:scripts["XTAP_Part3_DisableForTesting.ps1"] | Should -Match "'Contoso''s Partner'"
    }

    It "Only turns off sharing on relationships that also move mailboxes" {
        $Script:scripts["XTAP_Part3_DisableForTesting.ps1"] | Should -Match "(?m)^Set-OrganizationRelationship -Identity 'Split' -FreeBusyAccessEnabled \`$false"
        $Script:scripts["XTAP_Part4_Cleanup.ps1"] | Should -Match "(?m)^# Set-OrganizationRelationship -Identity 'Split' -FreeBusyAccessEnabled \`$false"
        foreach ($name in @("XTAP_Part3_DisableForTesting.ps1", "XTAP_Part4_Cleanup.ps1")) {
            $Script:scripts[$name] | Should -Not -Match "(Set|Remove)-OrganizationRelationship -Identity 'Split' (-Enabled|-Confirm)"
        }

        $Script:scripts["XTAP_Part3_Rollback.ps1"] | Should -Match "Set-OrganizationRelationship -Identity 'Split' -FreeBusyAccessEnabled \`$true -FreeBusyAccessLevel 'AvailabilityOnly'"
    }

    It "Leaves not eligible relationships out of Part 3 and Part 4" {
        foreach ($name in @("XTAP_Part3_DisableForTesting.ps1", "XTAP_Part4_Cleanup.ps1")) {
            $Script:scripts[$name] | Should -Not -Match "On-premises"
        }
    }

    It "Targets the specified organization in the generated scripts" {
        $generated = Get-XtapCommandScript -OrganizationRelationshipAnalysis $Script:orgAnalysis -AvailabilityAddressSpaceAnalysis @() -SharingPolicyAnalysis $Script:sharingAnalysis -RunName "BeforeMigration" -Organization "contoso.onmicrosoft.com"
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "Connect-MgGraph .*-TenantId 'contoso.onmicrosoft.com'"
        $generated["XTAP_Part3_DisableForTesting.ps1"] | Should -Match "Set-OrganizationRelationship -Identity 'Contoso''s Partner' -Enabled \`$false -Organization 'contoso.onmicrosoft.com'"
        $generated["XTAP_Part4_Cleanup.ps1"] | Should -Match "(?m)^# Remove-SharingPolicy .* -Organization 'contoso.onmicrosoft.com'"
        foreach ($name in $generated.Keys) {
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($generated[$name], [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0 -Because $name
        }
    }

    It "Uses placeholders guarded by an assertion when tenant IDs are unknown" {
        $unresolved = @(Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship))
        $generated = Get-XtapCommandScript -OrganizationRelationshipAnalysis $unresolved -AvailabilityAddressSpaceAnalysis @() -SharingPolicyAnalysis @() -RunName "BeforeMigration"
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "<PartnerTenantId"
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "function Assert-XtapInput"
    }

    It "Makes Step 4 inert until the administrator deliberately enables cleanup" {
        $cleanup = $Script:scripts["XTAP_Part4_Cleanup.ps1"]
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($cleanup, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
        $ast.EndBlock.Statements.Count | Should -Be 0
        $cleanup | Should -Match "(?m)^# Remove-OrganizationRelationship -Identity 'Contoso''s Partner'"
        $cleanup | Should -Match "(?m)^# Remove-SharingPolicy -Identity 'Default'"
        $cleanup | Should -Match "(?m)^# Set-OrganizationRelationship -Identity 'Split'"
        $cleanup | Should -Match "uncomment"
        $cleanup | Should -Match "Deletion is permanent"
        @(& ([ScriptBlock]::Create($cleanup))).Count | Should -Be 0
    }

    It "Explains assignment and default-policy prerequisites before removing a Sharing Policy" {
        $cleanup = $Script:scripts["XTAP_Part4_Cleanup.ps1"]

        $cleanup | Should -Match "Keep Sharing Policy 'Default' disabled until all mailbox assignments have been removed or reassigned"
        $cleanup | Should -Match "default Sharing Policy, select a replacement default policy before removal"
        $cleanup | Should -Match "no mailboxes remain assigned to it and it is no longer the default"
        $cleanup.IndexOf("all mailbox assignments") | Should -BeLessThan $cleanup.IndexOf("# Remove-SharingPolicy")
    }

    Describe "Generated Graph commands" {
        BeforeAll {
            function Connect-MgGraph { [CmdletBinding()] param($Scopes, $TenantId, $ContextScope) }
            function Get-MgPolicyCrossTenantAccessPolicyPartner { [CmdletBinding()] param($CrossTenantAccessPolicyConfigurationPartnerTenantId) }
            function New-MgPolicyCrossTenantAccessPolicyPartner {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Justification = "Mocked Graph cmdlet used to test generated scripts.")]
                [CmdletBinding()]
                param($BodyParameter)
            }
            function Update-MgPolicyCrossTenantAccessPolicyPartner {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Justification = "Mocked Graph cmdlet used to test generated scripts.")]
                [CmdletBinding()]
                param($CrossTenantAccessPolicyConfigurationPartnerTenantId, $BodyParameter)
            }
            function New-MgPolicyCrossTenantAccessPolicyPartnerM365Capability {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Justification = "Mocked Graph cmdlet used to test generated scripts.")]
                [CmdletBinding()]
                param($CrossTenantAccessPolicyConfigurationPartnerTenantId, $BodyParameter)
            }
            function New-MgPolicyCrossTenantAccessPolicyDefaultM365Capability {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "", Justification = "Mocked Graph cmdlet used to test generated scripts.")]
                [CmdletBinding()]
                param($BodyParameter)
            }

            $ast = [System.Management.Automation.Language.Parser]::ParseInput($Script:scripts["XTAP_Part2_CreatePolicies.ps1"], [ref]$null, [ref]$null)
            $helpers = $ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
                }, $true)
            foreach ($helper in $helpers) {
                . ([ScriptBlock]::Create($helper.Extent.Text))
            }
        }

        BeforeEach {
            Mock Connect-MgGraph {}
            Mock Get-MgPolicyCrossTenantAccessPolicyPartner { $null }
            Mock New-MgPolicyCrossTenantAccessPolicyPartner {}
            Mock Update-MgPolicyCrossTenantAccessPolicyPartner {}
            Mock New-MgPolicyCrossTenantAccessPolicyPartnerM365Capability {}
            Mock New-MgPolicyCrossTenantAccessPolicyDefaultM365Capability {}
            $Script:trustMessage = ""
            Mock Write-Host { $Script:trustMessage = "$Object" }
        }

        It "Stops the generated Part 2 script when a <Target> capability fails" -TestCases @(
            @{ Target = "Partner" }
            @{ Target = "Default" }
        ) {
            param($Target)
            Mock New-MgPolicyCrossTenantAccessPolicyPartnerM365Capability { throw "Capability creation failed" }
            Mock New-MgPolicyCrossTenantAccessPolicyDefaultM365Capability { throw "Capability creation failed" }
            $generated = if ($Target -eq "Partner") {
                Get-XtapCommandScript -OrganizationRelationshipAnalysis $Script:orgAnalysis
            } else {
                Get-XtapCommandScript -SharingPolicyAnalysis $Script:sharingAnalysis
            }
            $text = $generated["XTAP_Part2_CreatePolicies.ps1"].Replace("<SecurityGroupObjectId for Sharing Policy Default>", $Script:TenantA)
            $path = Join-Path -Path $TestDrive -ChildPath "Part2_$Target.ps1"
            Write-XtapTextFile -Path $path -Text ($text + "`r`nWrite-Host 'Must not continue'")

            { & $path } | Should -Throw -ExpectedMessage "*Failed to create*Capability creation failed*"

            Should -Invoke -CommandName Write-Host -Times 0 -Exactly -ParameterFilter { $Object -eq "Must not continue" }
        }

        It "Creates a <Target> capability successfully" -TestCases @(
            @{ Target = "Partner" }
            @{ Target = "Default" }
        ) {
            param($Target)
            $parameters = @{ Capability = "crossTenantCalendarAvailabilityBasic"; ResourceType = "user"; ResourceId = "All"; ODataPrefix = "microsoft.graph." }
            if ($Target -eq "Partner") { $parameters.PartnerTenantId = $Script:TenantA }

            Add-XtapCapability @parameters

            $commandName = "New-MgPolicyCrossTenantAccessPolicy${Target}M365Capability"
            Should -Invoke -CommandName $commandName -Times 1 -Exactly -ParameterFilter { $ErrorAction -eq "Stop" }
            Should -Invoke -CommandName Write-Host -Times 1 -Exactly -ParameterFilter { $Object -like "Created crossTenantCalendarAvailabilityBasic for *" }
        }

        It "Stops without reporting success when trust <Operation> raises a non-terminating error" -TestCases @(
            @{ Operation = "creation"; Existing = $null }
            @{ Operation = "update"; Existing = [PSCustomObject]@{ AdditionalProperties = @{} } }
        ) {
            param($Operation, $Existing)
            $Script:existingPartner = $Existing
            Mock Get-MgPolicyCrossTenantAccessPolicyPartner { $Script:existingPartner }
            Mock New-MgPolicyCrossTenantAccessPolicyPartner { Write-Error -Message "Trust write failed" }
            Mock Update-MgPolicyCrossTenantAccessPolicyPartner { Write-Error -Message "Trust write failed" }

            { Set-XtapPartnerTrust -PartnerTenantId $Script:TenantA } | Should -Throw -ExpectedMessage "*Trust write failed*"

            Should -Invoke -CommandName Write-Host -Times 0 -Exactly
            $commandName = if ($Operation -eq "creation") { "New-MgPolicyCrossTenantAccessPolicyPartner" } else { "Update-MgPolicyCrossTenantAccessPolicyPartner" }
            Should -Invoke -CommandName $commandName -Times 1 -Exactly -ParameterFilter { $ErrorAction -eq "Stop" }
        }

        It "Reports success after trust <Operation> succeeds" -TestCases @(
            @{ Operation = "creation"; Existing = $null; Message = "Created" }
            @{ Operation = "update"; Existing = [PSCustomObject]@{ AdditionalProperties = @{} }; Message = "Enabled" }
        ) {
            param($Operation, $Existing, $Message)
            $Script:existingPartner = $Existing
            Mock Get-MgPolicyCrossTenantAccessPolicyPartner { $Script:existingPartner }

            Set-XtapPartnerTrust -PartnerTenantId $Script:TenantA

            Should -Invoke -CommandName Write-Host -Times 1 -Exactly
            $Script:trustMessage | Should -Be "$Message the Microsoft 365 Collaboration trust for $($Script:TenantA)."
        }
    }

    It "Includes the run label and timestamp in generated headers" {
        foreach ($name in $Script:scripts.Keys) {
            $Script:scripts[$name] | Should -Match "for run 'BeforeMigration' on \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
        }
    }

    It "Only changes sharing settings when <Feature> must be preserved" -TestCases @(
        @{ Feature = "IdentityMove" }
        @{ Feature = "PeopleSearch" }
        @{ Feature = "ArchiveAccess" }
        @{ Feature = "DeliveryReport" }
        @{ Feature = "Photos" }
    ) {
        param($Feature)
        $analysis = @(Get-XtapOrganizationRelationshipAnalysis -ResolveTenantId -OrganizationRelationship (
                Get-TestRelationship -Name "Preserved" -AdditionalFeature $Feature -MailTips $true -MailTipsLevel "All" -FreeBusyScope "SomeGroup"))
        $generated = Get-XtapCommandScript -OrganizationRelationshipAnalysis $analysis
        $generated["XTAP_Part3_DisableForTesting.ps1"] | Should -Match "Set-OrganizationRelationship -Identity 'Preserved' -FreeBusyAccessEnabled \`$false -MailTipsAccessEnabled \`$false"
        $generated["XTAP_Part4_Cleanup.ps1"] | Should -Match "(?m)^# Set-OrganizationRelationship -Identity 'Preserved' -FreeBusyAccessEnabled"
        $generated["XTAP_Part3_Rollback.ps1"] | Should -Match "-FreeBusyAccessScope 'SomeGroup'.*-MailTipsAccessEnabled \`$true -MailTipsAccessLevel 'All'"
        foreach ($name in $generated.Keys) {
            $generated[$name] | Should -Not -Match "Remove-OrganizationRelationship|Set-OrganizationRelationship -Identity 'Preserved' -Enabled"
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($generated[$name], [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0
        }
    }

    It "Generates no commands for partially resolved or disabled relationships" {
        Mock Resolve-XtapDomainTenantId { if ($Domain -eq "good.com") { $Script:TenantA } }
        $analysis = @(Get-XtapOrganizationRelationshipAnalysis -ResolveTenantId -OrganizationRelationship @(
                (Get-TestRelationship -Name "Partial" -DomainNames @("good.com", "missing.com")),
                (Get-TestRelationship -Enabled $false -DomainNames @("good.com")))
        )
        $generated = Get-XtapCommandScript -OrganizationRelationshipAnalysis $analysis
        $generated.Count | Should -Be 0
    }

    It "Does not disable or remove policies containing mixed calendar and contacts rules" {
        $policy = [PSCustomObject]@{ Name = "Mixed"; Enabled = $true; Default = $true; Domains = @("partner.com:CalendarSharingFreeBusySimple,ContactsSharing") }
        $analysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy -ResolveTenantId)
        $generated = Get-XtapCommandScript -SharingPolicyAnalysis $analysis
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "CrossTenantCalendarSharingFreeBusySimple"
        $generated.Keys | Should -Not -Contain "XTAP_Part3_DisableForTesting.ps1"
        $generated.Keys | Should -Not -Contain "XTAP_Part4_Cleanup.ps1"
        $withPartner = Get-XtapCommandScript -OrganizationRelationshipAnalysis $Script:orgAnalysis -SharingPolicyAnalysis $analysis
        $withPartner["XTAP_Part3_DisableForTesting.ps1"] | Should -Match "Not disabled: Sharing Policy 'Mixed'"
        $withPartner["XTAP_Part3_DisableForTesting.ps1"] | Should -Not -Match "(?m)^Set-SharingPolicy"
        $withPartner["XTAP_Part4_Cleanup.ps1"] | Should -Not -Match "Remove-SharingPolicy"
    }
}

Describe "Get-XtapSharingConfiguration" {
    It "Falls back to Get-Mailbox when Get-EXOMailbox is not available" {
        function Get-OrganizationRelationship { param($Organization) }
        function Get-AvailabilityAddressSpace { param($Organization) }
        function Get-SharingPolicy { param($Organization) }
        function Get-Mailbox { param($Organization, $ResultSize, $RecipientTypeDetails) $script:getMailboxCalled = $true; [PSCustomObject]@{ SharingPolicy = "Default" }; [PSCustomObject]@{ SharingPolicy = "Default" } }
        Mock Get-Command { $null } -ParameterFilter { $Name -eq "Get-EXOMailbox" }
        $script:getMailboxCalled = $false
        $result = Get-XtapSharingConfiguration -ProcessUsers 6>$null
        $script:getMailboxCalled | Should -BeTrue
        $result.SharingPolicyAssignment[0].Name | Should -Be "Default"
        $result.SharingPolicyAssignment[0].Count | Should -Be 2
    }

    It "Does not query mailboxes unless ProcessUsers is used" {
        function Get-OrganizationRelationship { param($Organization) }
        function Get-AvailabilityAddressSpace { param($Organization) }
        function Get-SharingPolicy { param($Organization) }
        function Get-EXOMailbox { param($Organization, $ResultSize, $RecipientTypeDetails, $Properties) $script:mailboxQueried = $true }
        $script:mailboxQueried = $false
        $result = Get-XtapSharingConfiguration 6>$null
        $script:mailboxQueried | Should -BeFalse
        $result.SharingPolicyAssignment | Should -BeNullOrEmpty
        $null = Get-XtapSharingConfiguration -ProcessUsers 6>$null
        $script:mailboxQueried | Should -BeTrue
    }

    It "Passes -Organization to the collection cmdlets" {
        function Get-OrganizationRelationship { param($Organization) $script:capturedOrganization = $Organization }
        function Get-AvailabilityAddressSpace { param($Organization) }
        function Get-SharingPolicy { param($Organization) }
        function Get-EXOMailbox { param($Organization, $ResultSize, $RecipientTypeDetails, $Properties) }
        $null = Get-XtapSharingConfiguration -ProcessUsers -Organization "contoso.onmicrosoft.com" 6>$null
        $script:capturedOrganization | Should -Be "contoso.onmicrosoft.com"
    }

    It "Stops when a cmdlet has no -Organization parameter" {
        function Get-OrganizationRelationship { param() }
        function Get-AvailabilityAddressSpace { param($Organization) }
        function Get-SharingPolicy { param($Organization) }
        { Get-XtapSharingConfiguration -Organization "contoso.onmicrosoft.com" 6>$null } | Should -Throw
    }
}

Describe "Report helpers" {
    It "Lists only generated scripts in next steps for <Scenario>" -TestCases @(
        @{ Scenario = "ineligible"; Expected = @() }
        @{ Scenario = "address space only"; Expected = @("XTAP_Part2_CreatePolicies.ps1", "XTAP_Part3_DisableForTesting.ps1", "XTAP_Part3_Rollback.ps1") }
        @{ Scenario = "mixed policy"; Expected = @("XTAP_Part2_CreatePolicies.ps1") }
        @{ Scenario = "all scripts"; Expected = @("XTAP_Part2_CreatePolicies.ps1", "XTAP_Part3_DisableForTesting.ps1", "XTAP_Part3_Rollback.ps1", "XTAP_Part4_Cleanup.ps1") }
    ) {
        param($Scenario, $Expected)
        $policy = [PSCustomObject]@{ Name = "Test"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") }
        $generated = switch ($Scenario) {
            "ineligible" {
                $policy.Domains = @("*:ContactsSharing")
                Get-XtapCommandScript -SharingPolicyAnalysis @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy)
            }
            "address space only" {
                $space = [PSCustomObject]@{ ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetTenantId = $Script:TenantA }
                Get-XtapCommandScript -AvailabilityAddressSpaceAnalysis @(Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space)
            }
            "mixed policy" {
                $policy.Domains = @("*:CalendarSharingFreeBusySimple,ContactsSharing")
                Get-XtapCommandScript -SharingPolicyAnalysis @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy)
            }
            "all scripts" {
                Get-XtapCommandScript -SharingPolicyAnalysis @(Get-XtapSharingPolicyAnalysis -SharingPolicy $policy)
            }
        }
        @($generated.Keys) | Should -Be $Expected
        $files = @("Data.json", "Summary.txt") + @($generated.Keys)

        $text = (Get-XtapSummaryLines -RunName "Test" -Mode "Offline" -GeneratedFile $files -ScriptsGenerated) -join "`n"

        foreach ($name in @("XTAP_Part2_CreatePolicies.ps1", "XTAP_Part3_DisableForTesting.ps1", "XTAP_Part3_Rollback.ps1", "XTAP_Part4_Cleanup.ps1")) {
            if ($name -in $Expected) {
                $text | Should -Match ([regex]::Escape($name))
            } else {
                $text | Should -Not -Match ([regex]::Escape($name))
            }
        }
        if ($Scenario -eq "ineligible") {
            $text | Should -Match "No command scripts were generated"
        } elseif ($Scenario -eq "mixed policy") {
            $text | Should -Match "Automatic disable commands are unavailable"
            $text | Should -Match "Automatic rollback commands are unavailable"
            $text | Should -Match "Preserve unsupported legacy functionality"
        }
    }

    It "Explains how to request scripts for an assessment-only run" {
        $text = (Get-XtapSummaryLines -RunName "Test" -Mode "Offline" -GeneratedFile @("Data.json", "Summary.txt")) -join "`n"

        $text | Should -Match "assessment only"
        $text | Should -Match "run again with -GenerateCommandScripts"
        $text | Should -Not -Match "XTAP_Part\d.*\.ps1"
    }

    It "Summarizes preservation warnings and disabled potential capabilities" {
        $analysis = @(Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship @(
                (Get-TestRelationship -Name "Preserved" -AdditionalFeature "Photos"),
                (Get-TestRelationship -Name "Dormant" -Enabled $false)))
        $sharing = @(Get-XtapSharingPolicyAnalysis -SharingPolicy (
                [PSCustomObject]@{ Name = "Mixed"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple,ContactsSharing") }))
        $summary = Get-XtapSummaryLines -RunName "Test" -Mode "Live" -OrganizationRelationshipAnalysis $analysis -SharingPolicyAnalysis $sharing
        $text = $summary -join "`n"
        $text | Should -Match "No Availability Address Spaces found"
        $text | Should -Match "'Preserved'.*Photos.*Preserve this Organization Relationship"
        $text | Should -Match "\[Disabled\] Organization Relationship 'Dormant'.*Potential capabilities if enabled: crossTenantCalendarAvailabilityBasic"
        $text | Should -Match "Sharing Policy 'Mixed'.*ContactsSharing.*Preserve this legacy rule"
    }

    It "Writes text files with a UTF-8 BOM" {
        $path = Join-Path -Path $TestDrive -ChildPath "bom.txt"
        Write-XtapTextFile -Path $path -Text "hello"
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0..2] | Should -Be @(0xEF, 0xBB, 0xBF)
    }

    It "Resolves relative text paths against the PowerShell location" {
        $workingPath = Join-Path -Path $TestDrive -ChildPath "text working folder"
        New-Item -Path $workingPath -ItemType Directory | Out-Null
        $processPath = [System.Environment]::CurrentDirectory
        Push-Location -Path $workingPath
        try {
            Write-XtapTextFile -Path ".\relative.txt" -Text "relative output"

            Get-Content -LiteralPath ".\relative.txt" -Raw | Should -Be "relative output"
            [System.Environment]::CurrentDirectory | Should -Be $processPath
        } finally {
            Pop-Location
        }
    }

    It "Explains guarded Sharing Policy scopes when counts are missing" {
        $sharing = @(Get-XtapSharingPolicyAnalysis -SharingPolicy (
                [PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") }))

        $text = (Get-XtapSummaryLines -RunName "Test" -Mode "Live" -SharingPolicyAnalysis $sharing -MailboxCountsMissing) -join "`n"

        $text | Should -Match "Mailbox counts alone do not establish tenant-wide applicability"
        $text | Should -Match "guarded security-group placeholders"
    }

    It "Uses the console default for normal summary text" -TestCases @(
        @{ Line = "Summary" }
        @{ Line = "[Eligible] Ready to migrate" }
    ) {
        param($Line)
        Mock -CommandName Write-Host -MockWith {}

        Write-XtapSummary -Line $Line

        Should -Invoke -CommandName Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq $Line -and $null -eq $ForegroundColor
        }
    }

    It "Keeps warning colors for <Line>" -TestCases @(
        @{ Line = "[Review] Needs confirmation"; Color = "Yellow" }
        @{ Line = "[NotEligible] Keep existing configuration"; Color = "DarkYellow" }
        @{ Line = "[MailboxMoveOnly] Keep existing configuration"; Color = "DarkYellow" }
    ) {
        param($Line, $Color)
        Mock -CommandName Write-Host -MockWith {}

        Write-XtapSummary -Line $Line

        Should -Invoke -CommandName Write-Host -Times 1 -Exactly -ParameterFilter {
            $Object -eq $Line -and $ForegroundColor -eq $Color
        }
    }
}

Describe "CrossTenantAccessPolicyCalendarValidation JSON replay" {
    BeforeAll {
        $Script:inputPath = Join-Path -Path $TestDrive -ChildPath "input"
        New-Item -Path $Script:inputPath -ItemType Directory | Out-Null
        $Script:bundle = @{
            SchemaVersion    = 1
            Metadata         = @{
                ScriptName              = "CrossTenantAccessPolicyCalendarValidation"
                RunName                 = "Contoso"
                Organization            = "contoso.onmicrosoft.com"
                EntraLoginHost          = "login.microsoftonline.com"
                TenantResolutionSkipped = $false
            }
            Configuration    = @{
                OrganizationRelationship = @(Get-TestRelationship -Name "Partner")
                AvailabilityAddressSpace = @()
                SharingPolicy            = @([PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") })
                SharingPolicyAssignment  = $null
            }
            TenantResolution = @([PSCustomObject]@{ Domain = "partner.com"; TenantId = $Script:TenantA })
        }
        $Script:importPath = Join-Path -Path $Script:inputPath -ChildPath "data.json"
        Write-CalendarDiagnosticJsonFile -InputObject $Script:bundle -Path $Script:importPath
        $Script:outputPath = Join-Path -Path $TestDrive -ChildPath "out"
        New-Item -Path $Script:outputPath -ItemType Directory | Out-Null
        $Script:run = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -GenerateCommandScripts -ImportData $Script:importPath 6>$null 3>$null
    }

    BeforeEach {
        Mock Invoke-RestMethod { throw "Offline replay must not use the network." }
    }

    It "Analyzes the files and writes every output" {
        $Script:run.Mode | Should -Be "Offline"
        $Script:run.OrganizationRelationshipAnalysis[0].Status | Should -Be "Eligible"
        foreach ($file in $Script:run.GeneratedFiles) {
            Test-Path -LiteralPath (Join-Path -Path $Script:run.ResultsPath -ChildPath $file) | Should -BeTrue -Because $file
        }
    }

    It "Reads BOM-less bundles as UTF-8 and preserves non-ASCII identities in generated commands" {
        $bundle = $Script:bundle | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $name = "Calendar " + [char]0x00E9 + " " + [char]0x65E5
        $bundle.Configuration.OrganizationRelationship[0].Name = $name
        $bundle.Configuration.SharingPolicy[0].Name = $name
        $path = Join-Path -Path $TestDrive -ChildPath "names.json"
        $Script:bundlePath = $path
        Write-CalendarDiagnosticJsonFile -InputObject $bundle -Path $path
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0..2] | Should -Not -Be @(0xEF, 0xBB, 0xBF)
        $readContentCommand = Get-Command -Name Get-Content -CommandType Cmdlet
        Mock Get-Content { & $readContentCommand -LiteralPath $LiteralPath -Raw -Encoding $Encoding }

        $configuration = Get-XtapSharingConfiguration -ImportData $path 6>$null

        Should -Invoke -CommandName Get-Content -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $Script:bundlePath -and
            ($Encoding -eq "UTF8" -or ($Encoding -is [System.Text.Encoding] -and $Encoding.WebName -eq "utf-8"))
        }
        $configuration.OrganizationRelationship[0].Name | Should -Be $name
        $configuration.SharingPolicy[0].Name | Should -Be $name
        $relationships = @(Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship $configuration.OrganizationRelationship)
        $sharing = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $configuration.SharingPolicy)
        $generated = Get-XtapCommandScript -OrganizationRelationshipAnalysis $relationships -SharingPolicyAnalysis $sharing
        $generated["XTAP_Part3_DisableForTesting.ps1"] | Should -Match ([regex]::Escape("-Identity '$name'"))
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match ([regex]::Escape("Sharing Policy '$name'"))
    }

    It "Writes all output with a relative OutputPath after changing location" {
        $workingPath = Join-Path -Path $TestDrive -ChildPath "replay working folder"
        New-Item -Path $workingPath -ItemType Directory | Out-Null
        Push-Location -Path $workingPath
        try {
            $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath ".\relative results" -GenerateCommandScripts -ImportData $Script:importPath 6>$null 3>$null

            foreach ($file in $result.GeneratedFiles) {
                Test-Path -LiteralPath (Join-Path -Path $result.ResultsPath -ChildPath $file) | Should -BeTrue -Because $file
            }
            (Get-Content -LiteralPath $result.DataPath -Raw | ConvertFrom-Json).Metadata.Mode | Should -Be "Offline"
        } finally {
            Pop-Location
        }
    }

    It "Uses the console default for the title and successful completion" {
        Mock -CommandName Write-Host -MockWith {}

        Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -RunName "ConsoleColors" -ImportData $Script:importPath 6>$null | Out-Null

        Should -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -eq "Cross-Tenant Access Policy Calendar Validation" -and $null -eq $ForegroundColor
        }
        Should -Invoke -CommandName Write-Host -ParameterFilter {
            $Object -like "Results saved to *" -and $null -eq $ForegroundColor
        }
        Should -Not -Invoke -CommandName Write-Host -ParameterFilter {
            $ForegroundColor -in @("Cyan", "Green", "Black", "White")
        }
    }

    It "Puts the summary near the top and saves an empty run error array" {
        $data = Get-Content -LiteralPath $Script:run.DataPath -Raw | ConvertFrom-Json

        @($data.PSObject.Properties.Name | Select-Object -First 4) | Should -Be @("SchemaVersion", "Summary", "Metadata", "Errors")
        $data.Summary -is [array] | Should -BeTrue
        $data.Errors -is [array] | Should -BeTrue
        $data.Errors.Count | Should -Be 0
        $data.Metadata.User | Should -Not -BeNullOrEmpty
        $data.Metadata.User | Should -BeLike "*$([System.Environment]::UserName)"
    }

    It "Records resolved arguments and explicit switch values without old session errors" {
        Write-Error -Message "Unrelated session error" -ErrorAction SilentlyContinue
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath `
            -RunName "Partner's Calendar" -ImportData $Script:importPath -SkipTenantResolution:$false 6>$null
        $data = Get-Content -LiteralPath $result.DataPath -Raw | ConvertFrom-Json

        $data.Metadata.CommandLine | Should -BeLike "*Invoke-CrossTenantAccessPolicyCalendarValidation*"
        $data.Metadata.CommandLine | Should -Match ([regex]::Escape("-RunName 'Partner''s Calendar'"))
        $data.Metadata.CommandLine | Should -Match ([regex]::Escape('-SkipTenantResolution:$false'))
        $data.Metadata.CommandLine | Should -Match ([regex]::Escape("-ImportData '$Script:importPath'"))
        $data.Metadata.InvocationLine | Should -Not -BeNullOrEmpty
        $data.Errors.Count | Should -Be 0
    }

    It "Only assesses by default" {
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -RunName "Assess" -ImportData $Script:importPath 6>$null
        @(Get-ChildItem -Path $result.ResultsPath -Filter "XTAP_*.ps1").Count | Should -Be 0
        @(Get-ChildItem -Path $result.ResultsPath -Filter "*.json").Count | Should -Be 1
        @(Get-ChildItem -Path $result.ResultsPath -Filter "*.csv").Count | Should -Be 0
        @(Get-ChildItem -Path $result.ResultsPath -Filter "*.xml").Count | Should -Be 0
        (Get-Content -Path (Join-Path -Path $result.ResultsPath -ChildPath "Assess_CrossTenantAccessPolicyCalendarValidation_Summary.txt") -Raw) | Should -Match "-GenerateCommandScripts"
    }

    It "Works without a run name" {
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -RunName "" -ImportData $Script:importPath 6>$null
        Test-Path -LiteralPath (Join-Path -Path $result.ResultsPath -ChildPath "CrossTenantAccessPolicyCalendarValidation_Summary.txt") | Should -BeTrue
    }

    It "Uses RunName throughout saved output and preserves automatic run timestamps" {
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -RunName "AfterMigration" -GenerateCommandScripts -ImportData $Script:importPath 6>$null 3>$null
        $data = Get-Content -LiteralPath $result.DataPath -Raw | ConvertFrom-Json
        $data.Metadata.RunName | Should -Be "AfterMigration"
        $data.Metadata.PSObject.Properties.Name | Should -Not -Contain "CustomerName"
        (Get-Content -LiteralPath $result.DataPath -Raw) | Should -Match '"GeneratedUtc"\s*:\s*"\d{4}-\d{2}-\d{2}T[^"]+Z"'
        (Split-Path -Path $result.ResultsPath -Leaf) | Should -Match '^AfterMigration_XTAP_Calendar_\d{8}_\d{2}\.\d{2}\.\d{2}(?:_\d+)?$'
        (Split-Path -Path $result.DataPath -Leaf) | Should -Be "AfterMigration_CrossTenantAccessPolicyCalendarValidation_Data.json"
        $data.Summary[0] | Should -Match "^AfterMigration "
        $data.Summary -join "`n" | Should -Match "Generated: \d{4}-\d{2}-\d{2}"
        $data.CommandScripts.'XTAP_Part4_Cleanup.ps1' | Should -Match "for run 'AfterMigration'"
        $data.Summary -join "`n" | Should -Match "configuration-changing commands are commented out"
    }

    It "Uses a readable results folder timestamp for <Case>" -TestCases @(
        @{ Case = "Named"; RunName = "Microsoft"; ExpectedPrefix = "Microsoft_" }
        @{ Case = "NoLabel"; RunName = ""; ExpectedPrefix = "" }
        @{ Case = "WhitespaceLabel"; RunName = "   "; ExpectedPrefix = "" }
        @{ Case = "Sanitized"; RunName = "Microsoft/Calendar"; ExpectedPrefix = "Microsoft_Calendar_" }
    ) {
        param($Case, $RunName, $ExpectedPrefix)
        Mock -CommandName Get-Date -MockWith { [DateTime]::new(2026, 10, 21, 14, 27, 42, 387) }
        $outputPath = Join-Path -Path $TestDrive -ChildPath $Case
        New-Item -Path $outputPath -ItemType Directory | Out-Null

        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $outputPath -RunName $RunName -ImportData $Script:importPath 6>$null

        (Split-Path -Path $result.ResultsPath -Leaf) | Should -Be "${ExpectedPrefix}XTAP_Calendar_20261021_14.27.42"
        (Split-Path -Path $result.DataPath -Leaf) | Should -Be "${ExpectedPrefix}CrossTenantAccessPolicyCalendarValidation_Data.json"
        $result.GeneratedFiles | Should -Contain "${ExpectedPrefix}CrossTenantAccessPolicyCalendarValidation_Summary.txt"
    }

    It "Keeps repeated runs in separate folders without overwriting earlier output" {
        Mock -CommandName Get-Date -MockWith { [DateTime]::new(2026, 10, 21, 14, 27, 42, 387) }
        $first = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -RunName "Repeated" -ImportData $Script:importPath 6>$null
        $originalData = Get-Content -LiteralPath $first.DataPath -Raw
        $second = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -RunName "Repeated" -ImportData $Script:importPath 6>$null
        $third = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -RunName "Repeated" -ImportData $Script:importPath 6>$null

        (Split-Path -Path $first.ResultsPath -Leaf) | Should -Be "Repeated_XTAP_Calendar_20261021_14.27.42"
        (Split-Path -Path $second.ResultsPath -Leaf) | Should -Be "Repeated_XTAP_Calendar_20261021_14.27.42_1"
        (Split-Path -Path $third.ResultsPath -Leaf) | Should -Be "Repeated_XTAP_Calendar_20261021_14.27.42_2"
        (Get-Content -LiteralPath $first.DataPath -Raw) | Should -Be $originalData
        Test-Path -LiteralPath $second.DataPath | Should -BeTrue
        Test-Path -LiteralPath $third.DataPath | Should -BeTrue
    }

    It "Skips an existing file when choosing a results folder name" {
        Mock -CommandName Get-Date -MockWith { [DateTime]::new(2026, 10, 21, 14, 27, 42, 387) }
        $existingPath = Join-Path -Path $Script:outputPath -ChildPath "ExistingFile_XTAP_Calendar_20261021_14.27.42"
        Set-Content -LiteralPath $existingPath -Value "Preserve existing file" -NoNewline

        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -RunName "ExistingFile" -ImportData $Script:importPath 6>$null

        (Split-Path -Path $result.ResultsPath -Leaf) | Should -Be "ExistingFile_XTAP_Calendar_20261021_14.27.42_1"
        (Get-Content -LiteralPath $existingPath -Raw) | Should -Be "Preserve existing file"
    }

    It "Imports older CustomerName metadata as RunName and writes only the new name" {
        $path = Join-Path -Path $TestDrive -ChildPath "legacy.json"
        $data = Get-Content -LiteralPath $Script:importPath -Raw | ConvertFrom-Json
        $data.Metadata.PSObject.Properties.Remove("RunName")
        $data.Metadata | Add-Member -NotePropertyName CustomerName -NotePropertyValue "LegacyRun"
        Write-CalendarDiagnosticJsonFile -InputObject $data -Path $path
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -ImportData $path 6>$null
        $saved = Get-Content -LiteralPath $result.DataPath -Raw | ConvertFrom-Json
        $saved.Metadata.RunName | Should -Be "LegacyRun"
        $saved.Metadata.PSObject.Properties.Name | Should -Not -Contain "CustomerName"
    }

    It "Throws when an input file is missing" {
        { Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -ImportData "$Script:inputPath\Missing.json" 6>$null } | Should -Throw
    }

    It "Preserves JSON arrays, null counts, metadata, and generated commands" {
        $data = Get-Content -LiteralPath $Script:run.DataPath -Raw | ConvertFrom-Json
        $data.Configuration.OrganizationRelationship -is [array] | Should -BeTrue
        $data.Configuration.OrganizationRelationship.Count | Should -Be 1
        $data.Configuration.AvailabilityAddressSpace -is [array] | Should -BeTrue
        $data.Configuration.AvailabilityAddressSpace.Count | Should -Be 0
        $data.Configuration.SharingPolicyAssignment | Should -BeNullOrEmpty
        $data.Analysis.OrganizationRelationship -is [array] | Should -BeTrue
        $data.Analysis.AvailabilityAddressSpace -is [array] | Should -BeTrue
        $data.Metadata.Organization | Should -Be "contoso.onmicrosoft.com"
        $data.Metadata.RunName | Should -Be "Contoso"
        $data.CommandScripts.'XTAP_Part2_CreatePolicies.ps1' | Should -Match "-TenantId 'contoso.onmicrosoft.com'"
        $data.TenantResolution[0].TenantId | Should -Be $Script:TenantA
    }

    It "Replays its own output with identical analysis and without network requests" {
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -ImportData $Script:run.DataPath 6>$null 3>$null
        ($result.OrganizationRelationshipAnalysis | ConvertTo-Json -Depth 8) | Should -Be ($Script:run.OrganizationRelationshipAnalysis | ConvertTo-Json -Depth 8)
        ($result.SharingPolicyAnalysis | ConvertTo-Json -Depth 8) | Should -Be ($Script:run.SharingPolicyAnalysis | ConvertTo-Json -Depth 8)
        Should -Invoke -CommandName Invoke-RestMethod -Times 0 -Exactly
    }

    It "Keeps unknown domains unresolved rather than querying the network" {
        $path = Join-Path -Path $TestDrive -ChildPath "unresolved.json"
        $data = Get-Content -LiteralPath $Script:importPath -Raw | ConvertFrom-Json
        $data.TenantResolution = @()
        Write-CalendarDiagnosticJsonFile -InputObject $data -Path $path
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -ImportData $path 6>$null 3>$null
        $result.OrganizationRelationshipAnalysis[0].Status | Should -Be "Review"
        Should -Invoke -CommandName Invoke-RestMethod -Times 0 -Exactly
    }

    It "Rejects malformed JSON, incompatible schemas, and missing collections" {
        $path = Join-Path -Path $TestDrive -ChildPath "invalid.json"
        Set-Content -LiteralPath $path -Value "{invalid"
        { Get-XtapSharingConfiguration -ImportData $path 6>$null } | Should -Throw
        foreach ($json in @(
                '{"SchemaVersion":2}',
                '{"SchemaVersion":1,"Metadata":{"ScriptName":"CrossTenantAccessPolicyCalendarValidation"},"Configuration":{},"TenantResolution":[]}'
            )) {
            Set-Content -LiteralPath $path -Value $json
            { Get-XtapSharingConfiguration -ImportData $path 6>$null } | Should -Throw
        }
    }

    It "Rejects invalid configuration values and tenant resolution records" {
        $path = Join-Path -Path $TestDrive -ChildPath "invalidValues.json"
        foreach ($invalidCase in @("Boolean", "Collection", "Item", "TenantId", "TenantError", "Count", "Metadata", "MetadataHost", "RunName")) {
            $data = Get-Content -LiteralPath $Script:importPath -Raw | ConvertFrom-Json
            switch ($invalidCase) {
                "Boolean" { $data.Configuration.SharingPolicy[0].Enabled = "false" }
                "Collection" { $data.Configuration.SharingPolicy = $data.Configuration.SharingPolicy[0] }
                "Item" { $data.Configuration.OrganizationRelationship = @("invalid") }
                "TenantId" { $data.TenantResolution[0].TenantId = "invalid" }
                "TenantError" { $data.TenantResolution[0] | Add-Member -NotePropertyName Error -NotePropertyValue 42 }
                "Count" { $data.Configuration.SharingPolicyAssignment = @([PSCustomObject]@{ Name = "Default"; Count = -1 }) }
                "Metadata" { $data.Metadata.TenantResolutionSkipped = "false" }
                "MetadataHost" { $data.Metadata.EntraLoginHost = "127.0.0.1" }
                "RunName" { $data.Metadata.RunName = 42 }
            }
            Write-CalendarDiagnosticJsonFile -InputObject $data -Path $path
            { Get-XtapSharingConfiguration -ImportData $path 6>$null } | Should -Throw -Because $invalidCase
        }
    }

    It "Preserves multiple items and collected mailbox counts through replay" {
        $path = Join-Path -Path $TestDrive -ChildPath "multiple.json"
        $data = Get-Content -LiteralPath $Script:importPath -Raw | ConvertFrom-Json
        $data.Configuration.OrganizationRelationship += Get-TestRelationship -Name "Second"
        $data.Configuration.SharingPolicyAssignment = @([PSCustomObject]@{ Name = "Default"; Count = 7 })
        Write-CalendarDiagnosticJsonFile -InputObject $data -Path $path
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $Script:outputPath -ImportData $path 6>$null
        $result.OrganizationRelationshipAnalysis.Count | Should -Be 2
        $result.SharingPolicyAnalysis[0].AssignedMailboxCount | Should -Be 7
        $saved = Get-Content -LiteralPath $result.DataPath -Raw | ConvertFrom-Json
        $saved.Configuration.OrganizationRelationship.Count | Should -Be 2
        $saved.Configuration.SharingPolicyAssignment -is [array] | Should -BeTrue
        $saved.Configuration.SharingPolicyAssignment[0].Count | Should -Be 7
    }

    It "Rejects live-only parameters with ImportData in the public entry point" {
        $entryPath = Join-Path -Path $Script:parentPath -ChildPath "CrossTenantAccessPolicyCalendarValidation.ps1"
        { & $entryPath -ImportData $Script:importPath -ProcessUsers } | Should -Throw
        { & $entryPath -ImportData $Script:importPath -Organization "other.onmicrosoft.com" } | Should -Throw
    }

    It "Runs the public entry point offline without switches or results on the pipeline" {
        $entryPath = Join-Path -Path $Script:parentPath -ChildPath "CrossTenantAccessPolicyCalendarValidation.ps1"
        $publicOutputPath = Join-Path -Path $TestDrive -ChildPath "publicOutput"
        $result = @(& $entryPath -RunName "PublicReplay" -ImportData $Script:importPath -OutputPath $publicOutputPath 6>$null)
        $result.Count | Should -Be 0
        $files = @(Get-ChildItem -Path $publicOutputPath -Filter "PublicReplay_CrossTenantAccessPolicyCalendarValidation_Data.json" -Recurse)
        $files.Count | Should -Be 1
        $data = Get-Content -LiteralPath $files[0].FullName -Raw | ConvertFrom-Json
        $data.Metadata.Mode | Should -Be "Offline"
        $data.Metadata.CommandLine | Should -Match ([regex]::Escape("CrossTenantAccessPolicyCalendarValidation.ps1'"))
        $data.Metadata.CommandLine | Should -Match ([regex]::Escape("-RunName 'PublicReplay'"))
        $data.Metadata.CommandLine | Should -Match ([regex]::Escape("-OutputPath '$publicOutputPath'"))
        $data.Metadata.User | Should -Not -BeNullOrEmpty
        $data.Metadata.InvocationLine | Should -Not -BeNullOrEmpty
        Should -Invoke -CommandName Invoke-RestMethod -Times 0 -Exactly
    }
}

Describe "Calendar validation entry point update behavior" {
    BeforeAll {
        function Test-ScriptVersion { param([switch]$AutoUpdate) }
        $Script:entryPath = Join-Path -Path $Script:parentPath -ChildPath "CrossTenantAccessPolicyCalendarValidation.ps1"
        $entryAst = [System.Management.Automation.Language.Parser]::ParseFile($Script:entryPath, [ref]$null, [ref]$null)
        # Keep the real parameter binding and control flow while mocking dot-sourced dependencies.
        $statements = foreach ($statement in $entryAst.EndBlock.Statements) {
            if ($statement -is [System.Management.Automation.Language.PipelineAst] -and
                $statement.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst] -and
                $statement.PipelineElements[0].InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot) {
                continue
            }
            $statement.Extent.Text
        }
        $Script:entryWithoutImports = [ScriptBlock]::Create($entryAst.ParamBlock.Extent.Text + "`n" + ($statements -join "`n"))
    }

    BeforeEach {
        Mock Test-ScriptVersion { $false }
        Mock Invoke-CrossTenantAccessPolicyCalendarValidation { [PSCustomObject]@{ ResultsPath = "results" } }
    }

    It "Checks for updates automatically in live mode without emitting a results object" {
        $result = @(& $Script:entryWithoutImports -RunName "LiveRun" 6>$null)
        $result.Count | Should -Be 0
        Should -Invoke -CommandName Test-ScriptVersion -Times 1 -Exactly -ParameterFilter { $AutoUpdate }
        Should -Invoke -CommandName Invoke-CrossTenantAccessPolicyCalendarValidation -Times 1 -Exactly -ParameterFilter { $RunName -eq "LiveRun" }
    }

    It "Skips update checking automatically when importing data" {
        $result = @(& $Script:entryWithoutImports -ImportData "data.json" 6>$null)
        $result.Count | Should -Be 0
        Should -Invoke -CommandName Test-ScriptVersion -Times 0 -Exactly
        Should -Invoke -CommandName Invoke-CrossTenantAccessPolicyCalendarValidation -Times 1 -Exactly -ParameterFilter { $ImportData -eq "data.json" }
    }

    It "Defaults output to the script folder when launched from another working directory" {
        $scriptFolder = Join-Path -Path $TestDrive -ChildPath "script location"
        $workingFolder = Join-Path -Path $TestDrive -ChildPath "working"
        New-Item -Path $scriptFolder -ItemType Directory | Out-Null
        New-Item -Path $workingFolder -ItemType Directory | Out-Null
        $scriptCopy = Join-Path -Path $scriptFolder -ChildPath "CrossTenantAccessPolicyCalendarValidation.ps1"
        Write-XtapTextFile -Path $scriptCopy -Text $Script:entryWithoutImports.ToString()

        Push-Location -Path $workingFolder
        try {
            & $scriptCopy -ImportData "data.json" 6>$null

            (Get-Location).Path | Should -Be $workingFolder
            Should -Invoke -CommandName Invoke-CrossTenantAccessPolicyCalendarValidation -Times 1 -Exactly -ParameterFilter {
                $OutputPath -eq $scriptFolder
            }
        } finally {
            Pop-Location
        }
    }

    It "Preserves an explicitly supplied output folder" {
        & $Script:entryWithoutImports -ImportData "data.json" -OutputPath $TestDrive 6>$null

        Should -Invoke -CommandName Invoke-CrossTenantAccessPolicyCalendarValidation -Times 1 -Exactly -ParameterFilter {
            $OutputPath -eq $TestDrive
        }
    }

    It "Stops before assessment when an update was downloaded" {
        Mock Test-ScriptVersion { $true }
        & $Script:entryWithoutImports 6>$null
        Should -Invoke -CommandName Test-ScriptVersion -Times 1 -Exactly -ParameterFilter { $AutoUpdate }
        Should -Invoke -CommandName Invoke-CrossTenantAccessPolicyCalendarValidation -Times 0 -Exactly
    }

    It "Does not expose the removed switches" {
        $parameters = (Get-Command -Name $Script:entryPath).Parameters.Keys
        $parameters | Should -Not -Contain "SkipVersionCheck"
        $parameters | Should -Not -Contain "PassThru"
        { & $Script:entryPath -SkipVersionCheck } | Should -Throw
        { & $Script:entryPath -PassThru } | Should -Throw
    }
}

Describe "JSON collection normalization and live replay" {
    BeforeAll {
        function Get-OrganizationRelationship { param($Organization) }
        function Get-AvailabilityAddressSpace { param($Organization) }
        function Get-SharingPolicy { param($Organization) }
        function Get-EXOMailbox { param($Organization, $ResultSize, $RecipientTypeDetails, $Properties) }
    }

    BeforeEach {
        Mock Get-OrganizationRelationship {
            $relationship = Get-TestRelationship
            $relationship.TargetAutodiscoverEpr = [uri]$relationship.TargetAutodiscoverEpr
            $relationship.FreeBusyAccessLevel = [System.DayOfWeek]::Monday
            $relationship
        }
        Mock Get-AvailabilityAddressSpace {}
        Mock Get-SharingPolicy {
            [PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") }
        }
        Mock Get-EXOMailbox {}
        Mock Invoke-RestMethod { [PSCustomObject]@{ issuer = "https://login.microsoftonline.com/$Script:TenantA/v2.0" } }
    }

    It "Normalizes Exchange-specific scalar and collection values for JSON" {
        $data = Get-XtapSharingConfiguration 6>$null
        $data.OrganizationRelationship[0].TargetAutodiscoverEpr -is [string] | Should -BeTrue
        $data.OrganizationRelationship[0].FreeBusyAccessLevel | Should -Be "Monday"
        $data.OrganizationRelationship[0].Enabled -is [bool] | Should -BeTrue
        $data.SharingPolicy[0].Domains -is [array] | Should -BeTrue
    }

    It "Saves empty mailbox counts distinctly from uncollected counts" {
        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -RunName "EmptyCounts" -ProcessUsers -SkipTenantResolution 6>$null
        $data = Get-Content -LiteralPath $result.DataPath -Raw | ConvertFrom-Json
        $data.Configuration.SharingPolicyAssignment -is [array] | Should -BeTrue
        $data.Configuration.SharingPolicyAssignment.Count | Should -Be 0
    }

    It "Saves live tenant lookups and reproduces analysis from the saved bundle" {
        Mock Get-OrganizationRelationship { Get-TestRelationship }
        $live = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -RunName "Live" 6>$null
        $data = Get-Content -LiteralPath $live.DataPath -Raw | ConvertFrom-Json
        $data.TenantResolution.Count | Should -Be 1
        $data.TenantResolution[0].TenantId | Should -Be $Script:TenantA
        $offline = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -ImportData $live.DataPath 6>$null
        ($offline.OrganizationRelationshipAnalysis | ConvertTo-Json) | Should -Be ($live.OrganizationRelationshipAnalysis | ConvertTo-Json)
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly
    }

    It "Persists failed lookups without retrying during replay" {
        Mock Get-OrganizationRelationship { Get-TestRelationship }
        Mock Invoke-RestMethod { throw "Lookup unavailable" }
        $live = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -RunName "FailedLookup" 6>$null
        $data = Get-Content -LiteralPath $live.DataPath -Raw | ConvertFrom-Json
        $data.TenantResolution.Count | Should -Be 1
        $data.TenantResolution[0].TenantId | Should -BeNullOrEmpty
        $data.TenantResolution[0].Error | Should -Be "Lookup unavailable"
        $live.OrganizationRelationshipAnalysis[0].DomainTenantResolution[0].Error | Should -Be "Lookup unavailable"
        $live.OrganizationRelationshipAnalysis[0].Notes | Should -Match "partner.com.*Lookup unavailable"
        $data.Errors.message | Should -Contain "Lookup unavailable"
        $lookupError = $data.Errors | Where-Object -Property message -EQ "Lookup unavailable"
        $lookupError.exceptionType | Should -Not -BeNullOrEmpty
        $lookupError.category | Should -Not -BeNullOrEmpty
        $lookupError.fullyQualifiedErrorId | Should -Not -BeNullOrEmpty
        $offline = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -ImportData $live.DataPath 6>$null
        $offline.OrganizationRelationshipAnalysis[0].Status | Should -Be "Review"
        ($offline.OrganizationRelationshipAnalysis | ConvertTo-Json -Depth 8) | Should -Be (
            $live.OrganizationRelationshipAnalysis | ConvertTo-Json -Depth 8)
        $replayData = Get-Content -LiteralPath $offline.DataPath -Raw | ConvertFrom-Json
        $replayData.Errors.Count | Should -Be 0
        $replayData.Metadata.CommandLine | Should -Match ([regex]::Escape("-ImportData '$($live.DataPath)'"))
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly
    }

    It "Retains diagnostics across every assessment and replay without extra lookups" {
        Mock Get-OrganizationRelationship { Get-TestRelationship -Enabled $false -AdditionalFeature "IdentityMove" }
        Mock Get-AvailabilityAddressSpace {
            [PSCustomObject]@{ Name = "Partner"; ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetServiceEpr = "https://outlook.office365.com/ews" }
        }
        Mock Get-SharingPolicy {
            [PSCustomObject]@{ Name = "Disabled"; Enabled = $false; Default = $false; Domains = @("partner.com:CalendarSharingFreeBusyDetail,ContactsSharing") }
        }
        Mock Invoke-RestMethod { throw "Shared lookup failure" }
        $live = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -RunName "Diagnostics" -GenerateCommandScripts 6>$null 3>$null
        $live.OrganizationRelationshipAnalysis[0].DomainTenantResolution[0].Error | Should -Be "Shared lookup failure"
        $live.AvailabilityAddressSpaceAnalysis[0].TenantResolutionError | Should -Be "Shared lookup failure"
        $live.SharingPolicyAnalysis[0].TenantResolutionError | Should -Be "Shared lookup failure"
        $live.SharingPolicyAnalysis[0].RecommendedCapabilityIfEnabled | Should -BeNullOrEmpty
        $live.GeneratedFiles | Should -Not -Contain "XTAP_Part2_CreatePolicies.ps1"
        $offline = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -ImportData $live.DataPath 6>$null
        foreach ($property in @("OrganizationRelationshipAnalysis", "AvailabilityAddressSpaceAnalysis", "SharingPolicyAnalysis")) {
            ($offline.$property | ConvertTo-Json -Depth 8) | Should -Be ($live.$property | ConvertTo-Json -Depth 8)
        }
        $saved = Get-Content -LiteralPath $offline.DataPath -Raw | ConvertFrom-Json
        $saved.TenantResolution[0].Error | Should -Be "Shared lookup failure"
        $saved.Errors.Count | Should -Be 0
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly
    }

    It "Includes recoverable mailbox-count errors in the saved diagnostics" {
        Mock -CommandName Get-EXOMailbox -MockWith { throw "Mailbox count unavailable" }

        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -RunName "CountError" -ProcessUsers -SkipTenantResolution 6>$null 3>$null
        $data = Get-Content -LiteralPath $result.DataPath -Raw | ConvertFrom-Json

        $data.Errors.message | Should -Contain "Mailbox count unavailable"
        $data.Configuration.SharingPolicyAssignment | Should -BeNullOrEmpty
        $data.Metadata.CommandLine | Should -Match ([regex]::Escape('-ProcessUsers:$true'))
    }

    It "Records non-terminating collection errors without including older session errors" {
        Write-Error -Message "Error from a previous run" -ErrorAction SilentlyContinue
        Mock -CommandName Get-OrganizationRelationship -MockWith {
            Write-Error -Message "Current collection diagnostic" -ErrorAction Continue
            Get-TestRelationship
        }

        $result = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -RunName "DiagnosticError" -SkipTenantResolution 6>$null 2>$null
        $data = Get-Content -LiteralPath $result.DataPath -Raw | ConvertFrom-Json

        $data.Errors.message | Should -Contain "Current collection diagnostic"
        $data.Errors.message | Should -Not -Contain "Error from a previous run"
    }

    It "Keeps saved-script backups beside each assessment and restores them from another working directory" {
        $space = [PSCustomObject]@{ Name = "partner.com"; ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetTenantId = $Script:TenantA }
        $analysis = @(Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $space)
        $scripts = Get-XtapCommandScript -AvailabilityAddressSpaceAnalysis $analysis
        foreach ($name in $scripts.Keys) {
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($scripts[$name], [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0 -Because $name
            $scripts[$name] | Should -Not -Match "Clixml|\.xml"
        }
        function Remove-AvailabilityAddressSpace {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSShouldProcess", "", Justification = "Mocked cmdlet used to test generated scripts.")]
            [CmdletBinding(SupportsShouldProcess)]
            param($Identity)
        }
        function Add-AvailabilityAddressSpace { param($ForestName, $AccessMethod, $TargetTenantId) }
        Mock Get-AvailabilityAddressSpace { $space }
        Mock Remove-AvailabilityAddressSpace {}
        Mock Add-AvailabilityAddressSpace {}
        $firstPath = Join-Path -Path $TestDrive -ChildPath "first assessment"
        $secondPath = Join-Path -Path $TestDrive -ChildPath "second assessment"
        $workingPath = Join-Path -Path $TestDrive -ChildPath "unrelated working folder"
        New-Item -Path $firstPath, $secondPath, $workingPath -ItemType Directory | Out-Null
        foreach ($folder in @($firstPath, $secondPath)) {
            foreach ($name in $scripts.Keys) {
                Write-XtapTextFile -Path (Join-Path -Path $folder -ChildPath $name) -Text $scripts[$name]
            }
        }
        Push-Location -Path $workingPath
        try {
            & (Join-Path -Path $firstPath -ChildPath "XTAP_Part3_DisableForTesting.ps1")
            $firstBackup = Join-Path -Path $firstPath -ChildPath "AvailabilityAddressSpaceBackup_partner.com.json"
            Test-Path -LiteralPath $firstBackup | Should -BeTrue
            Test-Path -LiteralPath ".\AvailabilityAddressSpaceBackup_partner.com.json" | Should -BeFalse
            $firstText = Get-Content -LiteralPath $firstBackup -Raw -Encoding UTF8
            $otherSpace = [PSCustomObject]@{ ForestName = "partner.com"; AccessMethod = "OrgWideFBToken"; TargetTenantId = $Script:TenantB }
            Mock Get-AvailabilityAddressSpace { $otherSpace }
            & (Join-Path -Path $secondPath -ChildPath "XTAP_Part3_DisableForTesting.ps1")
            Get-Content -LiteralPath $firstBackup -Raw -Encoding UTF8 | Should -Be $firstText
            Test-Path -LiteralPath (Join-Path -Path $secondPath -ChildPath "AvailabilityAddressSpaceBackup_partner.com.json") | Should -BeTrue

            & (Join-Path -Path $firstPath -ChildPath "XTAP_Part3_Rollback.ps1")
            Should -Invoke -CommandName Add-AvailabilityAddressSpace -Times 1 -Exactly -ParameterFilter {
                $ForestName -eq "partner.com" -and $AccessMethod -eq "OrgWideFBToken" -and $TargetTenantId -eq $Script:TenantA
            }
            & (Join-Path -Path $secondPath -ChildPath "XTAP_Part3_Rollback.ps1")
            Should -Invoke -CommandName Add-AvailabilityAddressSpace -Times 1 -Exactly -ParameterFilter {
                $ForestName -eq "partner.com" -and $AccessMethod -eq "OrgWideFBToken" -and $TargetTenantId -eq $Script:TenantB
            }
            Should -Invoke -CommandName Remove-AvailabilityAddressSpace -Times 2 -Exactly
        } finally {
            Pop-Location
        }
    }
}
