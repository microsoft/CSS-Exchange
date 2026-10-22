# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Hosts that indicate the external organization is hosted in Microsoft 365.
$Script:XtapMicrosoft365HostPattern = '(^|\.)(outlook\.com|outlook\.cn|outlook\.office\.com|office365\.com|office365\.us)$'
# Names used by the Hybrid Configuration Wizard and by admins for on-premises relationships.
$Script:XtapHybridNamePattern = '(?i)on[\s-]*prem|hybrid'
$Script:XtapGuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
$Script:XtapCalendarSharingActions = @("CalendarSharingFreeBusySimple", "CalendarSharingFreeBusyDetail", "CalendarSharingFreeBusyReviewer")
$Script:XtapDomainTenantCache = @{}
$Script:XtapDomainTenantErrors = @{}
$Script:XtapEntraLoginHost = "login.microsoftonline.com"
$Script:XtapOfflineData = $false

<#
.SYNOPSIS
    Determines whether an endpoint value (URL, host name or URI) points to Microsoft 365.
.OUTPUTS
    $true if Microsoft 365, $false if something else (for example on-premises Exchange),
    $null if the value is empty.
#>
function Test-IsMicrosoft365Endpoint {
    [CmdletBinding()]
    [OutputType([System.Nullable[bool]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    $text = "$Value".Trim()
    if ([string]::IsNullOrEmpty($text)) {
        return $null
    }

    $hostName = $text
    $parsedUri = $null
    if ([System.Uri]::TryCreate($text, [System.UriKind]::Absolute, [ref]$parsedUri) -and
        -not [string]::IsNullOrEmpty($parsedUri.Host)) {
        $hostName = $parsedUri.Host
    }

    return ($hostName.TrimEnd('/') -match $Script:XtapMicrosoft365HostPattern)
}

<#
.SYNOPSIS
    Classifies where the external organization is hosted based on its endpoints and the relationship name.
.OUTPUTS
    Microsoft365, OnPremisesOrHybrid or Unknown.
#>
function Get-XtapTargetScenario {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$Endpoint,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Name
    )

    if ($Name -match $Script:XtapHybridNamePattern) {
        return "OnPremisesOrHybrid"
    }

    $values = @(@($Endpoint) | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrEmpty($_) })
    if ($values.Count -eq 0) {
        return "Unknown"
    }

    # The on-premises federation application URI always starts with FYDIBOHF25SPDLT.
    if (@($values | Where-Object { $_ -match "FYDIBOHF25SPDLT" }).Count -gt 0) {
        return "OnPremisesOrHybrid"
    }

    $results = @($values | ForEach-Object { Test-IsMicrosoft365Endpoint -Value $_ })
    if ($results -contains $false) {
        return "OnPremisesOrHybrid"
    }

    return "Microsoft365"
}

<#
.SYNOPSIS
    Resolves the Microsoft Entra tenant ID of a domain using the public OpenID Connect metadata endpoint.
.OUTPUTS
    The tenant ID, or $null if the domain isn't a Microsoft Entra domain or can't be resolved.
#>
function Resolve-XtapDomainTenantId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Domain
    )

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return $null
    }

    $normalizedDomain = $Domain.Trim().ToLowerInvariant()
    if ($normalizedDomain -notmatch '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$') {
        $Script:XtapDomainTenantErrors[$normalizedDomain] = "The domain is not a valid DNS host name."
        Write-Verbose "Unable to resolve domain [$normalizedDomain]: $($Script:XtapDomainTenantErrors[$normalizedDomain])"
        return $null
    }

    if ($Script:XtapDomainTenantCache.ContainsKey($normalizedDomain)) {
        return $Script:XtapDomainTenantCache[$normalizedDomain]
    }
    if ($Script:XtapOfflineData) {
        $Script:XtapDomainTenantCache[$normalizedDomain] = $null
        $Script:XtapDomainTenantErrors[$normalizedDomain] = "No saved tenant resolution is available for this domain. Collect live data to resolve it."
        return $null
    }

    $tenantId = $null
    try {
        $uri = "https://$($Script:XtapEntraLoginHost)/$normalizedDomain/v2.0/.well-known/openid-configuration"
        $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 20 -ErrorAction Stop
        if ("$($response.issuer)" -match '/([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})/') {
            $tenantId = $Matches[1].ToLowerInvariant()
        } else {
            throw "The OpenID issuer did not contain a valid Microsoft Entra tenant ID: $($response.issuer)"
        }
    } catch {
        $Script:XtapDomainTenantErrors[$normalizedDomain] = $_.Exception.Message
        Write-Verbose "Unable to resolve a tenant ID for domain [$normalizedDomain]: $($_.Exception.Message)"
    }

    $Script:XtapDomainTenantCache[$normalizedDomain] = $tenantId
    return $tenantId
}

function Get-XtapDomainTenantResolution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $normalizedDomain = $Domain.Trim().ToLowerInvariant()
    $tenantId = Resolve-XtapDomainTenantId -Domain $normalizedDomain
    $resolved = -not [string]::IsNullOrEmpty($tenantId)
    $resolutionError = ""
    if (-not $resolved) {
        $resolutionError = if ($Script:XtapDomainTenantErrors.ContainsKey($normalizedDomain)) {
            $Script:XtapDomainTenantErrors[$normalizedDomain]
        } else {
            "The domain did not resolve to a Microsoft Entra tenant ID; no detailed lookup error was saved."
        }
    }

    [PSCustomObject]@{
        Domain   = $normalizedDomain
        TenantId = $tenantId
        Status   = if ($resolved) { "Resolved" } else { "Unresolved" }
        Error    = $resolutionError
    }
}

<#
.SYNOPSIS
    Returns the domains of Organization Relationships that point to on-premises or hybrid organizations.
#>
function Get-XtapHybridDomain {
    [CmdletBinding()]
    [OutputType([string[]], [System.Array])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$OrganizationRelationshipAnalysis
    )

    @(@($OrganizationRelationshipAnalysis) | Where-Object { $null -ne $_ -and $_.Scenario -eq "OnPremisesOrHybrid" } |
            ForEach-Object { "$($_.DomainNames)" -split ";" } |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrEmpty($_) } |
            Select-Object -Unique)
}

<#
.SYNOPSIS
    Analyzes Get-OrganizationRelationship output and recommends Microsoft 365 Cross-Tenant Access Policy capabilities.
.DESCRIPTION
    Follows "Review your Organization Relationship configurations" from
    https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap
    Status is one of Eligible, Review, NotEligible, Disabled, NothingToMigrate or MailboxMoveOnly.
#>
function Get-XtapOrganizationRelationshipAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$OrganizationRelationship,

        [Parameter(Mandatory = $false)]
        [switch]$ResolveTenantId
    )

    foreach ($relationship in @($OrganizationRelationship)) {
        if ($null -eq $relationship) { continue }

        $notes = New-Object System.Collections.Generic.List[string]
        $name = "$($relationship.Name)"
        $domains = @(@($relationship.DomainNames) | Where-Object { $null -ne $_ } | ForEach-Object { "$_".Trim() } | Where-Object { -not [string]::IsNullOrEmpty($_) })
        $enabled = $relationship.Enabled -eq $true
        $freeBusyEnabled = $relationship.FreeBusyAccessEnabled -eq $true
        $mailTipsEnabled = $relationship.MailTipsAccessEnabled -eq $true
        $hasSharing = $freeBusyEnabled -or $mailTipsEnabled
        $hasMailboxMove = ($relationship.MailboxMoveEnabled -eq $true) -or
        ("$($relationship.MailboxMoveCapability)" -notin @("", "None"))
        $additionalFeatures = [ordered]@{
            MailboxMove    = $hasMailboxMove
            IdentityMove   = $relationship.IdentityMoveEnabled -eq $true -or
            ("$($relationship.IdentityMoveCapability)" -notin @("", "None"))
            PeopleSearch   = $relationship.PeopleSearchEnabled -eq $true
            ArchiveAccess  = $relationship.ArchiveAccessEnabled -eq $true
            DeliveryReport = $relationship.DeliveryReportEnabled -eq $true
            Photos         = $relationship.PhotosEnabled -eq $true
        }
        $additionalEnabledFunctionalities = @($additionalFeatures.GetEnumerator() |
                Where-Object { $_.Value } | ForEach-Object { $_.Key })
        $hasAdditionalFunctionalitiesAndSharing = $additionalEnabledFunctionalities.Count -gt 0 -and $hasSharing

        $scenario = Get-XtapTargetScenario -Name $name -Endpoint @(
            $relationship.TargetApplicationUri, $relationship.TargetSharingEpr, $relationship.TargetAutodiscoverEpr)

        $freeBusyCapability = ""
        if ($freeBusyEnabled) {
            switch ("$($relationship.FreeBusyAccessLevel)") {
                "AvailabilityOnly" { $freeBusyCapability = "crossTenantCalendarAvailabilityBasic" }
                "LimitedDetails" { $freeBusyCapability = "crossTenantCalendarAvailabilityLimitedDetails" }
                default { $notes.Add("FreeBusyAccessEnabled is True but FreeBusyAccessLevel is [$($relationship.FreeBusyAccessLevel)], so there is no Free/Busy capability to migrate.") }
            }
        }

        $mailTipsCapability = ""
        if ($mailTipsEnabled) {
            switch ("$($relationship.MailTipsAccessLevel)") {
                "Limited" { $mailTipsCapability = "crossTenantMailTipsLimited" }
                "All" { $mailTipsCapability = "crossTenantMailTipsAll" }
                default { $notes.Add("MailTipsAccessEnabled is True but MailTipsAccessLevel is [$($relationship.MailTipsAccessLevel)], so there is no MailTips capability to migrate.") }
            }
        }

        $freeBusyScope = "$($relationship.FreeBusyAccessScope)".Trim()
        $mailTipsScope = "$($relationship.MailTipsAccessScope)".Trim()
        $freeBusyScoped = $freeBusyCapability -ne "" -and -not [string]::IsNullOrEmpty($freeBusyScope)
        $mailTipsScoped = $mailTipsCapability -ne "" -and -not [string]::IsNullOrEmpty($mailTipsScope)
        if ($freeBusyScoped) {
            $notes.Add("FreeBusyAccessScope is [$freeBusyScope]. The generated commands need a security group for this scope. Confirm the scope behaves as expected before disabling the Organization Relationship, otherwise Free/Busy could be over-shared.")
        }

        if ($mailTipsScoped) {
            $notes.Add("MailTipsAccessScope is [$mailTipsScope]. The generated commands need a security group for this scope. Confirm the scope behaves as expected before disabling the Organization Relationship.")
        }

        $hasMailboxMoveAndSharing = $false
        if ($hasMailboxMove -and $hasSharing) {
            $hasMailboxMoveAndSharing = $true
            $notes.Add("This relationship also has mailbox move settings (MailboxMoveEnabled [$($relationship.MailboxMoveEnabled)], MailboxMoveCapability [$($relationship.MailboxMoveCapability)]). Keep it. The generated test and cleanup commands only turn off its Free/Busy and MailTips settings and leave mailbox moves working.")
        }
        $additionalRecommendation = ""
        if ($additionalEnabledFunctionalities.Count -gt 0) {
            $additionalRecommendation = "Additional enabled functionality: $($additionalEnabledFunctionalities -join ', '). Preserve this Organization Relationship. Verify current XTAP capability support before retiring it, and split any functionality that is not covered into a separate relationship if necessary."
            if ($hasAdditionalFunctionalitiesAndSharing) {
                $additionalRecommendation += " The generated test and cleanup commands only turn off Free/Busy and MailTips; they do not disable or remove the relationship."
            }
            if ($hasMailboxMove) {
                $additionalRecommendation += " Cross-tenant mailbox moves have no corresponding XTAP capability."
            }
            $notes.Add($additionalRecommendation)
        }

        $partnerTenantIds = @()
        $unresolvedDomains = @()
        $domainResolutions = @()
        $canAssess = $hasSharing -and $scenario -ne "OnPremisesOrHybrid" -and ($freeBusyCapability -ne "" -or $mailTipsCapability -ne "")
        if ($ResolveTenantId -and $canAssess) {
            foreach ($domain in $domains) {
                $resolution = Get-XtapDomainTenantResolution -Domain $domain
                $domainResolutions += $resolution
                if ($resolution.Status -ne "Resolved") {
                    $unresolvedDomains += $domain
                    $notes.Add("Tenant resolution failed for [$domain]: $($resolution.Error)")
                } else {
                    $partnerTenantIds += $resolution.TenantId
                }
            }

            $partnerTenantIds = @($partnerTenantIds | Select-Object -Unique)
            if ($partnerTenantIds.Count -gt 1) {
                $notes.Add("The domains belong to $($partnerTenantIds.Count) different tenants. One XTAP partner policy is generated for each tenant.")
            }

            if ($unresolvedDomains.Count -gt 0) {
                $notes.Add("Every relationship domain must resolve before migration commands can be generated. Resolve these domains first: $($unresolvedDomains -join ', ').")
            }
        }

        $sharingCapabilityWouldBeEligibleIfEnabled = $canAssess -and $scenario -eq "Microsoft365" -and
        $domains.Count -gt 0 -and (-not $ResolveTenantId -or $unresolvedDomains.Count -eq 0)
        $freeBusyCapabilityIfEnabled = if ($sharingCapabilityWouldBeEligibleIfEnabled) { $freeBusyCapability } else { "" }
        $mailTipsCapabilityIfEnabled = if ($sharingCapabilityWouldBeEligibleIfEnabled) { $mailTipsCapability } else { "" }

        if (-not $enabled) {
            $status = "Disabled"
            $notes.Add("The Organization Relationship is disabled, so it isn't sharing anything today.")
            if ($sharingCapabilityWouldBeEligibleIfEnabled) {
                $notes.Add("If enabled, its configured Free/Busy or MailTips capability appears eligible for XTAP. Scope and additional functionality still require review.")
            } elseif (-not $hasSharing) {
                $notes.Add("No Free/Busy or MailTips sharing is configured to migrate if enabled.")
            } else {
                $notes.Add("Eligibility if enabled is not confirmed. Review the target, domain names, access levels and tenant-resolution diagnostics.")
            }
        } elseif (-not $hasSharing) {
            if ($hasMailboxMove) {
                $status = "MailboxMoveOnly"
                $notes.Add("This relationship is only used for mailbox moves. Don't disable or remove it during the XTAP cleanup.")
            } else {
                $status = "NothingToMigrate"
                $notes.Add("Neither Free/Busy nor MailTips sharing is enabled.")
            }
        } elseif ($scenario -eq "OnPremisesOrHybrid") {
            $status = "NotEligible"
            $notes.Add("The target is on-premises Exchange (hybrid) or a non-Microsoft 365 organization. XTAP only applies between Microsoft 365 organizations, so keep this Organization Relationship.")
        } elseif ($freeBusyCapability -eq "" -and $mailTipsCapability -eq "") {
            $status = "NothingToMigrate"
            $notes.Add("No Free/Busy or MailTips access level maps to an XTAP capability.")
        } elseif ($scenario -eq "Unknown") {
            $status = "Review"
            $notes.Add("Can't tell from TargetApplicationUri, TargetSharingEpr and TargetAutodiscoverEpr whether the target is Microsoft 365. Confirm manually.")
        } elseif ($domains.Count -eq 0) {
            $status = "Review"
            $notes.Add("The relationship has no domain names to map to a Microsoft Entra tenant.")
        } elseif ($ResolveTenantId -and $unresolvedDomains.Count -gt 0) {
            $status = "Review"
            $notes.Add("One or more domains could not be confirmed as Microsoft Entra tenant domains. Ask the external organization for its tenant ID, or confirm it is hosted in Microsoft 365.")
        } else {
            $status = "Eligible"
            if (-not $ResolveTenantId) {
                $notes.Add("Tenant IDs weren't looked up. The generated commands contain a placeholder for the partner tenant ID.")
            }

            $notes.Add("Confirm the external organization has a corresponding Organization Relationship, and that both organizations create complementary XTAP policies for bidirectional sharing.")
        }

        if ($status -notin @("Eligible", "Review")) {
            $freeBusyCapability = ""
            $mailTipsCapability = ""
        }

        [PSCustomObject]@{
            OrganizationRelationship                  = $name
            Enabled                                   = $enabled
            DomainNames                               = $domains -join ";"
            Scenario                                  = $scenario
            Status                                    = $status
            FreeBusyAccessEnabled                     = $freeBusyEnabled
            FreeBusyAccessLevel                       = "$($relationship.FreeBusyAccessLevel)"
            FreeBusyAccessScope                       = if ([string]::IsNullOrEmpty($freeBusyScope)) { "All users" } else { $freeBusyScope }
            FreeBusyScoped                            = $freeBusyScoped
            FreeBusyCapability                        = $freeBusyCapability
            MailTipsAccessEnabled                     = $mailTipsEnabled
            MailTipsAccessLevel                       = "$($relationship.MailTipsAccessLevel)"
            MailTipsAccessScope                       = if ([string]::IsNullOrEmpty($mailTipsScope)) { "All users" } else { $mailTipsScope }
            MailTipsScoped                            = $mailTipsScoped
            MailTipsCapability                        = $mailTipsCapability
            MailboxMoveEnabled                        = $relationship.MailboxMoveEnabled -eq $true
            MailboxMoveCapability                     = "$($relationship.MailboxMoveCapability)"
            HasMailboxMove                            = $hasMailboxMove
            HasMailboxMoveAndSharing                  = $hasMailboxMoveAndSharing
            HasAdditionalEnabledFunctionalities       = $additionalEnabledFunctionalities.Count -gt 0
            AdditionalEnabledFunctionalities          = $additionalEnabledFunctionalities -join ";"
            HasAdditionalFunctionalitiesAndSharing    = $hasAdditionalFunctionalitiesAndSharing
            AdditionalFunctionalitiesRecommendation   = $additionalRecommendation
            SharingCapabilityWouldBeEligibleIfEnabled = $sharingCapabilityWouldBeEligibleIfEnabled
            FreeBusyCapabilityIfEnabled               = $freeBusyCapabilityIfEnabled
            MailTipsCapabilityIfEnabled               = $mailTipsCapabilityIfEnabled
            PartnerTenantIds                          = $partnerTenantIds -join ";"
            MultipleTenants                           = $partnerTenantIds.Count -gt 1
            UnresolvedDomains                         = $unresolvedDomains -join ";"
            DomainTenantResolution                    = @($domainResolutions)
            TargetApplicationUri                      = "$($relationship.TargetApplicationUri)"
            TargetSharingEpr                          = "$($relationship.TargetSharingEpr)"
            TargetAutodiscoverEpr                     = "$($relationship.TargetAutodiscoverEpr)"
            Notes                                     = $notes -join " "
        }
    }
}

<#
.SYNOPSIS
    Analyzes Get-AvailabilityAddressSpace output and recommends Microsoft 365 Cross-Tenant Access Policy capabilities.
.DESCRIPTION
    Follows "Review your Availability Address Space configurations" from
    https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap
#>
function Get-XtapAvailabilityAddressSpaceAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$AvailabilityAddressSpace,

        [Parameter(Mandatory = $false)]
        [switch]$ResolveTenantId
    )

    foreach ($addressSpace in @($AvailabilityAddressSpace)) {
        if ($null -eq $addressSpace) { continue }

        $notes = New-Object System.Collections.Generic.List[string]
        $accessMethod = "$($addressSpace.AccessMethod)"
        $forestName = "$($addressSpace.ForestName)".Trim()
        $tenantId = "$($addressSpace.TargetTenantId)".Trim()
        $configuredTenantId = $tenantId
        $parsedTenantId = [guid]::Empty
        $targetTenantIdValid = [guid]::TryParse($tenantId, [ref]$parsedTenantId)
        if ($targetTenantIdValid) {
            $tenantId = $parsedTenantId.ToString()
        }
        $resolutionStatus = if ($targetTenantIdValid) { "Provided" } elseif ($configuredTenantId -ne "") { "Invalid" } else { "NotRequired" }
        $resolutionError = if ($resolutionStatus -eq "Invalid") { "TargetTenantId [$configuredTenantId] is not a valid GUID." } else { "" }
        $endpoints = @($addressSpace.TargetAutodiscoverEpr, $addressSpace.TargetServiceEpr, $addressSpace.ProxyUrl)

        if (@($endpoints | Where-Object { "$_" -match "(?i)google\.com" }).Count -gt 0) {
            $scenario = "GoogleWorkspace"
        } elseif (@($endpoints | Where-Object { "$_" -match "FYDIBOHF25SPDLT" }).Count -gt 0) {
            $scenario = "OnPremisesOrHybrid"
        } elseif (-not [string]::IsNullOrEmpty($tenantId) -and -not $targetTenantIdValid) {
            $scenario = "Unknown"
        } elseif ($targetTenantIdValid) {
            $scenario = "Microsoft365"
        } else {
            $scenario = Get-XtapTargetScenario -Endpoint $endpoints
        }

        $capability = ""
        $status = "Review"
        if ($accessMethod -ne "OrgWideFBToken") {
            $status = "NotEligible"
            $notes.Add("Only the OrgWideFBToken access method is functional between two Exchange Online tenants, so this Availability Address Space can't be migrated to XTAP. Keep it.")
        } elseif ($scenario -eq "GoogleWorkspace") {
            $status = "NotEligible"
            $notes.Add("The target is Google Workspace. XTAP only applies between Microsoft 365 organizations. Keep it.")
        } elseif ($scenario -eq "OnPremisesOrHybrid") {
            $status = "NotEligible"
            $notes.Add("The target is on-premises Exchange or a non-Microsoft 365 organization. Keep it.")
        } else {
            if (-not [string]::IsNullOrEmpty($configuredTenantId) -and -not $targetTenantIdValid) {
                $notes.Add($resolutionError)
                $tenantId = ""
            } elseif ($targetTenantIdValid) {
                $resolutionStatus = "Provided"
            } elseif ($ResolveTenantId -and -not [string]::IsNullOrEmpty($forestName)) {
                $resolution = Get-XtapDomainTenantResolution -Domain $forestName
                $tenantId = "$($resolution.TenantId)"
                $resolutionStatus = $resolution.Status
                $resolutionError = $resolution.Error
                if ($resolutionStatus -eq "Unresolved") {
                    $notes.Add("Tenant resolution failed for [$forestName]: $resolutionError")
                }
            } else {
                $resolutionStatus = "Skipped"
            }

            if ([string]::IsNullOrEmpty($tenantId) -or $tenantId -notmatch $Script:XtapGuidPattern) {
                $tenantId = ""
                if ($resolutionStatus -ne "Invalid") {
                    $notes.Add("TargetTenantId is empty or couldn't be resolved. Get the partner tenant ID from the external organization.")
                }
            } elseif ($scenario -eq "Unknown") {
                $notes.Add("The endpoints don't identify the target as Microsoft 365. Confirm manually.")
            } else {
                $status = "Eligible"
            }

            if ($status -eq "Eligible" -or $tenantId -ne "") {
                $capability = "crossTenantCalendarAvailabilityBasic"
                $notes.Add("Migration is optional: Free/Busy through an Availability Address Space doesn't depend on EWS. XTAP adds additional security features and more granular configuration options.")
                $notes.Add("An Availability Address Space can't be temporarily disabled. The generated test script backs it up and removes it, and the rollback script restores it.")
            }
        }

        [PSCustomObject]@{
            AvailabilityAddressSpace = "$($addressSpace.Name)"
            ForestName               = $forestName
            AccessMethod             = $accessMethod
            UseServiceAccount        = $addressSpace.UseServiceAccount -eq $true
            Scenario                 = $scenario
            Status                   = $status
            TargetTenantId           = $tenantId
            ConfiguredTargetTenantId = $configuredTenantId
            TargetTenantIdValid      = $targetTenantIdValid
            ResolvedEntraTenantId    = if ($tenantId -match $Script:XtapGuidPattern) { $tenantId } else { "" }
            TenantResolutionStatus   = $resolutionStatus
            TenantResolutionError    = $resolutionError
            MigrationRecommendation  = "XTAP migration is recommended for additional security features and more granular configuration when eligible, but is not required because of EWS deprecation. Keep existing configuration until eligibility is confirmed."
            RecommendedCapability    = $capability
            TargetServiceEpr         = "$($addressSpace.TargetServiceEpr)"
            TargetAutodiscoverEpr    = "$($addressSpace.TargetAutodiscoverEpr)"
            ProxyUrl                 = "$($addressSpace.ProxyUrl)"
            Notes                    = $notes -join " "
        }
    }
}

<#
.SYNOPSIS
    Analyzes Get-SharingPolicy output and recommends Microsoft 365 Cross-Tenant Access Policy capabilities.
.DESCRIPTION
    Follows "Review your Sharing Policy configurations" from
    https://learn.microsoft.com/exchange/sharing/migrate-to-m365-xtap
    One row is returned for each access level of each Domains entry.
.PARAMETER SharingPolicyAssignment
    Optional output of Get-EXOMailbox grouped by SharingPolicy (objects with Name and Count).
.PARAMETER HybridDomain
    Domains of on-premises or hybrid Organization Relationships. Rules for these domains are not eligible.
#>
function Get-XtapSharingPolicyAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$SharingPolicy,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$SharingPolicyAssignment,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$HybridDomain,

        [Parameter(Mandatory = $false)]
        [switch]$ResolveTenantId
    )

    $assignmentByName = @{}
    $hasAssignmentData = $null -ne $SharingPolicyAssignment
    foreach ($assignment in @($SharingPolicyAssignment)) {
        if ($null -ne $assignment) {
            $assignmentByName["$($assignment.Name)"] = $assignment.Count
        }
    }

    $hybridDomains = @(@($HybridDomain) | Where-Object { -not [string]::IsNullOrEmpty($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() })

    foreach ($policy in @($SharingPolicy)) {
        if ($null -eq $policy) { continue }

        $policyName = "$($policy.Name)"
        $policyEnabled = $policy.Enabled -eq $true
        $policyDefault = $policy.Default -eq $true
        $assignedCount = $null
        if ($hasAssignmentData) {
            $assignedCount = if ($assignmentByName.ContainsKey($policyName)) { $assignmentByName[$policyName] } else { 0 }
        }

        foreach ($entry in @(@($policy.Domains) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" })) {
            $parts = $entry -split ":", 2
            $domain = $parts[0].Trim()
            $actions = @()
            if ($parts.Count -gt 1) {
                $actions = @($parts[1].Split(",") | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrEmpty($_) })
            }

            if ($actions.Count -eq 0) {
                $actions = @("")
            }
            $hasContactsSharing = "ContactsSharing" -in $actions
            $contactsSharingAssessment = if ($hasContactsSharing) {
                "ContactsSharing has no identified XTAP equivalent. Preserve this legacy rule until contacts sharing is separately addressed."
            } else { "" }
            $allActionsSupported = @($actions | Where-Object { $_ -notin $Script:XtapCalendarSharingActions }).Count -eq 0

            if ($domain -eq "*") {
                $ruleType = "Wildcard"
            } elseif ($domain -eq "Anonymous") {
                $ruleType = "Anonymous"
            } else {
                $ruleType = "Domain-specific"
            }

            foreach ($action in $actions) {
                $notes = New-Object System.Collections.Generic.List[string]
                $partnerTenantId = ""
                $resolution = "NotApplicable"
                $resolutionError = ""
                $capability = ""
                $status = "Eligible"

                if ($action -in $Script:XtapCalendarSharingActions) {
                    $suffix = $action.Substring("CalendarSharing".Length)
                    $capability = if ($ruleType -eq "Anonymous") { "AnonymousCalendarSharing$suffix" } else { "CrossTenantCalendarSharing$suffix" }
                } elseif ($action -eq "ContactsSharing") {
                    $status = "NotEligible"
                    $notes.Add("ContactsSharing has no Microsoft 365 Cross-Tenant Access Policy equivalent. Keep this Sharing Policy rule.")
                } else {
                    $status = "NotEligible"
                    $notes.Add("[$action] has no Microsoft 365 Cross-Tenant Access Policy calendar sharing capability, or the Domains entry couldn't be parsed. Keep this rule.")
                }

                if ($status -eq "Eligible") {
                    if ($ruleType -eq "Wildcard") {
                        $notes.Add("Created in the default Cross-Tenant Access Policy.")
                    } elseif ($ruleType -eq "Anonymous") {
                        $notes.Add("Anonymous capabilities can only be set in the default Cross-Tenant Access Policy.")
                    } elseif ($domain.ToLowerInvariant() -in $hybridDomains) {
                        $status = "NotEligible"
                        $capability = ""
                        $notes.Add("This domain belongs to an on-premises or hybrid Organization Relationship, so XTAP doesn't apply. Keep this rule.")
                    } elseif ($ResolveTenantId) {
                        $domainResolution = Get-XtapDomainTenantResolution -Domain $domain
                        $partnerTenantId = "$($domainResolution.TenantId)"
                        $resolutionError = $domainResolution.Error
                        if ([string]::IsNullOrEmpty($partnerTenantId)) {
                            $resolution = "Unresolved"
                            $status = "Review"
                            $notes.Add("The domain didn't resolve to a Microsoft Entra tenant ID. Either it isn't hosted in Microsoft 365, in which case XTAP can't be used, or the lookup failed.")
                            $notes.Add("Tenant resolution failed for [$domain]: $resolutionError")
                        } else {
                            $resolution = "Resolved"
                        }
                    } else {
                        $resolution = "Skipped"
                        $status = "Review"
                        $notes.Add("Tenant ID lookup was skipped, so it isn't confirmed that this domain is hosted in Microsoft 365.")
                    }
                }

                $calendarCapabilityWouldBeEligibleIfEnabled = $status -eq "Eligible"
                $capabilityIfEnabled = if ($calendarCapabilityWouldBeEligibleIfEnabled) { $capability } else { "" }
                if ($hasContactsSharing -and $action -ne "ContactsSharing") {
                    $notes.Add($contactsSharingAssessment)
                }
                if (-not $policyEnabled) {
                    $status = "Disabled"
                    $capability = ""
                    $notes.Add("The Sharing Policy is disabled.")
                    if ($calendarCapabilityWouldBeEligibleIfEnabled) {
                        $notes.Add("If enabled, this calendar-sharing capability appears eligible for XTAP.")
                    } else {
                        $notes.Add("Eligibility if enabled is not confirmed; review the rule and tenant-resolution diagnostics.")
                    }
                } elseif ($hasAssignmentData -and $assignedCount -eq 0) {
                    $notes.Add("The Sharing Policy isn't assigned to any user or shared mailbox.")
                }

                [PSCustomObject]@{
                    SharingPolicy                              = $policyName
                    Enabled                                    = $policyEnabled
                    Default                                    = $policyDefault
                    AssignedMailboxCount                       = $assignedCount
                    Rule                                       = $entry
                    RuleType                                   = $ruleType
                    Domain                                     = $domain
                    AccessLevel                                = $action
                    Status                                     = $status
                    RecommendedCapability                      = $capability
                    PartnerTenantId                            = $partnerTenantId
                    TenantResolution                           = $resolution
                    TenantResolutionError                      = $resolutionError
                    HasContactsSharing                         = $hasContactsSharing
                    ContactsSharingAssessment                  = $contactsSharingAssessment
                    LegacyRuleCanBeRetired                     = $policyEnabled -and $calendarCapabilityWouldBeEligibleIfEnabled -and $allActionsSupported
                    CalendarCapabilityWouldBeEligibleIfEnabled = $calendarCapabilityWouldBeEligibleIfEnabled
                    RecommendedCapabilityIfEnabled             = $capabilityIfEnabled
                    Notes                                      = $notes -join " "
                }
            }
        }
    }
}
