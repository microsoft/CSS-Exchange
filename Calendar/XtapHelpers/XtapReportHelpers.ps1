# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-XtapInvocationMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.InvocationInfo]$InvocationInfo
    )

    $commandName = if ($InvocationInfo.MyCommand -is [System.Management.Automation.ExternalScriptInfo]) {
        $InvocationInfo.MyCommand.Path
    } else {
        $InvocationInfo.MyCommand.Name
    }
    $commandParts = New-Object System.Collections.Generic.List[string]
    $commandParts.Add("& $(ConvertTo-CalendarDiagnosticCommandLineValue -Value $commandName)")
    foreach ($parameterName in ($InvocationInfo.BoundParameters.Keys | Sort-Object)) {
        if ($parameterName -eq "InvocationInfo") { continue }
        $value = $InvocationInfo.BoundParameters[$parameterName]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            $switchValue = if ($value.IsPresent) { '$true' } else { '$false' }
            $commandParts.Add("-${parameterName}:$switchValue")
        } else {
            $commandParts.Add("-$parameterName $(ConvertTo-CalendarDiagnosticCommandLineValue -Value $value)")
        }
    }
    $userName = [System.Environment]::UserName
    $userDomain = [System.Environment]::UserDomainName

    [PSCustomObject]@{
        CommandLine    = $commandParts -join " "
        InvocationLine = ([string]$InvocationInfo.Line).Trim()
        User           = $(if ([string]::IsNullOrEmpty($userDomain)) { $userName } else { "$userDomain\$userName" })
    }
}

function Write-XtapTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    # UTF-8 with a BOM so Windows PowerShell 5.1 reads the generated scripts correctly.
    $filePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [System.IO.File]::WriteAllText($filePath, $Text, (New-Object System.Text.UTF8Encoding($true)))
}

function Get-XtapStatusSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Analysis
    )

    $rows = @(@($Analysis) | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) {
        return "0"
    }

    $groups = @($rows | Group-Object -Property Status | Sort-Object -Property Name | ForEach-Object { "$($_.Name) $($_.Count)" })
    return "$($rows.Count) ($($groups -join ', '))"
}

<#
.SYNOPSIS
    Builds the plain text summary for tenant administrators and support.
.DESCRIPTION
    Each line that describes an item starts with [Status] so the console writer can color it.
#>
function Get-XtapSummaryLines {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunName,

        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$OrganizationRelationshipAnalysis,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$AvailabilityAddressSpaceAnalysis,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$SharingPolicyAnalysis,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$GeneratedFile,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ReplayCommand,

        [Parameter(Mandatory = $false)]
        [switch]$TenantResolutionSkipped,

        [Parameter(Mandatory = $false)]
        [switch]$ScriptsGenerated,

        [Parameter(Mandatory = $false)]
        [switch]$MailboxCountsMissing
    )

    $orgRows = @(@($OrganizationRelationshipAnalysis) | Where-Object { $null -ne $_ })
    $aasRows = @(@($AvailabilityAddressSpaceAnalysis) | Where-Object { $null -ne $_ })
    $sharingRows = @(@($SharingPolicyAnalysis) | Where-Object { $null -ne $_ })

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$RunName Cross-Tenant Access Policy Calendar Validation - Summary")
    $lines.Add("=" * 60)
    $lines.Add("Collection mode: $Mode")
    $lines.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
    $lines.Add("")
    $lines.Add("Organization Relationships: $(Get-XtapStatusSummary -Analysis $orgRows)")
    $lines.Add("Availability Address Spaces: $(Get-XtapStatusSummary -Analysis $aasRows)")
    $lines.Add("Sharing Policy rules: $(Get-XtapStatusSummary -Analysis $sharingRows)")
    $lines.Add("Organization Relationships with additional enabled functionality: $(@($orgRows | Where-Object { $_.HasAdditionalEnabledFunctionalities }).Count)")
    $lines.Add("Organization Relationships resolving to multiple tenants: $(@($orgRows | Where-Object { $_.MultipleTenants }).Count)")
    $lines.Add("Unresolved Organization Relationship domains: $(@($orgRows | ForEach-Object { $_.DomainTenantResolution } | Where-Object { $_.Status -eq 'Unresolved' }).Count)")
    if ($aasRows.Count -eq 0) {
        $lines.Add("No Availability Address Spaces found.")
    }

    $lines.Add("")
    $lines.Add("Ready to migrate")
    $lines.Add("----------------")
    $ready = 0
    foreach ($row in @($orgRows | Where-Object { $_.Status -eq "Eligible" })) {
        $ready++
        $capabilities = @($row.FreeBusyCapability, $row.MailTipsCapability) | Where-Object { -not [string]::IsNullOrEmpty($_) }
        $lines.Add("[Eligible] Organization Relationship '$($row.OrganizationRelationship)' ($($row.DomainNames)): $($capabilities -join ', ')")
    }

    foreach ($row in @($aasRows | Where-Object { $_.Status -eq "Eligible" })) {
        $ready++
        $lines.Add("[Eligible] Availability Address Space '$($row.ForestName)': $($row.RecommendedCapability)")
    }

    foreach ($row in @($sharingRows | Where-Object { $_.Status -eq "Eligible" })) {
        $ready++
        $lines.Add("[Eligible] Sharing Policy '$($row.SharingPolicy)' rule '$($row.Rule)': $($row.RecommendedCapability)")
    }

    if ($ready -eq 0) {
        $lines.Add("None.")
    }

    $lines.Add("")
    $lines.Add("Can't be upgraded at this time, and why")
    $lines.Add("-----------------------------------------")
    $blocked = 0
    foreach ($row in @($orgRows | Where-Object { $_.Status -in @("NotEligible", "MailboxMoveOnly") })) {
        $blocked++
        $lines.Add("[$($row.Status)] Organization Relationship '$($row.OrganizationRelationship)' ($($row.DomainNames)): $($row.Notes)")
    }

    foreach ($row in @($aasRows | Where-Object { $_.Status -eq "NotEligible" })) {
        $blocked++
        $lines.Add("[$($row.Status)] Availability Address Space '$($row.ForestName)': $($row.Notes)")
    }

    foreach ($row in @($sharingRows | Where-Object { $_.Status -eq "NotEligible" })) {
        $blocked++
        $lines.Add("[$($row.Status)] Sharing Policy '$($row.SharingPolicy)' rule '$($row.Rule)' [$($row.AccessLevel)]: $($row.Notes)")
    }

    if ($blocked -eq 0) {
        $lines.Add("None.")
    }

    $lines.Add("")
    $lines.Add("Needs a manual check before commands can be generated")
    $lines.Add("-----------------------------------------------------")
    $review = 0
    foreach ($row in @($orgRows | Where-Object { $_.Status -eq "Review" })) {
        $review++
        $lines.Add("[Review] Organization Relationship '$($row.OrganizationRelationship)' ($($row.DomainNames)): $($row.Notes)")
    }

    foreach ($row in @($aasRows | Where-Object { $_.Status -eq "Review" })) {
        $review++
        $lines.Add("[Review] Availability Address Space '$($row.ForestName)': $($row.Notes)")
    }

    foreach ($row in @($sharingRows | Where-Object { $_.Status -eq "Review" })) {
        $review++
        $lines.Add("[Review] Sharing Policy '$($row.SharingPolicy)' rule '$($row.Rule)': $($row.Notes)")
    }

    if ($review -eq 0) {
        $lines.Add("None.")
    }

    $lines.Add("")
    $lines.Add("Disabled configuration - assessment if enabled")
    $lines.Add("----------------------------------------------")
    $disabled = 0
    foreach ($row in @($orgRows | Where-Object { $_.Status -eq "Disabled" })) {
        $disabled++
        $capabilities = @($row.FreeBusyCapabilityIfEnabled, $row.MailTipsCapabilityIfEnabled) |
            Where-Object { -not [string]::IsNullOrEmpty($_) }
        $lines.Add("[Disabled] Organization Relationship '$($row.OrganizationRelationship)': $($row.Notes) Potential capabilities if enabled: $($capabilities -join ', ')")
    }
    foreach ($row in @($sharingRows | Where-Object { $_.Status -eq "Disabled" })) {
        $disabled++
        $lines.Add("[Disabled] Sharing Policy '$($row.SharingPolicy)' rule '$($row.Rule)' [$($row.AccessLevel)]: $($row.Notes) Potential capability if enabled: $($row.RecommendedCapabilityIfEnabled)")
    }
    if ($disabled -eq 0) {
        $lines.Add("None.")
    }

    $lines.Add("")
    $lines.Add("Warnings")
    $lines.Add("--------")
    $warnings = 0
    if ($TenantResolutionSkipped) {
        $warnings++
        $lines.Add("Tenant ID lookup was skipped. Sharing Policy domains need a manual check and the generated commands contain placeholders for tenant IDs.")
    }

    foreach ($row in @($orgRows | Where-Object { $_.HasAdditionalEnabledFunctionalities })) {
        $warnings++
        $lines.Add("'$($row.OrganizationRelationship)': $($row.AdditionalFunctionalitiesRecommendation)")
    }

    foreach ($row in @($orgRows | Where-Object { $_.MultipleTenants })) {
        $warnings++
        $lines.Add("'$($row.OrganizationRelationship)' has domains from several tenants: $($row.PartnerTenantIds)")
    }

    foreach ($row in @($orgRows | Where-Object { $_.Status -eq "Eligible" -and ($_.FreeBusyScoped -or $_.MailTipsScoped) })) {
        $warnings++
        $lines.Add("'$($row.OrganizationRelationship)' is limited to a group. The generated commands need a security group ID. XTAP group scoping may behave differently, so test before you rely on it.")
    }

    $assignedPolicies = @($sharingRows | Where-Object { $_.Enabled -and $_.AssignedMailboxCount -gt 0 } | Select-Object -ExpandProperty SharingPolicy -Unique)
    if ($assignedPolicies.Count -gt 1) {
        $warnings++
        $lines.Add("More than one enabled Sharing Policy is assigned to mailboxes ($($assignedPolicies -join ', ')). Comparable XTAP policies need security groups, so the generated calendar sharing commands contain group placeholders.")
    }
    if (@($sharingRows | Where-Object { $_.Status -eq "Eligible" -and ($null -eq $_.AssignedMailboxCount -or $_.AssignedMailboxCount -gt 0) }).Count -gt 0) {
        $warnings++
        $lines.Add("Generated calendar sharing commands require a security group containing only the mailboxes using each Sharing Policy, including inherited default-policy assignments. Mailbox counts alone do not establish tenant-wide applicability. Policies confirmed to have no assigned mailboxes are excluded from generated scripts.")
    }

    foreach ($row in @($orgRows | Where-Object { $_.UnresolvedDomains })) {
        $warnings++
        $lines.Add("'$($row.OrganizationRelationship)' has unresolved domains: $($row.UnresolvedDomains). No migration, test or cleanup commands are generated for this relationship until all domains resolve.")
    }

    foreach ($row in @($sharingRows | Where-Object { $_.HasContactsSharing } |
                Select-Object -Property SharingPolicy, Rule, ContactsSharingAssessment -Unique)) {
        $warnings++
        $lines.Add("Sharing Policy '$($row.SharingPolicy)' rule '$($row.Rule)': $($row.ContactsSharingAssessment)")
    }

    if ($MailboxCountsMissing -and $sharingRows.Count -gt 0) {
        $warnings++
        $lines.Add("The number of mailboxes assigned to each Sharing Policy wasn't collected. Run with -ProcessUsers to identify unused policies. Generated calendar sharing commands use guarded security-group placeholders rather than assuming tenant-wide access.")
    }

    if ($warnings -eq 0) {
        $lines.Add("None.")
    }

    $lines.Add("")
    $lines.Add("Generated files")
    $lines.Add("---------------")
    foreach ($file in @($GeneratedFile)) {
        if (-not [string]::IsNullOrEmpty($file)) { $lines.Add($file) }
    }

    $lines.Add("")
    $lines.Add("Next steps")
    $lines.Add("----------")
    $lines.Add("1. Review the analysis in the JSON bundle and this summary.")
    $hasCreateScript = "XTAP_Part2_CreatePolicies.ps1" -in $GeneratedFile
    $hasTestScript = "XTAP_Part3_DisableForTesting.ps1" -in $GeneratedFile
    $hasRollbackScript = "XTAP_Part3_Rollback.ps1" -in $GeneratedFile
    $hasCleanupScript = "XTAP_Part4_Cleanup.ps1" -in $GeneratedFile
    $nextStep = 2
    if ($hasCreateScript -or $hasTestScript -or $hasRollbackScript -or $hasCleanupScript) {
        if ($hasCreateScript) {
            $lines.Add("$nextStep. Replace any <placeholder> in XTAP_Part2_CreatePolicies.ps1, then run it. Creating the trust needs Global Administrator. Stop if any command fails; do not disable legacy sharing until replacement policies are confirmed.")
            $nextStep++
        }
        if ($hasTestScript) {
            $lines.Add("$nextStep. After confirming Part 2 succeeded, coordinate with the external organizations, then run XTAP_Part3_DisableForTesting.ps1 and test.")
            $nextStep++
        } else {
            $lines.Add("Automatic disable commands are unavailable for this assessment. Preserve unsupported legacy functionality and plan manual testing before changing the existing configuration.")
        }
        if ($hasRollbackScript) {
            $lines.Add("XTAP_Part3_Rollback.ps1 restores the configuration changed during testing. Keep it together with any Availability Address Space backups.")
        } else {
            $lines.Add("Automatic rollback commands are unavailable for this assessment. Plan a manual rollback before changing the existing configuration.")
        }
        if ($hasCleanupScript) {
            $lines.Add("$nextStep. When both sides confirm it works, review XTAP_Part4_Cleanup.ps1. Its configuration-changing commands are commented out; deliberately uncomment the required commands or copy and run them individually. Deletion is permanent.")
        }
    } elseif ($ScriptsGenerated) {
        $lines.Add("2. No command scripts were generated. Review eligibility and mailbox assignments in the analysis; keep the existing configuration until migration prerequisites are satisfied.")
    } else {
        $lines.Add("2. This was an assessment only and no command scripts were created. To get the cmdlets for the eligible items, run again with -GenerateCommandScripts (add -ProcessUsers to count the mailboxes for each Sharing Policy).")
    }

    $lines.Add("Existing Organization Relationships, Availability Address Spaces and Sharing Policies take precedence over XTAP.")

    if (@($ReplayCommand).Count -gt 0) {
        $lines.Add("")
        $lines.Add("Offline-analysis command")
        $lines.Add("--------------------------------")
        foreach ($line in $ReplayCommand) { $lines.Add($line) }
    }

    return $lines.ToArray()
}

function Write-XtapSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]$Line
    )

    foreach ($text in $Line) {
        $color = switch -Regex ($text) {
            "^\[Review\]" { "Yellow" }
            "^\[(NotEligible|MailboxMoveOnly)\]" { "DarkYellow" }
            default { $null }
        }

        if ($color) {
            Write-Host $text -ForegroundColor $color
        } else {
            Write-Host $text
        }
    }
}
