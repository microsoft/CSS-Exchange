# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Protect-XtapCsvValue {
    [CmdletBinding()]
    [OutputType([object], [string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    # Stop spreadsheet applications from running configuration values that look like formulas.
    if ($Value -is [string] -and $Value -match '^[=+\-@\t\r]') {
        return "'$Value"
    }

    return $Value
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
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($true)))
}

function Export-XtapAnalysisCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Analysis,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rows = @(@($Analysis) | Where-Object { $null -ne $_ } | ForEach-Object {
            $safeRow = [ordered]@{}
            foreach ($property in $_.PSObject.Properties) {
                $safeRow[$property.Name] = Protect-XtapCsvValue -Value $property.Value
            }

            [PSCustomObject]$safeRow
        })

    if ($rows.Count -eq 0) {
        # Export-Csv writes nothing for empty input, so write an explicit empty file.
        Write-XtapTextFile -Path $Path -Text ""
        return
    }

    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
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
    Builds the plain text summary for support and the customer.
.DESCRIPTION
    Each line that describes an item starts with [Status] so the console writer can color it.
#>
function Get-XtapSummaryLines {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CustomerName,

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
    $lines.Add("$CustomerName XTAP Migration Readiness - Summary")
    $lines.Add("=" * 60)
    $lines.Add("Collection mode: $Mode")
    $lines.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
    $lines.Add("")
    $lines.Add("Organization Relationships: $(Get-XtapStatusSummary -Analysis $orgRows)")
    $lines.Add("Availability Address Spaces: $(Get-XtapStatusSummary -Analysis $aasRows)")
    $lines.Add("Sharing Policy rules: $(Get-XtapStatusSummary -Analysis $sharingRows)")

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
    $lines.Add("Warnings")
    $lines.Add("--------")
    $warnings = 0
    if ($TenantResolutionSkipped) {
        $warnings++
        $lines.Add("Tenant ID lookup was skipped. Sharing Policy domains need a manual check and the generated commands contain placeholders for tenant IDs.")
    }

    foreach ($row in @($orgRows | Where-Object { $_.HasMailboxMoveAndSharing })) {
        $warnings++
        $lines.Add("'$($row.OrganizationRelationship)' combines mailbox moves with Free/Busy or MailTips. It is kept. The Part 3 and Part 4 scripts only turn off its Free/Busy and MailTips settings, and the Part 3 rollback restores them.")
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

    foreach ($row in @($orgRows | Where-Object { $_.Status -eq "Eligible" -and $_.UnresolvedDomains })) {
        $warnings++
        $lines.Add("'$($row.OrganizationRelationship)' has domains with no tenant ID that are skipped: $($row.UnresolvedDomains)")
    }

    if ($MailboxCountsMissing -and $sharingRows.Count -gt 0) {
        $warnings++
        $lines.Add("The number of mailboxes assigned to each Sharing Policy wasn't collected. Run with -ProcessUsers to count them. This matters when more than one Sharing Policy is in use.")
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
    $lines.Add("1. Review the analysis CSV files and this summary.")
    if ($ScriptsGenerated) {
        $lines.Add("2. Replace any <placeholder> in XTAP_Part2_CreatePolicies.ps1, then run it. Creating the trust needs Global Administrator.")
        $lines.Add("3. Coordinate with the external organizations, then run XTAP_Part3_DisableForTesting.ps1 and test. XTAP_Part3_Rollback.ps1 undoes it.")
        $lines.Add("4. When both sides confirm it works, run XTAP_Part4_Cleanup.ps1.")
    } else {
        $lines.Add("2. This was an assessment only and no command scripts were created. To get the cmdlets for the eligible items, run again with -GenerateCommandScripts (add -ProcessUsers to count the mailboxes for each Sharing Policy).")
    }

    $lines.Add("Existing Organization Relationships, Availability Address Spaces and Sharing Policies take precedence over XTAP.")

    if (@($ReplayCommand).Count -gt 0) {
        $lines.Add("")
        $lines.Add("Support offline-analysis command")
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
            "^\[Eligible\]" { "Green" }
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
