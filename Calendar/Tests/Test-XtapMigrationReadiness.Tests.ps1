# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\XtapHelpers\XtapAnalysisHelpers.ps1
    . $Script:parentPath\XtapHelpers\XtapCollectionHelpers.ps1
    . $Script:parentPath\XtapHelpers\XtapCommandHelpers.ps1
    . $Script:parentPath\XtapHelpers\XtapReportHelpers.ps1
    . $Script:parentPath\XtapHelpers\Invoke-XtapMigrationReadiness.ps1

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
            [string]$ApplicationUri = "outlook.com",
            [string]$AutodiscoverEpr = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc/WSSecurity"
        )

        [PSCustomObject]@{
            Name                  = $Name
            DomainNames           = $DomainNames
            Enabled               = $Enabled
            FreeBusyAccessEnabled = $FreeBusy
            FreeBusyAccessLevel   = $FreeBusyLevel
            FreeBusyAccessScope   = $FreeBusyScope
            MailTipsAccessEnabled = $MailTips
            MailTipsAccessLevel   = $MailTipsLevel
            MailTipsAccessScope   = ""
            MailboxMoveEnabled    = $MailboxMove
            MailboxMoveCapability = $MailboxMoveCapability
            TargetApplicationUri  = $ApplicationUri
            TargetSharingEpr      = ""
            TargetAutodiscoverEpr = $AutodiscoverEpr
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
        $Script:scripts = Get-XtapCommandScript -OrganizationRelationshipAnalysis $Script:orgAnalysis -AvailabilityAddressSpaceAnalysis @() -SharingPolicyAnalysis $Script:sharingAnalysis -CustomerName "Contoso"
    }

    It "Returns the four scripts" {
        @($Script:scripts.Keys) | Should -Be @("XTAP_Part2_CreatePolicies.ps1", "XTAP_Part3_DisableForTesting.ps1", "XTAP_Part3_Rollback.ps1", "XTAP_Part4_Cleanup.ps1")
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
        foreach ($name in @("XTAP_Part3_DisableForTesting.ps1", "XTAP_Part4_Cleanup.ps1")) {
            $Script:scripts[$name] | Should -Match "Set-OrganizationRelationship -Identity 'Split' -FreeBusyAccessEnabled \`$false"
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
        $generated = Get-XtapCommandScript -OrganizationRelationshipAnalysis $Script:orgAnalysis -AvailabilityAddressSpaceAnalysis @() -SharingPolicyAnalysis $Script:sharingAnalysis -CustomerName "Contoso" -Organization "contoso.onmicrosoft.com"
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "Connect-MgGraph .*-TenantId 'contoso.onmicrosoft.com'"
        $generated["XTAP_Part3_DisableForTesting.ps1"] | Should -Match "Set-OrganizationRelationship -Identity 'Contoso''s Partner' -Enabled \`$false -Organization 'contoso.onmicrosoft.com'"
        $generated["XTAP_Part4_Cleanup.ps1"] | Should -Match "Remove-SharingPolicy .* -Organization 'contoso.onmicrosoft.com'"
        foreach ($name in $generated.Keys) {
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($generated[$name], [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0 -Because $name
        }
    }

    It "Uses placeholders guarded by an assertion when tenant IDs are unknown" {
        $unresolved = @(Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship (Get-TestRelationship))
        $generated = Get-XtapCommandScript -OrganizationRelationshipAnalysis $unresolved -AvailabilityAddressSpaceAnalysis @() -SharingPolicyAnalysis @() -CustomerName "Contoso"
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "<PartnerTenantId"
        $generated["XTAP_Part2_CreatePolicies.ps1"] | Should -Match "function Assert-XtapInput"
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
        $result = Get-XtapSharingConfiguration -OutputFolder $TestDrive -FilePrefix "fb_" -ProcessUsers 6>$null
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
        $result = Get-XtapSharingConfiguration -OutputFolder $TestDrive -FilePrefix "np_" 6>$null
        $script:mailboxQueried | Should -BeFalse
        $result.SharingPolicyAssignment | Should -BeNullOrEmpty
        $null = Get-XtapSharingConfiguration -OutputFolder $TestDrive -FilePrefix "p_" -ProcessUsers 6>$null
        $script:mailboxQueried | Should -BeTrue
    }

    It "Passes -Organization to the collection cmdlets" {
        function Get-OrganizationRelationship { param($Organization) $script:capturedOrganization = $Organization }
        function Get-AvailabilityAddressSpace { param($Organization) }
        function Get-SharingPolicy { param($Organization) }
        function Get-EXOMailbox { param($Organization, $ResultSize, $RecipientTypeDetails, $Properties) }
        $null = Get-XtapSharingConfiguration -OutputFolder $TestDrive -FilePrefix "org_" -ProcessUsers -Organization "contoso.onmicrosoft.com" 6>$null
        $script:capturedOrganization | Should -Be "contoso.onmicrosoft.com"
    }

    It "Stops when a cmdlet has no -Organization parameter" {
        function Get-OrganizationRelationship { param() }
        function Get-AvailabilityAddressSpace { param($Organization) }
        function Get-SharingPolicy { param($Organization) }
        { Get-XtapSharingConfiguration -OutputFolder $TestDrive -FilePrefix "org2_" -Organization "contoso.onmicrosoft.com" 6>$null } | Should -Throw
    }
}

Describe "Report helpers" {
    It "Protects CSV values that could be formulas" {
        Protect-XtapCsvValue -Value "=cmd|calc" | Should -Be "'=cmd|calc"
        Protect-XtapCsvValue -Value "normal" | Should -Be "normal"
    }

    It "Writes text files with a UTF-8 BOM" {
        $path = Join-Path -Path $TestDrive -ChildPath "bom.txt"
        Write-XtapTextFile -Path $path -Text "hello"
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0..2] | Should -Be @(0xEF, 0xBB, 0xBF)
    }
}

Describe "Invoke-XtapMigrationReadiness offline" {
    BeforeAll {
        Mock Resolve-XtapDomainTenantId { $Script:TenantA }
        $Script:inputPath = Join-Path -Path $TestDrive -ChildPath "input"
        New-Item -Path $Script:inputPath -ItemType Directory | Out-Null
        @(Get-TestRelationship -Name "Partner") | Export-Clixml -Path "$Script:inputPath\OrgRel.xml"
        @() | Export-Clixml -Path "$Script:inputPath\AAS.xml"
        @([PSCustomObject]@{ Name = "Default"; Enabled = $true; Default = $true; Domains = @("*:CalendarSharingFreeBusySimple") }) | Export-Clixml -Path "$Script:inputPath\SharingPolicy.xml"
        $Script:outputPath = Join-Path -Path $TestDrive -ChildPath "out"
        New-Item -Path $Script:outputPath -ItemType Directory | Out-Null
        $Script:run = Invoke-XtapMigrationReadiness -OutputPath $Script:outputPath -CustomerName "Contoso" -PassThru -GenerateCommandScripts 6>$null 3>$null `
            -OrganizationRelationshipXml "$Script:inputPath\OrgRel.xml" `
            -AvailabilityAddressSpaceXml "$Script:inputPath\AAS.xml" `
            -SharingPolicyXml "$Script:inputPath\SharingPolicy.xml"
    }

    It "Analyzes the files and writes every output" {
        $Script:run.Mode | Should -Be "Offline"
        $Script:run.OrganizationRelationshipAnalysis[0].Status | Should -Be "Eligible"
        foreach ($file in $Script:run.GeneratedFiles) {
            Test-Path -LiteralPath (Join-Path -Path $Script:run.ResultsPath -ChildPath $file) | Should -BeTrue -Because $file
        }
    }

    It "Only assesses by default" {
        $result = Invoke-XtapMigrationReadiness -OutputPath $Script:outputPath -CustomerName "Assess" -PassThru 6>$null `
            -OrganizationRelationshipXml "$Script:inputPath\OrgRel.xml" `
            -AvailabilityAddressSpaceXml "$Script:inputPath\AAS.xml" `
            -SharingPolicyXml "$Script:inputPath\SharingPolicy.xml"
        @(Get-ChildItem -Path $result.ResultsPath -Filter "XTAP_*.ps1").Count | Should -Be 0
        @(Get-ChildItem -Path $result.ResultsPath -Filter "*_Analysis.csv").Count | Should -Be 3
        (Get-Content -Path (Join-Path $result.ResultsPath "Assess_XtapReadiness_Summary.txt") -Raw) | Should -Match "-GenerateCommandScripts"
    }

    It "Works without a customer name" {
        $result = Invoke-XtapMigrationReadiness -OutputPath $Script:outputPath -PassThru 6>$null `
            -OrganizationRelationshipXml "$Script:inputPath\OrgRel.xml" `
            -AvailabilityAddressSpaceXml "$Script:inputPath\AAS.xml" `
            -SharingPolicyXml "$Script:inputPath\SharingPolicy.xml"
        Test-Path -LiteralPath (Join-Path $result.ResultsPath "XtapReadiness_Summary.txt") | Should -BeTrue
    }

    It "Throws when an input file is missing" {
        { Invoke-XtapMigrationReadiness -OutputPath $Script:outputPath -OrganizationRelationshipXml "$Script:inputPath\OrgRel.xml" -AvailabilityAddressSpaceXml "$Script:inputPath\Missing.xml" -SharingPolicyXml "$Script:inputPath\SharingPolicy.xml" 6>$null } | Should -Throw
    }
}
