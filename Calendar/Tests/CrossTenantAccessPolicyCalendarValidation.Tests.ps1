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
    . $Script:parentPath\CalLogHelpers\Write-DashLineBoxColor.ps1

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
        $Script:scripts = Get-XtapCommandScript -OrganizationRelationshipAnalysis $Script:orgAnalysis -AvailabilityAddressSpaceAnalysis @() -SharingPolicyAnalysis $Script:sharingAnalysis -RunName "BeforeMigration"
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

    It "Includes the run label and timestamp in generated headers" {
        foreach ($name in $Script:scripts.Keys) {
            $Script:scripts[$name] | Should -Match "for run 'BeforeMigration' on \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
        }
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
    It "Writes text files with a UTF-8 BOM" {
        $path = Join-Path -Path $TestDrive -ChildPath "bom.txt"
        Write-XtapTextFile -Path $path -Text "hello"
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0..2] | Should -Be @(0xEF, 0xBB, 0xBF)
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
        (Split-Path -Path $result.ResultsPath -Leaf) | Should -Match '^CrossTenantAccessPolicyCalendarValidation_AfterMigration_\d{8}_\d{6}_\d{3}$'
        (Split-Path -Path $result.DataPath -Leaf) | Should -Be "AfterMigration_CrossTenantAccessPolicyCalendarValidation_Data.json"
        $data.Summary[0] | Should -Match "^AfterMigration "
        $data.Summary -join "`n" | Should -Match "Generated: \d{4}-\d{2}-\d{2}"
        $data.CommandScripts.'XTAP_Part4_Cleanup.ps1' | Should -Match "for run 'AfterMigration'"
        $data.Summary -join "`n" | Should -Match "configuration-changing commands are commented out"
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
        foreach ($invalidCase in @("Boolean", "Collection", "Item", "TenantId", "Count", "Metadata", "RunName")) {
            $data = Get-Content -LiteralPath $Script:importPath -Raw | ConvertFrom-Json
            switch ($invalidCase) {
                "Boolean" { $data.Configuration.SharingPolicy[0].Enabled = "false" }
                "Collection" { $data.Configuration.SharingPolicy = $data.Configuration.SharingPolicy[0] }
                "Item" { $data.Configuration.OrganizationRelationship = @("invalid") }
                "TenantId" { $data.TenantResolution[0].TenantId = "invalid" }
                "Count" { $data.Configuration.SharingPolicyAssignment = @([PSCustomObject]@{ Name = "Default"; Count = -1 }) }
                "Metadata" { $data.Metadata.TenantResolutionSkipped = "false" }
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
        $offline = Invoke-CrossTenantAccessPolicyCalendarValidation -OutputPath $TestDrive -ImportData $live.DataPath 6>$null
        $offline.OrganizationRelationshipAnalysis[0].Status | Should -Be "Review"
        Should -Invoke -CommandName Invoke-RestMethod -Times 1 -Exactly
    }

    It "Generates JSON backup and rollback scripts that parse and restore the address space" {
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
        Push-Location -Path $TestDrive
        try {
            & ([ScriptBlock]::Create($scripts["XTAP_Part3_DisableForTesting.ps1"]))
            Test-Path -LiteralPath ".\AvailabilityAddressSpaceBackup_partner.com.json" | Should -BeTrue
            & ([ScriptBlock]::Create($scripts["XTAP_Part3_Rollback.ps1"]))
            Should -Invoke -CommandName Add-AvailabilityAddressSpace -Times 1 -Exactly -ParameterFilter {
                $ForestName -eq "partner.com" -and $AccessMethod -eq "OrgWideFBToken" -and $TargetTenantId -eq $Script:TenantA
            }
        } finally {
            Pop-Location
        }
    }
}
