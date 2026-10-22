# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# cSpell:ignore Dont

function Invoke-CrossTenantAccessPolicyCalendarValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Get-Location).Path,

        [Parameter(Mandatory = $false)]
        [string]$RunName,

        [Parameter(Mandatory = $false)]
        [string]$ImportData,

        [Parameter(Mandatory = $false)]
        [switch]$SkipTenantResolution,

        [Parameter(Mandatory = $false)]
        [string]$EntraLoginHost = "login.microsoftonline.com",

        [Parameter(Mandatory = $false)]
        [switch]$ProcessUsers,

        [Parameter(Mandatory = $false)]
        [switch]$GenerateCommandScripts,

        [Parameter(Mandatory = $false)]
        [string]$Organization,

        [Parameter(DontShow)]
        [System.Management.Automation.InvocationInfo]$InvocationInfo = $MyInvocation
    )

    $initialErrors = New-Object 'System.Collections.Generic.HashSet[object]'
    foreach ($runError in @($global:Error)) {
        [void]$initialErrors.Add($runError)
    }
    $invocationMetadata = Get-XtapInvocationMetadata -InvocationInfo $InvocationInfo

    if ($EntraLoginHost -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' -or
        [uri]::CheckHostName($EntraLoginHost) -ne [UriHostNameType]::Dns) {
        throw "EntraLoginHost [$EntraLoginHost] isn't a valid host name."
    }

    $title = "Cross-Tenant Access Policy Calendar Validation"
    $separator = "-" * $title.Length
    Write-XtapSummary -Line @("", $separator, $title, $separator, "")
    $configuration = Get-XtapSharingConfiguration -ImportData $ImportData -ProcessUsers:$ProcessUsers -Organization $Organization
    $Script:XtapDomainTenantCache = @{}
    $Script:XtapDomainTenantErrors = @{}
    $Script:XtapOfflineData = $configuration.Mode -eq "Offline"
    if ($Script:XtapOfflineData) {
        foreach ($entry in $configuration.TenantResolution) {
            $Script:XtapDomainTenantCache[$entry.Domain.ToLowerInvariant()] = $entry.TenantId
            $resolutionError = $entry.PSObject.Properties["Error"]
            if ($null -ne $resolutionError -and -not [string]::IsNullOrEmpty($resolutionError.Value)) {
                $Script:XtapDomainTenantErrors[$entry.Domain.ToLowerInvariant()] = $resolutionError.Value
            }
        }
        $Organization = $configuration.Metadata.Organization
        $EntraLoginHost = $configuration.Metadata.EntraLoginHost
        if (-not $PSBoundParameters.ContainsKey("RunName")) { $RunName = $configuration.Metadata.RunName }
        if (-not $PSBoundParameters.ContainsKey("SkipTenantResolution")) {
            $SkipTenantResolution = [bool]$configuration.Metadata.TenantResolutionSkipped
        }
    }
    $Script:XtapEntraLoginHost = $EntraLoginHost

    $displayName = if ([string]::IsNullOrWhiteSpace($RunName)) { "Calendar Validation" } else { $RunName }
    $safeName = if ([string]::IsNullOrWhiteSpace($RunName)) { "" } else { ConvertTo-CalendarDiagnosticFileNameStem -Value $RunName }
    $filePrefix = if ([string]::IsNullOrWhiteSpace($RunName)) { "" } else { "${safeName}_" }

    $folderName = "{0}XTAP_Calendar_{1:yyyyMMdd_HH.mm.ss}" -f $filePrefix, (Get-Date)
    $resultsPath = Join-Path -Path $OutputPath -ChildPath $folderName
    $folderSuffix = 0
    while (Test-Path -LiteralPath $resultsPath) {
        $folderSuffix++
        $resultsPath = Join-Path -Path $OutputPath -ChildPath "${folderName}_$folderSuffix"
    }
    New-Item -Path $resultsPath -ItemType Directory -ErrorAction Stop | Out-Null
    Write-Host "Results will be saved to $resultsPath"

    $resolve = -not $SkipTenantResolution
    if ($resolve) {
        Write-Host "Looking up tenant IDs for the external domains (use -SkipTenantResolution to skip)..."
    }

    $organizationRelationshipAnalysis = @(Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship $configuration.OrganizationRelationship -ResolveTenantId:$resolve)
    $hybridDomains = @(Get-XtapHybridDomain -OrganizationRelationshipAnalysis $organizationRelationshipAnalysis)
    $availabilityAddressSpaceAnalysis = @(Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $configuration.AvailabilityAddressSpace -ResolveTenantId:$resolve)
    $sharingPolicyAnalysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $configuration.SharingPolicy `
            -SharingPolicyAssignment $configuration.SharingPolicyAssignment -HybridDomain $hybridDomains -ResolveTenantId:$resolve)

    $mailboxCountsMissing = $null -eq $configuration.SharingPolicyAssignment
    $commandScripts = [ordered]@{}
    if ($GenerateCommandScripts) {
        if ($mailboxCountsMissing -and $sharingPolicyAnalysis.Count -gt 0) {
            Write-Warning "The mailbox count for each Sharing Policy wasn't collected (-ProcessUsers). The generated sharing commands assume only one Sharing Policy is in use."
        }

        $commandScripts = Get-XtapCommandScript -OrganizationRelationshipAnalysis $organizationRelationshipAnalysis `
            -AvailabilityAddressSpaceAnalysis $availabilityAddressSpaceAnalysis `
            -SharingPolicyAnalysis $sharingPolicyAnalysis -RunName $displayName -Organization $Organization
        foreach ($fileName in $commandScripts.Keys) {
            Write-XtapTextFile -Path (Join-Path -Path $resultsPath -ChildPath $fileName) -Text $commandScripts[$fileName]
        }
    }

    $summaryName = "${filePrefix}CrossTenantAccessPolicyCalendarValidation_Summary.txt"
    $dataName = "${filePrefix}CrossTenantAccessPolicyCalendarValidation_Data.json"
    $generatedFiles = @($dataName, $summaryName) + @($commandScripts.Keys)

    $replayCommand = @(
        "# Copy this script and the JSON bundle into one folder, then run:",
        ".\CrossTenantAccessPolicyCalendarValidation.ps1 -ImportData $(ConvertTo-XtapLiteral -Value ".\$dataName")"
    )

    $summaryLines = Get-XtapSummaryLines -RunName $displayName -Mode $configuration.Mode `
        -OrganizationRelationshipAnalysis $organizationRelationshipAnalysis `
        -AvailabilityAddressSpaceAnalysis $availabilityAddressSpaceAnalysis `
        -SharingPolicyAnalysis $sharingPolicyAnalysis `
        -GeneratedFile $generatedFiles -ReplayCommand $replayCommand `
        -TenantResolutionSkipped:$SkipTenantResolution `
        -ScriptsGenerated:$GenerateCommandScripts -MailboxCountsMissing:$mailboxCountsMissing
    Write-XtapTextFile -Path (Join-Path -Path $resultsPath -ChildPath $summaryName) -Text ($summaryLines -join "`r`n")

    $data = [ordered]@{
        SchemaVersion    = 1
        Summary          = @($summaryLines)
        Metadata         = [ordered]@{
            ScriptName              = "CrossTenantAccessPolicyCalendarValidation"
            GeneratedUtc            = [DateTime]::UtcNow.ToString("o")
            Mode                    = $configuration.Mode
            RunName                 = $RunName
            Organization            = $Organization
            EntraLoginHost          = $EntraLoginHost
            TenantResolutionSkipped = [bool]$SkipTenantResolution
            CommandLine             = $invocationMetadata.CommandLine
            InvocationLine          = $invocationMetadata.InvocationLine
            User                    = $invocationMetadata.User
        }
        Errors           = @(@($global:Error) |
                Where-Object { -not $initialErrors.Contains($_) } |
                ForEach-Object { ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_ })
        Configuration    = [ordered]@{
            OrganizationRelationship = @($configuration.OrganizationRelationship)
            AvailabilityAddressSpace = @($configuration.AvailabilityAddressSpace)
            SharingPolicy            = @($configuration.SharingPolicy)
            SharingPolicyAssignment  = $configuration.SharingPolicyAssignment
        }
        TenantResolution = @(
            foreach ($domain in ($Script:XtapDomainTenantCache.Keys | Sort-Object)) {
                [PSCustomObject]@{
                    Domain   = $domain
                    TenantId = $Script:XtapDomainTenantCache[$domain]
                    Error    = if ($Script:XtapDomainTenantErrors.ContainsKey($domain)) { $Script:XtapDomainTenantErrors[$domain] } else { "" }
                }
            }
        )
        Analysis         = [ordered]@{
            OrganizationRelationship = $organizationRelationshipAnalysis
            AvailabilityAddressSpace = $availabilityAddressSpaceAnalysis
            SharingPolicy            = $sharingPolicyAnalysis
        }
        CommandScripts   = $commandScripts
        GeneratedFiles   = $generatedFiles
    }
    Write-CalendarDiagnosticJsonFile -InputObject $data -Path (Join-Path -Path $resultsPath -ChildPath $dataName)

    Write-Host ""
    Write-XtapSummary -Line $summaryLines
    Write-Host ""
    Write-Host "Results saved to $resultsPath"
    Write-Host "These files include your sharing configuration, external domains, command line, executing user, and run errors. Review them before sharing them outside your organization."

    [PSCustomObject]@{
        ResultsPath                      = $resultsPath
        DataPath                         = Join-Path -Path $resultsPath -ChildPath $dataName
        Mode                             = $configuration.Mode
        OrganizationRelationshipAnalysis = $organizationRelationshipAnalysis
        AvailabilityAddressSpaceAnalysis = $availabilityAddressSpaceAnalysis
        SharingPolicyAnalysis            = $sharingPolicyAnalysis
        GeneratedFiles                   = $generatedFiles
    }
}
