# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-XtapMigrationReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Get-Location).Path,

        [Parameter(Mandatory = $false)]
        [string]$CustomerName,

        [Parameter(Mandatory = $false)]
        [string]$OrganizationRelationshipXml,

        [Parameter(Mandatory = $false)]
        [string]$AvailabilityAddressSpaceXml,

        [Parameter(Mandatory = $false)]
        [string]$SharingPolicyXml,

        [Parameter(Mandatory = $false)]
        [string]$SharingPolicyAssignmentXml,

        [Parameter(Mandatory = $false)]
        [switch]$SkipTenantResolution,

        [Parameter(Mandatory = $false)]
        [string]$EntraLoginHost = "login.microsoftonline.com",

        [Parameter(Mandatory = $false)]
        [switch]$ProcessUsers,

        [Parameter(Mandatory = $false)]
        [switch]$GenerateCommandScripts,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru,

        [Parameter(Mandatory = $false)]
        [string]$Organization
    )

    if ($EntraLoginHost -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$') {
        throw "EntraLoginHost [$EntraLoginHost] isn't a valid host name."
    }

    $Script:XtapEntraLoginHost = $EntraLoginHost

    $isOffline = -not [string]::IsNullOrEmpty($OrganizationRelationshipXml)
    if ($isOffline) {
        foreach ($path in @($OrganizationRelationshipXml, $AvailabilityAddressSpaceXml, $SharingPolicyXml)) {
            if ([string]::IsNullOrEmpty($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "The file [$path] wasn't found. Offline analysis needs OrganizationRelationshipXml, AvailabilityAddressSpaceXml and SharingPolicyXml."
            }
        }

        if (-not [string]::IsNullOrEmpty($SharingPolicyAssignmentXml) -and -not (Test-Path -LiteralPath $SharingPolicyAssignmentXml -PathType Leaf)) {
            throw "The file [$SharingPolicyAssignmentXml] wasn't found."
        }
    }

    $displayName = if ([string]::IsNullOrWhiteSpace($CustomerName)) { "Customer" } else { $CustomerName }
    $safeName = $CustomerName -replace '[^A-Za-z0-9._-]', "_"
    $filePrefix = if ([string]::IsNullOrWhiteSpace($CustomerName)) { "" } else { "${safeName}_" }

    $folderName = "XtapReadiness_{0}{1:yyyyMMdd_HHmmss}" -f $filePrefix, (Get-Date)
    $resultsPath = Join-Path -Path $OutputPath -ChildPath $folderName
    New-Item -Path $resultsPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Host "Results will be saved to $resultsPath"

    $configuration = Get-XtapSharingConfiguration -OutputFolder $resultsPath -FilePrefix $filePrefix `
        -OrganizationRelationshipXml $OrganizationRelationshipXml `
        -AvailabilityAddressSpaceXml $AvailabilityAddressSpaceXml `
        -SharingPolicyXml $SharingPolicyXml `
        -SharingPolicyAssignmentXml $SharingPolicyAssignmentXml `
        -ProcessUsers:$ProcessUsers -Organization $Organization

    $resolve = -not $SkipTenantResolution
    if ($resolve) {
        Write-Host "Looking up tenant IDs for the external domains (use -SkipTenantResolution to skip)..."
    }

    $organizationRelationshipAnalysis = @(Get-XtapOrganizationRelationshipAnalysis -OrganizationRelationship $configuration.OrganizationRelationship -ResolveTenantId:$resolve)
    $hybridDomains = @(Get-XtapHybridDomain -OrganizationRelationshipAnalysis $organizationRelationshipAnalysis)
    $availabilityAddressSpaceAnalysis = @(Get-XtapAvailabilityAddressSpaceAnalysis -AvailabilityAddressSpace $configuration.AvailabilityAddressSpace -ResolveTenantId:$resolve)
    $sharingPolicyAnalysis = @(Get-XtapSharingPolicyAnalysis -SharingPolicy $configuration.SharingPolicy `
            -SharingPolicyAssignment $configuration.SharingPolicyAssignment -HybridDomain $hybridDomains -ResolveTenantId:$resolve)

    $csvFiles = @{
        "${filePrefix}OrganizationRelationships_Analysis.csv" = $organizationRelationshipAnalysis
        "${filePrefix}AvailabilityAddressSpaces_Analysis.csv" = $availabilityAddressSpaceAnalysis
        "${filePrefix}SharingPolicies_Analysis.csv"           = $sharingPolicyAnalysis
    }
    foreach ($fileName in $csvFiles.Keys) {
        Export-XtapAnalysisCsv -Analysis $csvFiles[$fileName] -Path (Join-Path -Path $resultsPath -ChildPath $fileName)
    }

    $mailboxCountsMissing = $null -eq $configuration.SharingPolicyAssignment
    $commandScripts = [ordered]@{}
    if ($GenerateCommandScripts) {
        if ($mailboxCountsMissing -and $sharingPolicyAnalysis.Count -gt 0) {
            Write-Warning "The mailbox count for each Sharing Policy wasn't collected (-ProcessUsers). The generated sharing commands assume only one Sharing Policy is in use."
        }

        $commandScripts = Get-XtapCommandScript -OrganizationRelationshipAnalysis $organizationRelationshipAnalysis `
            -AvailabilityAddressSpaceAnalysis $availabilityAddressSpaceAnalysis `
            -SharingPolicyAnalysis $sharingPolicyAnalysis -CustomerName $displayName -Organization $Organization
        foreach ($fileName in $commandScripts.Keys) {
            Write-XtapTextFile -Path (Join-Path -Path $resultsPath -ChildPath $fileName) -Text $commandScripts[$fileName]
        }
    }

    $summaryName = "${filePrefix}XtapReadiness_Summary.txt"
    $rawFiles = @($configuration.Paths.Values | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Split-Path -Path $_ -Leaf } | Sort-Object)
    $generatedFiles = @($rawFiles) + @($csvFiles.Keys | Sort-Object) + @($summaryName) + @($commandScripts.Keys)

    $replayCommand = @()
    if ($configuration.Mode -eq "Live") {
        $replayCommand = @(
            "# Copy this script and the XML files into one folder, then run:",
            ".\Test-XtapMigrationReadiness.ps1 ``",
            "    -CustomerName '$safeName' ``",
            "    -OrganizationRelationshipXml '.\$(Split-Path -Path $configuration.Paths.OrganizationRelationship -Leaf)' ``",
            "    -AvailabilityAddressSpaceXml '.\$(Split-Path -Path $configuration.Paths.AvailabilityAddressSpace -Leaf)' ``",
            "    -SharingPolicyXml '.\$(Split-Path -Path $configuration.Paths.SharingPolicy -Leaf)'" + $(if ($null -ne $configuration.SharingPolicyAssignment) { " ``" } else { "" })
        )
        if ($null -ne $configuration.SharingPolicyAssignment) {
            $replayCommand += "    -SharingPolicyAssignmentXml '.\$(Split-Path -Path $configuration.Paths.SharingPolicyAssignment -Leaf)'"
        }
    }

    $summaryLines = Get-XtapSummaryLines -CustomerName $displayName -Mode $configuration.Mode `
        -OrganizationRelationshipAnalysis $organizationRelationshipAnalysis `
        -AvailabilityAddressSpaceAnalysis $availabilityAddressSpaceAnalysis `
        -SharingPolicyAnalysis $sharingPolicyAnalysis `
        -GeneratedFile $generatedFiles -ReplayCommand $replayCommand `
        -TenantResolutionSkipped:$SkipTenantResolution `
        -ScriptsGenerated:$GenerateCommandScripts -MailboxCountsMissing:$mailboxCountsMissing
    Write-XtapTextFile -Path (Join-Path -Path $resultsPath -ChildPath $summaryName) -Text ($summaryLines -join "`r`n")

    Write-Host ""
    Write-XtapSummary -Line $summaryLines
    Write-Host ""
    Write-Host "Results saved to $resultsPath" -ForegroundColor Green
    Write-Host "These files describe your sharing configuration, including external domain names. Review them before sharing them outside your organization."

    if (-not $PassThru) {
        return
    }

    [PSCustomObject]@{
        ResultsPath                      = $resultsPath
        Mode                             = $configuration.Mode
        OrganizationRelationshipAnalysis = $organizationRelationshipAnalysis
        AvailabilityAddressSpaceAnalysis = $availabilityAddressSpaceAnalysis
        SharingPolicyAnalysis            = $sharingPolicyAnalysis
        GeneratedFiles                   = $generatedFiles
    }
}
