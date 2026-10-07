# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# TODO: Split the reusable skill-package composition and validation into a common build function
# when a second troubleshooting skill adopts this workflow. Keep RBA-specific link and heading
# transformations in an RBA adapter instead of adding product-specific branches to the common function.
function New-RbaTroubleshootingSkillFile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$SkillPath,

        [Parameter(Mandatory)]
        [string]$TsgRulesPath,

        [Parameter(Mandatory)]
        [string]$RulesPath,

        [Parameter(Mandatory)]
        [string]$ManifestPath,

        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    foreach ($requiredPath in @($SkillPath, $TsgRulesPath, $RulesPath, $ManifestPath)) {
        if (-not (Test-Path -Path $requiredPath -PathType Leaf)) {
            throw "Required RBA troubleshooting skill source is missing: $requiredPath"
        }
    }

    $manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
    $skillContent = Get-Content -Path $SkillPath -Raw
    $tsgRulesContent = Get-Content -Path $TsgRulesPath -Raw
    $rulesContent = Get-Content -Path $RulesPath -Raw
    $skillContent = $skillContent.Replace(
        "[TSG-Rules.md](TSG-Rules.md)",
        "the TSG core rules included in this file")
    $skillContent = $skillContent.Replace(
        "Validate each finding against [RBA-Rules.md](RBA-Rules.md)",
        "Validate each finding against the RBA finding rules included in this file")
    $skillContent = $skillContent.Replace(
        "[RBA-Rules.md](RBA-Rules.md)",
        "the RBA finding rules included in this file")
    $tsgRulesContent = $tsgRulesContent.Replace("# EXO TSG core rules", "## TSG core rules")
    $rulesContent = $rulesContent.Replace("# EXO RBA finding rules", "## RBA finding rules")

    $packageMetadata = @"

## Package metadata

- Collection: $($manifest.displayCollection)
- Skill ID: ``$($manifest.id)``
- Skill version: ``$($manifest.version)``
- TSG rules version: ``$($manifest.tsgRulesVersion)``
- Supported report schemas: ``$($manifest.reportSchemaVersions -join "``, ``")``
- Canonical download: $($manifest.downloadUrl)

"@

    $sectionSeparator = [Environment]::NewLine + [Environment]::NewLine
    $combinedContent = @(
        $skillContent.Trim()
        $packageMetadata.Trim()
        $tsgRulesContent.Trim()
        $rulesContent.Trim()
    ) -join $sectionSeparator

    if ($PSCmdlet.ShouldProcess($DestinationPath, "Create RBA troubleshooting skill file")) {
        Set-Content -Path $DestinationPath -Value ($combinedContent + [Environment]::NewLine) -Encoding utf8
    }
}

function New-PrototypeSkillFiles {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [System.IO.DirectoryInfo]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$DestinationFolder
    )

    $destinationPath = Join-Path -Path $DestinationFolder -ChildPath "EXO-RBA-Troubleshooting-SKILL.md"
    if ($PSCmdlet.ShouldProcess($destinationPath, "Create prototype troubleshooting skill files")) {
        $rbaSkillSource = Join-Path -Path $RepoRoot -ChildPath "Calendar\RBA\exo-rba-troubleshooting"
        New-RbaTroubleshootingSkillFile `
            -SkillPath (Join-Path -Path $rbaSkillSource -ChildPath "SKILL.md") `
            -TsgRulesPath (Join-Path -Path $rbaSkillSource -ChildPath "TSG-Rules.md") `
            -RulesPath (Join-Path -Path $rbaSkillSource -ChildPath "RBA-Rules.md") `
            -ManifestPath (Join-Path -Path $rbaSkillSource -ChildPath "manifest.json") `
            -DestinationPath $destinationPath -Confirm:$false
    }
}
