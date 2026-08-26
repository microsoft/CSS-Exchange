# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    Registry of all CVE mitigation definitions for EOMT.
    Provides a function to retrieve a mitigation definition in a standardized format
    so the orchestrator remains CVE-agnostic.

    Each CVE definition must return a PSCustomObject with these required properties:

    [string]   Id                 - The CVE identifier (e.g., "CVE-2022-41040")
    [int]      Priority           - Lower number = higher priority. The lowest Priority CVE
                                    is presented as the default selection when -CVE is not specified.
    [string]   Description        - Human-readable description of the vulnerability and mitigation
    [bool]     RequiresUrlRewrite - Whether the IIS URL Rewrite Module must be installed
    [string]   SiteName           - The IIS site where mitigations are applied (e.g., "Default Web Site")
    [ScriptBlock] TestVulnerable
                                    - Returns a hashtable with the following properties:
                                      [bool]  MitigationApplied - Whether the IIS mitigation rules
                                              are currently present AND enabled.
                                      [bool]  CodeFixApplied    - Whether the server's Exchange build
                                              includes the security fix for this CVE.
                                      [array] DisabledRules     - Array of @{ Filter; PSPath } for rules
                                              that match the mitigation but are disabled. Empty array
                                              when no disabled rules found. The orchestrator uses this
                                              to re-enable rules instead of creating new ones.
                                      [bool]  RuleNameMatch     - True when a rule exists with the expected
                                              name but does NOT match the expected behavior. Indicates a
                                              name conflict that blocks apply — admin must rollback first.
                                      Should throw on unrecoverable errors (e.g., can't
                                      determine Exchange version). Must work over PS remoting
                                      (no module dependencies).
    [ScriptBlock] GetActions      - Returns an array of PSCustomObject action definitions, each with:
                                        [string]    Cmdlet      - The IIS cmdlet to execute
                                        [hashtable] Parameters  - Parameters to pass to the cmdlet
                                        [string]    RuleName    - (Required for Add-WebConfigurationProperty)
                                                                  The element name, used to build targeted
                                                                  Clear-WebConfiguration filter for rollback
                                        [string]    ElementName - (Optional for Add-WebConfigurationProperty)
                                                                  The IIS collection element type. Defaults to "rule".
                                                                  Override for other types (e.g., "preCondition").
#>

. $PSScriptRoot\CVE-2021-26855.ps1
. $PSScriptRoot\CVE-2022-41040.ps1
. $PSScriptRoot\CVE-2026-42897.ps1

$script:MitigationDefinitionMap = @{
    "CVE-2021-26855" = { Get-CVE202126855-MitigationDefinition }
    "CVE-2022-41040" = { Get-CVE202241040-MitigationDefinition }
    "CVE-2026-42897" = { Get-CVE202642897-MitigationDefinition }
}

<#
.DESCRIPTION
    Returns the mitigation definition for the specified CVE.
#>
function Get-MitigationDefinition {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CVE
    )

    if (-not $script:MitigationDefinitionMap.ContainsKey($CVE)) {
        throw "Unknown CVE identifier: $CVE. Available: $($script:MitigationDefinitionMap.Keys -join ', ')"
    }

    return (& $script:MitigationDefinitionMap[$CVE])
}
