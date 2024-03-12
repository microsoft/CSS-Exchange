# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1

<#
.DESCRIPTION
    Check for ADV24199947 Outside In Module vulnerability
    Must be on March 2024 SU and no overrides in place to be considered secure.
    Overrides are found in the Configuration.xml file with appending flag of |NO
    This only needs to occur on the Mailbox Servers Roles
#>
function Invoke-AnalyzerSecurityADV24199947 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$SecurityObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $params = @{
            AnalyzedInformation = $AnalyzeResults
            DisplayGroupingKey  = $DisplayGroupingKey
            Name                = "Security Vulnerability"
            DisplayWriteType    = "Red"
            Details             = "{0}"
            DisplayTestingValue = "ADV24199947"
        }

        if ($SecurityObject.IsEdgeServer) {
            Write-Verbose "Skipping over test as this is an edge server."
            return
        }

        $isVulnerable = (-not (Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $SecurityObject.BuildInformation -SUName "Mar24SU"))

        # if patch is installed, need to check for the override.
        if ($isVulnerable -eq $false) {
            Write-Verbose "Mar24SU is installed, checking to see if override is set"
            # Key for the file content information
            $key = [System.IO.Path]::Combine($SecurityObject.ExchangeInformation.RegistryValues.FipFsDatabasePath, "Configuration.xml")
            $unknownError = [string]::IsNullOrEmpty($SecurityObject.ExchangeInformation.RegistryValues.FipFsDatabasePath) -or
                ($null -eq $SecurityObject.ExchangeInformation.FileContentInformation[$key])

            if ($unknownError) {
                $params.Details += " Unable to determine if override is set due to no data to review."
                $params.DisplayWriteType = "Yellow"
                $isVulnerable = $true
            } else {
                $isVulnerable = $null -ne ($SecurityObject.ExchangeInformation.FileContentInformation[$key] | Select-String "\|NO")
            }
        }

        if ($isVulnerable) {
            $params.Details = ("$($params.Details)`r`n`t`tSee: https://portal.msrc.microsoft.com/security-guidance/advisory/{0} for more information." -f "ADV24199947")
            Add-AnalyzedResultInformation @params
        } else {
            Write-Verbose "Not vulnerable to ADV24199947"
        }
    }
}
