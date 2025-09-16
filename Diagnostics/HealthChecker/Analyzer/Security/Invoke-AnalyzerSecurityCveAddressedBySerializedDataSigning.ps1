# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-SerializedDataSigningState.ps1
. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Invoke-AnalyzerSecurityCveAddressedBySerializedDataSigning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$SecurityObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    <#
        Description: Check for vulnerabilities that are addressed by turning serialized data signing for PowerShell payload on
        Affected Exchange versions: 2016, 2019
        Fix: Serialized Data Signing for PowerShell payload must be enabled and have Nov23SU or newer installed.
    #>

    begin {
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $params = @{
            AnalyzedInformation = $AnalyzeResults
            DisplayGroupingKey  = $DisplayGroupingKey
            Name                = "Security Vulnerability"
            DisplayWriteType    = "Red"
        }

        $detailsString = "{0}`r`n`t`tSee: https://portal.msrc.microsoft.com/security-guidance/advisory/{0} for more information."

        $getSerializedDataSigningState = $null
        Get-SerializedDataSigningState -SecurityObject $SecurityObject | Invoke-RemotePipelineHandler -Result ([ref]$getSerializedDataSigningState)
    }
    process {
        if ($getSerializedDataSigningState.SupportedRole -ne $false) {
            # Enabled by default started with Nov23SU, this will be true when we have that code installed.
            if ($getSerializedDataSigningState.Enabled -eq $false -or
                $getSerializedDataSigningState.EnabledByDefaultVersion -eq $false) {
                Write-Verbose "Vulnerable to serialized data signing CVEs"
                foreach ($cve in @("CVE-2023-36050", "CVE-2023-36039", "CVE-2023-36035", "CVE-2023-36439")) {
                    $params.Details = $detailsString -f $cve
                    $params.DisplayTestingValue = $cve
                    Add-AnalyzedResultInformation @params
                }
            } else {
                Write-Verbose "Not vulnerable to serialized data signing CVEs"
            }
        } else {
            Write-Verbose "Exchange server role is not affected by these vulnerabilities"
        }
        Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($stopWatch.Elapsed.TotalSeconds) seconds"
    }
}
