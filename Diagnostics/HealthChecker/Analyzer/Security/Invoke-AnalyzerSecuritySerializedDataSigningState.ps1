# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-SerializedDataSigningState.ps1
function Invoke-AnalyzerSecuritySerializedDataSigningState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    $getSerializedDataSigningState = Get-SerializedDataSigningState -HealthServerObject $HealthServerObject
    # Because this is tied to public CVEs now, everything must be Red unless configured correctly
    # We must also show it even if not on the correct build of Exchange.
    $serializedDataSigningWriteType = "Red"
    $serializedDataSigningState = $false

    if ($getSerializedDataSigningState.SupportedRole -eq $false) {
        Write-Verbose "Not on a supported role, skipping over displaying this information."
        return
    }

    if ($getSerializedDataSigningState.SupportedVersion -eq $false) {
        Write-Verbose "Not on a supported version of Exchange that has serialized data signing option."
        $serializedDataSigningState = "Unsupported Version"
    } elseif ($getSerializedDataSigningState.Enabled) {
        $serializedDataSigningState = $true
        $serializedDataSigningWriteType = "Green"
    }

    $params = $baseParams + @{
        Name             = "SerializedDataSigning Enabled"
        Details          = $serializedDataSigningState
        DisplayWriteType = $serializedDataSigningWriteType
    }
    Add-AnalyzedResultInformation @params

    # Always display if not true
    if (-not ($serializedDataSigningState -eq $true)) {
        $addLine = "This may pose a security risk to your servers`r`n`t`tMore Information: https://aka.ms/HC-SerializedDataSigning"

        if (-not ([string]::IsNullOrEmpty($getSerializedDataSigningState.AdditionalInformation))) {
            $details = "$($getSerializedDataSigningState.AdditionalInformation)`r`n`t`t$addLine"
        } else {
            $details = $addLine
        }

        $params = $baseParams + @{
            Details                = $details
            DisplayWriteType       = $serializedDataSigningWriteType
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }
}
