# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-FipsUpgradeConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $ErrorRefAndSetupLog
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $errorReference = $ErrorRefAndSetupLog.ErrorReference
        $setupLogReviewer = $ErrorRefAndSetupLog.SetupLogReviewer

        if ($errorReference.Matches.Groups[1].Value -eq "BridgeheadComponent___9FAA17C4-73D7-4E6D-9012-6274971434D5") {
            Write-Verbose "Found Fips Upgrade Configuration - BridgeheadComponent___9FAA17C4-73D7-4E6D-9012-6274971434D5"

            $errorContext = $setupLogReviewer | GetFirstErrorWithContextToLine $errorReference.LineNumber
            $accessDenied = $errorContext | Select-String "Access to the path is denied."

            if ($null -ne $accessDenied) {
                Write-Verbose "Access to the path denied found"
                $errorContext | New-ErrorContext
                New-ActionPlan @(
                    "Failed to access the path and upgrade '\V15\FIP-FS\Data\Configuration.xml'",
                    "Check access rights to this location OR use PROCMON to determine why this is occurring."
                )
            }
        }
    }
}
