# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This script reviews the ExchangeSetup.log and determines if it is a known issue and reports an
# action to take to resolve the issue.
#
# Use the DelegateSetup switch if the log is from a Delegated Setup and you are running into a Prerequisite Check issue
#
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true,
        Position = 0)]
    [System.IO.FileInfo]$SetupLog,
    [switch]$DelegatedSetup
)

. $PSScriptRoot\..\Shared\SetupLogReviewerLogic.ps1

try {
    Invoke-SetupLogReviewer -SetupLog $SetupLog -DelegatedSetup:$DelegatedSetup
} catch {
    "$($Error[0].Exception)" | Write-Output
    "$($Error[0].ScriptStackTrace)" | Write-Output
    Write-Warning ("Ran into an issue with the script. If possible please email the Setup Log to 'ExToolsFeedback@microsoft.com', or at least notify them of the issue.")
}
