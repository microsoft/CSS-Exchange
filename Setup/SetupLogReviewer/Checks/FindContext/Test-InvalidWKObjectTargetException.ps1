# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
Function Test-InvalidWKObjectTargetException {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $invalidWKObjectTargetException = $SetupLogReviewer |
            SelectStringLastRunOfExchangeSetup "The well-known object entry with the GUID `"(.+)`", which is on the `"(.+)`" container object's otherWellKnownObjects attribute, refers to a group `"(.+)`" of the wrong group type. Either delete the well-known object entry, or promote the target object to `"(.+)`"."

        if ($null -ne $invalidWKObjectTargetException) {
            $invalidWKObjectTargetException.Line | New-ErrorContext
            New-ActionPlan @(
                "- Change the $($invalidWKObjectTargetException.Matches.Groups[3].Value) object to $($invalidWKObjectTargetException.Matches.Groups[4].Value)",
                "- Another problem can be that the group is set correctly, but is mail enabled and shouldn't be."
            )
            return
        }
        Write-Verbose "Didn't find invalidWKObjectTargetException"
    }
}
