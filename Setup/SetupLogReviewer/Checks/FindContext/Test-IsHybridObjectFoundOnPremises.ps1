# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
. $PSScriptRoot\..\New-ErrorContext.ps1
. $PSScriptRoot\..\New-WriteObject.ps1
Function Test-IsHybridObjectFoundOnPremises {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        if (($SetupLogReviewer | TestEvaluatedSettingOrRule "DidOnPremisesSettingCreatedAnException" "Rule") -eq "True") {
            $isHybridObjectFoundOnPremises = Get-ChildItem $SetupLogReviewer.SetupLog |
                Select-String "Evaluated \[Setting:IsHybridObjectFoundOnPremises\]" -Context 20, 20 |
                Select-Object -Last 1

            Write-Verbose "Found DidOnPremisesSettingCreatedAnException Rule set to true"

            if ($null -eq $isHybridObjectFoundOnPremises -or
                (-not ($isHybridObjectFoundOnPremises.LineNumber -gt $SetupLogReviewer.LastSetupRunLine))) {
                New-WriteObject "Ran into a logical error. Failed to find the IsHybridObjectFoundOnPremises context in the last run of the setup" -WriteType "Error"
                return
            }

            $contextOfError = @()

            foreach ($line in $isHybridObjectFoundOnPremises.Context.PreContext) {
                $contextOfError += $line
            }

            foreach ($line in $isHybridObjectFoundOnPremises.Context.PostContext) {
                $contextOfError += $line
            }

            $contextOfError | New-ErrorContext
            Write-Verbose "Searching for TargetApplicationUri"
            $targetApplicationUri = $contextOfError | Select-String `
                "Searching for (.+) as the TargetApplicationUri"

            if ($null -eq $targetApplicationUri -or
                $targetApplicationUri.Count -gt 1) {
                New-WriteObject "Ran into a logical error. Failed to find targetApplicationUri context" -WriteType "Error"
                return
            }

            New-ActionPlan @(
                "One of the Organization Relationship objects has a null value to the ApplicationURI attribute.",
                "Please add `"$($targetApplicationUri.Matches.Groups[1].Value)`" to it"
            )
        }
    }
}
