Function Test-OtherKnownIssues {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )

    process {
        if (($SetupLogReviewer.TestEvaluatedSettingOrRule("DidOnPremisesSettingCreatedAnException", "Rule")) -eq "True") {
            $isHybridObjectFoundOnPremises = Get-ChildItem $SetupLogReviewer.SetupLog |
                Select-String "Evaluated \[Setting:IsHybridObjectFoundOnPremises\]" -Context 20, 20 |
                Select-Object -Last 1

            if ($null -eq $isHybridObjectFoundOnPremises -or
                !($SetupLogReviewer.IsInLastRunOfExchangeSetup($isHybridObjectFoundOnPremises))) {
                $SetupLogReviewer.WriteLogicError()
                return $true
            }

            $errorContext = @()

            foreach ($line in $isHybridObjectFoundOnPremises.Context.PreContext) {
                $errorContext += $line
            }

            foreach ($line in $isHybridObjectFoundOnPremises.Context.PostContext) {
                $errorContext += $line
            }

            $targetApplicationUri = $errorContext | Select-String `
                "Searching for (.+) as the TargetApplicationUri"

            if ($null -eq $targetApplicationUri -or
                $targetApplicationUri.Count -gt 1) {
                $SetupLogReviewer.WriteLogicError()
                return $true
            }

            $SetupLogReviewer.WriteErrorContext($errorContext)
            $SetupLogReviewer.WriteActionPlan("One of the Organization Relationship objects has a null value to the ApplicationURI attribute. `r`n`tPlease add `"$($targetApplicationUri.Matches.Groups[1].Value)`" to it")
            return $true
        }

        return $false
    }
}
