Function Test-KnownIssuesByErrors {
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

        $certificateOutdated = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR\] The certificate is expired.")

        if ($null -ne $certificateOutdated) {
            $outdatedCertificateInfo = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("Installing certificate signed by '(.*)' for site '(.*)'.  Certificate is valid from (\d{1,2}\/\d{1,2}\/\d{4} \d{2}:\d{2}:\d{2} \w\w) until (\d{1,2}\/\d{1,2}\/\d{4} \d{2}:\d{2}:\d{2} \w\w)")

            if ($null -ne $outdatedCertificateInfo.Matches.Groups[4].Value) {
                $SetupLogReviewer.WriteActionPlan("Certificate: $($outdatedCertificateInfo.Matches.Groups[2].Value) expired on: $($outdatedCertificateInfo.Matches.Groups[4].Value). `r`n`tPlease replace it, reboot the server and run setup again.")
            } else {
                $SetupLogReviewer.WriteActionPlan("Certificate: $($outdatedCertificateInfo.Matches.Groups[2].Value) has expired. `r`n`tPlease replace it, reboot the server and run setup again.")
            }
            return $true
        }
        return $false
    }
}
