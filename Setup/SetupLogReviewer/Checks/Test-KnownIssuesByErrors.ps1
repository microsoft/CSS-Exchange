Function Test-KnownIssuesByErrors {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    begin {
        $diagnosticContext = New-Object 'System.Collections.Generic.List[string]'
        $displayContext = New-Object 'System.Collections.Generic.List[PSCustomObject]'
        $foundKnownIssue = $true
        $actionPlan = New-Object 'System.Collections.Generic.List[string]'
        $errorContext = New-Object 'System.Collections.Generic.List[string]'
        $writeErrorContext = New-Object 'System.Collections.Generic.List[string]'
        $writeWarning = [string]::Empty
        $breadCrumb = 0
    }
    process {
        $diagnosticContext.Add("KnownIssuesByErrors $($breadCrumb; $breadCrumb++)")

        if (($SetupLogReviewer.TestEvaluatedSettingOrRule("DidOnPremisesSettingCreatedAnException", "Rule")) -eq "True") {
            $isHybridObjectFoundOnPremises = Get-ChildItem $SetupLogReviewer.SetupLog |
                Select-String "Evaluated \[Setting:IsHybridObjectFoundOnPremises\]" -Context 20, 20 |
                Select-Object -Last 1

            $diagnosticContext.Add("Found DidOnPremisesSettingCreatedAnException Rule set to true")

            if ($null -eq $isHybridObjectFoundOnPremises -or
                !($SetupLogReviewer.IsInLastRunOfExchangeSetup($isHybridObjectFoundOnPremises))) {
                $diagnosticContext.Add("Ran into a logical error. Failed to find the IsHybridObjectFoundOnPremises context in the last run of the setup")
                $SetupLogReviewer.WriteLogicError()
                return
            }

            $contextOfError = @()

            foreach ($line in $isHybridObjectFoundOnPremises.Context.PreContext) {
                $contextOfError += $line
            }

            foreach ($line in $isHybridObjectFoundOnPremises.Context.PostContext) {
                $contextOfError += $line
            }

            $writeErrorContext.AddRange($contextOfError)
            $diagnosticContext.Add("Searching for TargetApplicationUri")
            $targetApplicationUri = $contextOfError | Select-String `
                "Searching for (.+) as the TargetApplicationUri"

            if ($null -eq $targetApplicationUri -or
                $targetApplicationUri.Count -gt 1) {
                $diagnosticContext.Add("Ran into a logical error. Failed to find targetApplicationUri context")
                $SetupLogReviewer.WriteLogicError()
                return
            }

            $actionPlan.Add("One of the Organization Relationship objects has a null value to the ApplicationURI attribute.")
            $actionPlan.Add("Please add `"$($targetApplicationUri.Matches.Groups[1].Value)`" to it")
            return
        }

        $certificateOutdated = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR\] The certificate is expired.")
        $diagnosticContext.Add("KnownIssuesByErrors $($breadCrumb; $breadCrumb++)")

        if ($null -ne $certificateOutdated) {
            $diagnosticContext.Add("Found Error regarding certificate is expired.")
            $outdatedCertificateInfo = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("Installing certificate signed by '(.*)' for site '(.*)'.  Certificate is valid from (\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}:\d{2} \w\w) until (\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}:\d{2} \w\w)")
            $actionPlan.Add("Certificate: $($outdatedCertificateInfo.Matches.Groups[2].Value) has expired.")

            if ($null -ne $outdatedCertificateInfo.Matches.Groups[4].Value) {
                $actionPlan.Add("Certificate expired on: $($outdatedCertificateInfo.Matches.Groups[4].Value).")
            }

            $actionPlan.Add("Please replace it, reboot the server and run setup again.")
            return
        }
        $diagnosticContext.Add("KnownIssuesByErrors $($breadCrumb; $breadCrumb++)")
        $errorReference = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR-REFERENCE\] Id=(.+) Component=")

        if ($null -eq $errorReference) {
            $foundKnownIssue = $false
            $diagnosticContext.Add("KnownIssuesByErrors - no known issue - No Error Reference")
            return
        }
        $diagnosticContext.Add("KnownIssuesByErrors $($breadCrumb; $breadCrumb++)")
        $contextOfError = $SetupLogReviewer.FirstErrorWithContextToLine($errorReference.LineNumber)

        if ($null -ne $contextOfError) {
            $diagnosticContext.Add("Found context around error reference")
            $serviceNotStarted = $contextOfError | Select-String "System.ComponentModel.Win32Exception: The service cannot be started, either because it is disabled or because it has no enabled devices associated with it"

            if ($null -ne $serviceNotStarted) {
                $diagnosticContext.Add("Found Service isn't starting")
                $contextOfError | ForEach-Object { $writeErrorContext.Add($_) }
                $actionPlan.Add("Required Exchange Services are failing to start because it appears to be disabled or dependent services are disabled. Enable them and try again")
                #TODO: Improve Action plan
                $actionPlan.Add("NOTE: Might need to do this often while setup is running")
                $actionPlan.Add("Example Command: Get-Service MSExchange* | Set-Service -StartupType Automatic")
                return
            }
        }

        $foundKnownIssue = $false
        $diagnosticContext.Add("KnownIssuesByErrors - no known issue")
        return
    }
    end {
        return [PSCustomObject]@{
            DiagnosticContext = $diagnosticContext
            DisplayContext    = $displayContext
            FoundKnownIssue   = $foundKnownIssue
            ActionPlan        = $actionPlan
            ErrorContext      = $errorContext
            WriteErrorContext = $writeErrorContext
            WriteWarning      = $writeWarning
        }
    }
}
