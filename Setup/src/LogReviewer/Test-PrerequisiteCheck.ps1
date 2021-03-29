Function Test-PrerequisiteCheck {
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
        $returnNow = $false
    }

    process {
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")
        $adValidationError = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR\] Setup encountered a problem while validating the state of Active Directory: (.*) See the Exchange setup log for more information on this error.")

        if ($adValidationError) {
            $writeWarning = "Setup failed to validate AD environment level. This is the internal exception that occurred:"
            $displayContext.Add($SetupLogReviewer.GetWriteObject($adValidationError.Matches.Groups[1].Value, "Yellow"))
            $returnNow = $true
        }
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")

        if (($SetupLogReviewer.TestEvaluatedSettingOrRule("PendingRebootWindowsComponents", "Rule")) -eq "True") {
            $displayContext.Add($SetupLogReviewer.GetWriteObject("Computer is pending reboot based off the Windows Component is the registry", "Red"))
            $returnNow = $true
        }
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")

        if (($SetupLogReviewer.TestEvaluatedSettingOrRule("RebootPending", "Rule")) -eq "True") {
            $displayContext.Add($SetupLogReviewer.GetWriteObject("Computer is pending reboot based off the Session Manager is the registry", "Red"))
            $returnNow = $true
        }
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")

        if (($SetupLogReviewer.TestEvaluatedSettingOrRule("ProcessNeedsToBeClosedOnUpgrade", "Rule")) -eq "True") {
            $displayContext.Add($SetupLogReviewer.GetWriteObject("Additional PowerShell Sessions are open. Close them before running setup again.", "Red"))
            $returnNow = $true
        }

        if ($returnNow) { return }

        $schemaUpdateRequired = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("Schema Update Required Status : '(\w+)'.")
        $orgConfigUpdateRequired = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("Organization Configuration Update Required Status : '(\w+)'.")
        $domainConfigUpdateRequired = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("Domain Configuration Update Required Status : '(\w+)'.")
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")

        if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer.TestEvaluatedSettingOrRule("SchemaAdmin")) -eq "False") {
            $displayContext.Add($SetupLogReviewer.GetWriteObject("/PrepareSchema is required and user $($SetupLogReviewer.User) isn't apart of the Schema Admins group.", "Red"))
            return
        }
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")

        if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer.TestEvaluatedSettingOrRule("EnterpriseAdmin")) -eq "False") {
            $displayContext.Add($SetupLogReviewer.GetWriteObject("/PrepareSchema is required and user $($SetupLogReviewer.User) isn't apart of the Enterprise Admins group.", "Red"))
        }
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")

        if ($orgConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer.TestEvaluatedSettingOrRule("EnterpriseAdmin")) -eq "False") {
            $displayContext.Add($SetupLogReviewer.GetWriteObject("/PrepareAD is required and user $($SetupLogReviewer.User) isn't apart of the Enterprise Admins group.", "Red"))
            return
        }
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")

        if ($domainConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer.TestEvaluatedSettingOrRule("EnterpriseAdmin")) -eq "False") {
            $displayContext.Add($SetupLogReviewer.GetWriteObject("/PrepareDomain needs to be run in this domain, but we actually require Enterprise Admin group to properly run this command.", "Red"))
            return
        }
        $diagnosticContext.Add("PrerequisiteCheck $($breadCrumb; $breadCrumb++)")

        if (($SetupLogReviewer.TestEvaluatedSettingOrRule("ExOrgAdmin")) -eq "False") {
            $sid = $SetupLogReviewer.GetEvaluatedSettingOrRule("SidExOrgAdmins", "Setting", ".")
            $diagnosticContext.Add("PrerequisiteCheck - Didn't find ExOrgAdmin")

            if ($null -ne $sid) {
                $displayContext.Add($SetupLogReviewer.GetWriteObject("User $($SetupLogReviewer.User) isn't apart of Organization Management group.", "Red"))
                $displayContext.Add($SetupLogReviewer.GetWriteObject("Looking to be in this group SID: $($sid.Matches.Groups[1].Value)"))
                return
            } else {
                $diagnosticContext.Add("PrerequisiteCheck - didn't find SID of ExOrgAdmin")
                $displayContext.Add($SetupLogReviewer.GetWriteObject("Didn't find the user to be in ExOrgAdmin, but didn't find the SID for the group either. Suspect /PrepareAD hasn't been run yet.", "Yellow"))
            }
        }

        $diagnosticContext.Add("PrerequisiteCheck - no known issue")
        $foundKnownIssue = $false
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
