Function Test-PrerequisiteCheck {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )

    process {

        if (($SetupLogReviewer.TestEvaluatedSettingOrRule("PendingRebootWindowsComponents", "Rule")) -eq "True") {
            $SetupLogReviewer.ReceiveOutput("Computer is pending reboot based off the Windows Component is the registry", "Red")
            return $true
        }

        $adValidationError = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("\[ERROR\] Setup encountered a problem while validating the state of Active Directory: (.*) See the Exchange setup log for more information on this error.")

        if ($adValidationError) {
            Write-Warning "Setup failed to validate AD environment level. This is the internal exception that occurred:"
            $SetupLogReviewer.ReceiveOutput($adValidationError.Matches.Groups[1].Value, "Yellow")
            return $true
        }

        $schemaUpdateRequired = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("Schema Update Required Status : '(\w+)'.")
        $orgConfigUpdateRequired = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("Organization Configuration Update Required Status : '(\w+)'.")
        $domainConfigUpdateRequired = $SetupLogReviewer.SelectStringLastRunOfExchangeSetup("Domain Configuration Update Required Status : '(\w+)'.")

        if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer.TestEvaluatedSettingOrRule("SchemaAdmin")) -eq "False") {
            $SetupLogReviewer.ReceiveOutput("/PrepareSchema is required and user $($SetupLogReviewer.User) isn't apart of the Schema Admins group.", "Red")
            return $true
        }

        if ($schemaUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer.TestEvaluatedSettingOrRule("EnterpriseAdmin")) -eq "False") {
            $SetupLogReviewer.ReceiveOutput("/PrepareSchema is required and user $($SetupLogReviewer.User) isn't apart of the Enterprise Admins group.", "Red")
            return $true
        }

        if ($orgConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer.TestEvaluatedSettingOrRule("EnterpriseAdmin")) -eq "False") {
            $SetupLogReviewer.ReceiveOutput("/PrepareAD is required and user $($SetupLogReviewer.User) isn't apart of the Enterprise Admins group.", "Red")
            return $true
        }

        if ($domainConfigUpdateRequired.Matches.Groups[1].Value -eq "True" -and
            ($SetupLogReviewer.TestEvaluatedSettingOrRule("EnterpriseAdmin")) -eq "False") {
            $SetupLogReviewer.ReceiveOutput("/PrepareDomain needs to be run in this domain, but we actually require Enterprise Admin group to properly run this command.", "Red")
            return $true
        }

        if (($SetupLogReviewer.TestEvaluatedSettingOrRule("ExOrgAdmin")) -eq "False") {
            $sid = $SetupLogReviewer.GetEvaluatedSettingOrRule("SidExOrgAdmins", "Setting", ".")
            if ($null -ne $sid) {
                $SetupLogReviewer.ReceiveOutput("User $($SetupLogReviewer.User) isn't apart of Organization Management group.", "Red")
                $SetupLogReviewer.ReceiveOutput("Looking to be in this group SID: $($sid.Matches.Groups[1].Value)")
                return $true
            } else {
                $SetupLogReviewer.ReceiveOutput("Didn't find the user to be in ExOrgAdmin, but didn't find the SID for the group either. Suspect /PrepareAD hasn't been run yet.", "Yellow")
            }
        }
        return $false
    }
}