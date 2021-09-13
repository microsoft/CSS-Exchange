# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\New-ActionPlan.ps1
. $PSScriptRoot\New-ErrorContext.ps1
. $PSScriptRoot\New-WriteObject.ps1
Function Test-KnownIssuesByErrors {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
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
            return
        }

        $certificateOutdated = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "\[ERROR\] The certificate is expired."

        if ($null -ne $certificateOutdated) {
            Write-Verbose "Found Error regarding certificate is expired."
            $outdatedCertificateInfo = $SetupLogReviewer |
                SelectStringLastRunOfExchangeSetup "Installing certificate signed by '(.*)' for site '(.*)'.  Certificate is valid from (\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}:\d{2} \w\w) until (\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}:\d{2} \w\w)"

            $actionPlan = @()
            $actionPlan += "Certificate: $($outdatedCertificateInfo.Matches.Groups[2].Value) has expired."

            if ($null -ne $outdatedCertificateInfo.Matches.Groups[4].Value) {
                $actionPlan += "Certificate expired on: $($outdatedCertificateInfo.Matches.Groups[4].Value)."
            }

            $actionPlan += "Please replace it, reboot the server and run setup again."
            New-ActionPlan $actionPlan
            return
        }
        $errorReference = $SetupLogReviewer | SelectStringLastRunOfExchangeSetup "\[ERROR-REFERENCE\] Id=(.+) Component="

        if ($null -eq $errorReference) {
            Write-Verbose "KnownIssuesByErrors - no known issue - No Error Reference"
            return
        }

        $contextOfError = $SetupLogReviewer | GetFirstErrorWithContextToLine $errorReference.LineNumber

        if ($null -ne $contextOfError) {
            Write-Verbose "Found context around error reference"
            $serviceNotStarted = $contextOfError | Select-String "System.ComponentModel.Win32Exception: The service cannot be started, either because it is disabled or because it has no enabled devices associated with it"

            if ($null -ne $serviceNotStarted) {
                Write-Verbose "Found Service isn't starting"
                $contextOfError | New-ErrorContext
                New-ActionPlan @(
                    "Required Exchange Services are failing to start because it appears to be disabled or dependent services are disabled. Enable them and try again",
                    "NOTE: Might need to do this often while setup is running",
                    "Example Command: Get-Service MSExchange* | Set-Service -StartupType Automatic"
                )
                return
            }
        }
    }
}
