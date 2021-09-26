# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-ActionPlan.ps1
Function Test-ExpiredCertificate {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $SetupLogReviewer
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
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
        } else {
            Write-Verbose "No error regarding certificate is expired found."
        }
    }
}
