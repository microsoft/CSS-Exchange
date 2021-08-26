# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-DomainControllerDnsHostName {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        foreach ($dc in $domain.DomainControllers) {
            $firstDotIndex = $dc.Name.IndexOf(".")

            $params = @{
                TestName      = "DC DNS Host Name"
                Details       = $dc.Name
                ReferenceInfo = "Does not have an FQDN in dnsHostName. This may cause setup to fail."
            }

            if ($firstDotIndex -lt 0) {
                New-TestResult @params -Result "Failed"
            } else {
                New-TestResult @params -Result "Passed"
            }
        }
    }
}
