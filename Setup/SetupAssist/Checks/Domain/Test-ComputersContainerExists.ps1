# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1

Function Test-ComputersContainerExists {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        $domainDN = $domain.GetDirectoryEntry().distinguishedName
        $computersPath = ("LDAP://CN=Computers," + $domainDN)
        $params = @{
            TestName   = "Computers Container Exists"
            CustomData = $domainDN
        }

        if (-not [System.DirectoryServices.DirectoryEntry]::Exists($computersPath)) {
            New-TestResult @params -Result "Failed" -AdditionalContext "A Failed result indicates /PrepareAD will fail in some scenarios. Please see https://support.microsoft.com/help/5005319 for details."
        } else {
            New-TestResult @params -Result "Passed"
        }
    }
}
