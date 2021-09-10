# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1

Function Test-ComputersContainerExists {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        $domainDN = $domain.GetDirectoryEntry().distinguishedName
        $computersPath = ("LDAP://CN=Computers," + $domainDN)
        $params = @{
            TestName = "Computers Container Exists"
            Details  = $domainDN
        }

        if (-not [System.DirectoryServices.DirectoryEntry]::Exists($computersPath)) {
            New-TestResult @params -Result "Failed" -ReferenceInfo "https://aka.ms/SA-Computers"
        } else {
            New-TestResult @params -Result "Passed"
        }
    }
}

