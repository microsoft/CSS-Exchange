# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1

function Test-ComputersContainerExists {
    try {
        $forest = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest
        foreach ($domain in $forest.Domains) {
            try {
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
            } catch {
                Write-Warning "Failed to Test Computers Container Exists - DomainDN: $domainDN"
            }
        }
    } catch {
        Write-Warning "Failed to run Test-ComputersContainerExists"
    }
}
