# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-ReadOnlyDomainControllerLocation {

    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

    foreach ($domain in $forest.Domains) {
        foreach ($dc in $domain.DomainControllers) {
            $firstDotIndex = $dc.Name.IndexOf(".")

            if ($firstDotIndex -ge 0) {
                $cn = $dc.Name.Substring(0, $firstDotIndex)
            } else {
                $cn = $dc.Name
            }

            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectClass=computer)(cn=$cn))"
            foreach ($searchResult in $searcher.FindAll()) {

                if ($searchResult.Properties["primaryGroupID"][0] -eq 521) {
                    $dn = $searchResult.Properties["distinguishedName"][0].ToString()

                    $params = @{
                        TestName      = "RODC In Computers Container"
                        Details       = $dn
                        ReferenceInfo = "https://aka.ms/SA-RODC"
                    }

                    if (-not $dn.StartsWith("CN=$cn,OU=Domain Controllers,DC=")) {
                        New-TestResult @params -Result "Failed"
                    } else {
                        New-TestResult @params -Result "Passed"
                    }
                }
            }
        }
    }
}
