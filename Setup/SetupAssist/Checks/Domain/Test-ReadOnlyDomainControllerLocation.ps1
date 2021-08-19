# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-ReadOnlyDomainControllerLocation {
    [CmdletBinding()]
    param()
    begin {
        $result = "Passed"
        $context = [string]::Empty
        $dcList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
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

                        if (-not $dn.StartsWith("CN=$cn,OU=Domain Controllers,DC=")) {
                            $result = "Failed"
                            $dcList.Add($cn)
                        }
                    }
                }
            }
        }

        if ($dcList.Count -gt 0) {
            $context = "$($dcList.Count) RODCs not in the correct spot"
        }
    }
    end {
        $params = @{
            TestName          = "Read Only DC Location"
            Result            = $result
            AdditionalContext = $context
            CustomData        = $dcList
        }

        return (New-TestResult @params)
    }
}
