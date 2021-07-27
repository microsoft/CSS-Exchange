# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-ReadOnlyDomainControllerLocation {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        foreach ($dc in $domain.DomainControllers) {
            $cn = $dc.Name.Substring(0, $dc.Name.IndexOf("."))
            $filter = "(&(objectClass=computer)(cn=$cn))"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = $filter
            foreach ($result in $searcher.FindAll()) {
                if ($result.Properties["primaryGroupID"][0] -eq 521) {
                    $dn = $result.Properties["distinguishedName"][0].ToString()
                    if (-not $dn.StartsWith("CN=$cn,OU=Domain Controllers,DC=")) {
                        ("Domain Controller $cn appears to be in a container other than Domain Controllers. " +
                            "This will cause /PrepareAd to fail in some scenarios. Please see https://support.microsoft.com/help/5005319 for details.") | Receive-Output -IsWarning
                    }
                }
            }
        }
    }
}
