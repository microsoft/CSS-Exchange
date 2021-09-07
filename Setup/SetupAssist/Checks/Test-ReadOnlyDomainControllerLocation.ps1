# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-ReadOnlyDomainControllerLocation {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        foreach ($dc in $domain.DomainControllers) {
            $firstDotIndex = $dc.Name.IndexOf(".")
            if ($firstDotIndex -ge 0) {
                $cn = $dc.Name.Substring(0, $dc.Name.IndexOf("."))
            } else {
                $cn = $dc.Name
            }
            $filter = "(&(objectClass=computer)(cn=$cn))"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = $filter
            foreach ($result in $searcher.FindAll()) {
                if ($result.Properties["primaryGroupID"][0] -eq 521) {
                    $dn = $result.Properties["distinguishedName"][0].ToString()
                    if (-not $dn.StartsWith("CN=$cn,OU=Domain Controllers,DC=")) {
                        ("Read Only Domain Controller $cn appears to be in a container other than Domain Controllers. " +
                        "This will cause setup to fail if we attempt to domain prep that domain. The path" +
                        "to the RODC must be CN=DCName,OU=Domain Controllers...") | Receive-Output -IsWarning
                    }
                }
            }
        }
    }
}

