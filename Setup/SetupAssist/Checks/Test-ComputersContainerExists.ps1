# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-ComputersContainerExists {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        $domainDN = $domain.GetDirectoryEntry().distinguishedName
        $computersPath = ("LDAP://CN=Computers," + $domainDN)
        if (-not [System.DirectoryServices.DirectoryEntry]::Exists($computersPath)) {
            "The Computers container in domain $domainDN has been renamed or deleted. This will cause /PrepareAd to fail in some scenarios." | Receive-Output -IsWarning
        }
    }
}
