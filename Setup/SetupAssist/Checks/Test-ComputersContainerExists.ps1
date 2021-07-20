# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-ComputersContainerExists {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        $domainDN = $domain.GetDirectoryEntry().distinguishedName
        $computersPath = ("LDAP://CN=Computers," + $domainDN)
        if (-not [System.DirectoryServices.DirectoryEntry]::Exists($computersPath)) {
            ("The Computers container in domain $domainDN may have been renamed or deleted, or we do not have permissions to see it. " +
                "This will cause /PrepareAd to fail in some scenarios. Please see https://support.microsoft.com/help/5005319 for details.") | Receive-Output -IsWarning
        }
    }
}
