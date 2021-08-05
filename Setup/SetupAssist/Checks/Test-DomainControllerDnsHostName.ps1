# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-DomainControllerDnsHostName {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    foreach ($domain in $forest.Domains) {
        foreach ($dc in $domain.DomainControllers) {
            $firstDotIndex = $dc.Name.IndexOf(".")
            if ($firstDotIndex -lt 0) {
                "Domain Controller $($dc.Name) does not have an FQDN in dnsHostName. This may cause setup to fail." | Receive-Output -IsWarning
            }
        }
    }
}
