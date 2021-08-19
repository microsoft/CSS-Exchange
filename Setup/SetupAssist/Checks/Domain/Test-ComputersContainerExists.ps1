# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-ComputersContainerExists {
    [CmdletBinding()]
    param(
        $DisableTest = $false
    )
    begin {
        $domainsFailed = New-Object 'System.Collections.Generic.List[object]'
        $context = [string]::Empty
        $result = "Passed"
        if ($DisableTest) {
            return
        }
    }
    process {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        foreach ($domain in $forest.Domains) {
            $domainDN = $domain.GetDirectoryEntry().distinguishedName
            $computersPath = ("LDAP://CN=Computers," + $domainDN)

            if (-not ([System.DirectoryServices.DirectoryEntry]::Exists($computersPath))) {
                $result = "Failed"
                $domainsFailed.Add($domainDN)
            }
        }
    }
    end {
        $params = @{
            TestName          = "Computers Container Exists"
            Result            = $result
            AdditionalContext = $context
            CustomData        = $domainsFailed
        }

        return (New-TestResult @params)
    }
}
