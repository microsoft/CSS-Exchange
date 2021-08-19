# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
function Test-DomainControllerDnsHostName {
    [CmdletBinding()]
    param()
    begin {
        $result = "Passed"
        $context = [string]::Empty
        $dcsFailed = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

        foreach ($domain in $forest.Domains) {
            foreach ($dc in $domain.DomainControllers) {
                $firstDotIndex = $dc.Name.IndexOf(".")

                if ($firstDotIndex -lt 0) {
                    $result = "Failed"
                    $dcsFailed.Add($dc)
                }
            }
        }
    }
    end {
        $params = @{
            TestName          = "DC DNS Host Name"
            Result            = $result
            AdditionalContext = $context
            CustomData        = $dcsFailed
        }

        return (New-TestResult @params)
    }
}
