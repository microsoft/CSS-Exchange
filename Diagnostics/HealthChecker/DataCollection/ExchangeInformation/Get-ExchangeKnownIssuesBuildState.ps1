# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-ExchangeKnownIssuesBuildState {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param(
        [Parameter(Mandatory = $true)]
        [System.Enum]
        $MajorVersion,
        [Parameter(Mandatory = $true)]
        [System.Double]
        $BuildAndRevision
    )
    begin {
        # Syntax for the var is:
        # first 3 chars of the month, year, SU or CU, IssueDescription
        # Example: $mar1999SUIssueDescription for SU or $mar1999CUIssueDescription for CU
        $mar1999SUIssueDescription = "https://support.microsoft.com/help/xxxxxxx"
        $isBuildWithKnownIssues = $true
        $issueDescription = $null
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed - ExchangeMajorVersion: $MajorVersion"
        Write-Verbose "Passed - Build and Revision: $BuildAndRevision"
    } process {
        if ($MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
            switch ("$BuildAndRevision") {
                1496.1 { $issueDescription = $mar1999SUIssueDescription }
                Default { $isBuildWithKnownIssues = $false }
            }
        } elseif ($MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) {
            switch ("$BuildAndRevision") {
                2307.1 { $issueDescription = $mar1999SUIssueDescription }
                2374.1 { $issueDescription = $mar1999SUIssueDescription }
                Default { $isBuildWithKnownIssues = $false }
            }
        } elseif ($MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {
            switch ("$BuildAndRevision") {
                921.1 { $issueDescription = $mar1999SUIssueDescription }
                985.2 { $issueDescription = $mar1999SUIssueDescription }
                Default { $isBuildWithKnownIssues = $false }
            }
        } else {
            Write-Verbose "ExchangeMajorVersion: $MajorVersion is unknown"
            $isBuildWithKnownIssues = $false
        }

        if ($isBuildWithKnownIssues) {
            Write-Verbose "Exchange Server build with known issues detected"
        }
    } end {
        return [PSCustomObject]@{
            BuildWithIssues = $isBuildWithKnownIssues
            IssueKB         = $issueDescription
        }
    }
}
