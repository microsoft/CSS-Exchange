# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-ExchangeBuildVersionInformation {
    [CmdletBinding()]
    param(
        [object]$AdminDisplayVersion
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed $($AdminDisplayVersion.ToString())"
        $AdminDisplayVersion = $AdminDisplayVersion.ToString()
        $exchangeMajorVersion = [string]::Empty
        [int]$major = 0
        [int]$minor = 0
        [int]$build = 0
        [int]$revision = 0
        $product = $null
        [double]$buildVersion = 0.0
    }
    process {
        $split = $AdminDisplayVersion.Substring(($AdminDisplayVersion.IndexOf(" ")) + 1, 4).Split(".")
        $major = [int]$split[0]
        $minor = [int]$split[1]
        $product = $major + ($minor / 10)

        $buildStart = $AdminDisplayVersion.LastIndexOf(" ") + 1
        $split = $AdminDisplayVersion.Substring($buildStart, ($AdminDisplayVersion.LastIndexOf(")") - $buildStart)).Split(".")
        $build = [int]$split[0]
        $revision = [int]$split[1]
        $revisionDecimal = if ($revision -lt 10) { $revision / 10 } else { $revision / 100 }
        $buildVersion = $build + $revisionDecimal

        Write-Verbose "Determining Major Version based off of $product"

        switch ([string]$product) {
            "14.3" { $exchangeMajorVersion = "Exchange2010" }
            "15" { $exchangeMajorVersion = "Exchange2013" }
            "15.1" { $exchangeMajorVersion = "Exchange2016" }
            "15.2" { $exchangeMajorVersion = "Exchange2019" }
            default { $exchangeMajorVersion = "Unknown" }
        }
    }
    end {
        Write-Verbose "Found Major Version '$exchangeMajorVersion'"
        return [PSCustomObject]@{
            MajorVersion = $exchangeMajorVersion
            Major        = $major
            Minor        = $minor
            Build        = $build
            Revision     = $revision
            Product      = $product
            BuildVersion = $buildVersion
        }
    }
}
