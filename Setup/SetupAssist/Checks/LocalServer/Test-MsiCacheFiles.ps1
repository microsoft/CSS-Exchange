# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Get-InstallerPackages.ps1
. $PSScriptRoot\..\New-TestResult.ps1
function Test-MsiCacheFiles {
    [CmdletBinding()]
    param()
    begin {
        $result = "Passed"
        $context = [string]::Empty
        $msiFiles = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        $packagesMissing = @(Get-InstallerPackages -FilterDisplayName @(
                "Microsoft Lync Server",
                "Exchange",
                "Microsoft Server Speech",
                "Microsoft Unified Communications") |
                Where-Object { $_.ValidMsi -eq $false })

        if ($packagesMissing.Count -gt 0) {
            $result = "Failed"
            #TODO ADD context and object information
        }
    }
    end {
        $params = @{
            TestName          = "Msi Cache Files"
            Result            = $result
            AdditionalContext = $context
            CustomData        = $msiFiles
        }

        return (New-TestResult @params)
    }
}
