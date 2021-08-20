# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Get-InstallerPackages.ps1
. $PSScriptRoot\..\New-TestResult.ps1
function Test-MsiCacheFiles {
    $msiFiles = @(Get-InstallerPackages -FilterDisplayName @(
            "Microsoft Lync Server",
            "Exchange",
            "Microsoft Server Speech",
            "Microsoft Unified Communications"))

    foreach ($msi in $msiFiles) {
        $params = @{
            TestName = "Msi Cache File"
            Details  = "$($msi.DisplayName)"
        }

        if ($msi.ValidMsi) {
            New-TestResult @params -Result "Passed"
        } else {
            New-TestResult @params -Result "Failed"
        }
    }
}
