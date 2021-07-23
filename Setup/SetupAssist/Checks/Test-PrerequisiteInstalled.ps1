# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-PrerequisiteInstalled {
    [CmdletBinding()]
    param()

    process {
        $netVersion = Get-NETFrameworkVersion

        if ($netVersion.MinimumValue -lt 528040) {
            "Download .NET 4.8 and install: https://dotnet.microsoft.com/download/dotnet-framework/net48" | Receive-Output
        }

        $vcRedistributable = Get-VisualCRedistributableVersion

        if (-not ((Get-VcRedistributableVersionStatus -VisualCRedistributableVersion $vcRedistributable `
                        -VersionInformation (Get-VisualCRedistributable2012Information)) -band 2)) {
            "Download Visual C++ 2012 Redistributable Package and install: $((Get-VisualCRedistributable2012Information).DownloadUrl)" | Receive-Output
        }

        if (-not ((Get-VcRedistributableVersionStatus -VisualCRedistributableVersion $vcRedistributable `
                        -VersionInformation (Get-VisualCRedistributable2013Information)) -band 2)) {
            "Download Visual C++ 2013 Redistributable Package and install: $((Get-VisualCRedistributable2013Information).DownloadUrl)" | Receive-Output
        }
    }
}
