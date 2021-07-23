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

        $installed = Get-VisualCRedistributableInstalledVersion

        if (-not (Test-VisualCRedistributableUpToDate -Year 2012 -Installed $installed)) {
            "Download Visual C++ 2012 Redistributable Package and install: $((Get-VisualCRedistributableInfo 2012).DownloadUrl)" | Receive-Output
        }

        if (-not (Test-VisualCRedistributableUpToDate -Year 2013 -Installed $installed)) {
            "Download Visual C++ 2013 Redistributable Package and install: $((Get-VisualCRedistributableInfo 2013).DownloadUrl)" | Receive-Output
        }
    }
}
