Function Test-PrerequisiteInstalled {
    [CmdletBinding()]
    param()
    begin {
        $2012VersionFound = $false
        $2013VersionFound = $false
    }
    process {
        $netVersion = Get-NETFrameworkVersion

        if ($netVersion.MinimumValue -lt 528040) {
            "Download .NET 4.8 and install: https://dotnet.microsoft.com/download/dotnet-framework/net48" | Receive-Output
        }

        $vcRedistributable = Get-VisualCRedistributableVersion

        foreach ($detectedVc in $vcRedistributable) {

            if ($detectedVc.VersionIdentifier -eq 201347597) {
                $2013VersionFound = $true
            } elseif ($detectedVc.VersionIdentifier -eq 184600103) {
                $2012VersionFound = $true
            }
        }

        if (-not $2012VersionFound) {
            "Download Visual C++ 2012 Redistributable Package and install: https://www.microsoft.com/en-us/download/details.aspx?id=30679" | Receive-Output
        }

        if (-not $2013VersionFound) {
            "Download Visual C++ 2013 Redistributable Package and install: https://support.microsoft.com/en-us/topic/update-for-visual-c-2013-redistributable-package-d8ccd6a5-4e26-c290-517b-8da6cfdf4f10" | Receive-Output
        }
    }
}
