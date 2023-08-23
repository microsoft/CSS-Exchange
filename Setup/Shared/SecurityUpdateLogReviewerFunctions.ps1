# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SecurityUpdateLogReviewer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SecurityUpdateLog
    )
    begin {
        # GUID for Exchange 2016 and 2019 MSI
        $msiGuid = "CD981244-E9B8-405A-9026-6AEB9DCEF1F1"
        $installRunDate = [System.DateTime]::MinValue
        $patchVersions = @{}
    }
    process {

        if ($null -eq (Select-String $msiGuid $SecurityUpdateLog)) {
            throw "Failed to provide valid Security Update Log"
        }

        $matchInstallRunTime = Select-String "Verbose logging started: (.+) Build Type" $SecurityUpdateLog

        if ($null -ne $matchInstallRunTime) {
            $installRunDate = [System.Convert]::ToDateTime($matchInstallRunTime.Matches.Groups[1].Value, [System.Globalization.DateTimeFormatInfo]::InvariantInfo)
        }

        # find all the related patch GUIDs
        $matchAllPatchGuid = Select-String "PatchGUID: \{(.+)\}.+ResultantVersion: (\d+\.\d+\.\d+\.\d+)\s.+Sequence: (\d+\.\d+\.\d+\.\d+)\s.+SequenceOrder: (\d+)" $SecurityUpdateLog

        foreach ($patch in $matchAllPatchGuid) {
            $guid = $patch.Matches.Groups[1].Value

            if (-not ($patchVersions.ContainsKey($guid))) {
                $patchVersions.Add($guid, ([PSCustomObject]@{
                            MsiGuid          = $guid
                            CuBuildNumber    = $patch.Matches.Groups[2].Value
                            PatchBuildNumber = $patch.Matches.Groups[3].Value
                            Order            = $patch.Matches.Groups[4].Value
                        }))
            }
        }
    }
    end {
        [PSCustomObject]@{
            SecurityUpdateLog = $SecurityUpdateLog
            InstallRunDate    = $installRunDate
            InstallPatches    = $patchVersions
        }
    }
}
