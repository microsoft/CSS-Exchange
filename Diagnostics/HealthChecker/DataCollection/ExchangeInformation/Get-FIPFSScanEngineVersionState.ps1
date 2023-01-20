# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

function Get-FIPFSScanEngineVersionState {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        [System.Version]
        $ExSetupVersion,
        [Parameter(Mandatory = $true)]
        [bool]
        $AffectedServerRole
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        function GetFolderFromExchangeInstallPath {
            param(
                [Parameter(Mandatory = $true)]
                [string]
                $ExchangeSubDir
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            try {
                $exSetupPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction Stop).MsiInstallPath
            } catch {
                # since this is a script block, can't call Invoke-CatchActions
                $exSetupPath = $env:ExchangeInstallPath
            }

            $finalPath = Join-Path $exSetupPath $ExchangeSubDir

            if ($ExchangeSubDir -notmatch '\.[a-zA-Z0-9]+$') {

                if (Test-Path $finalPath) {
                    $getDir = Get-ChildItem -Path $finalPath -Attributes Directory
                }

                return ([PSCustomObject]@{
                        Name             = $getDir.Name
                        LastWriteTimeUtc = $getDir.LastWriteTimeUtc
                        Failed           = $null -eq $getDir
                    })
            }
            return $null
        }

        function GetHighestScanEngineVersionNumber {
            param (
                [string]
                $ComputerName
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            try {
                $scanEngineVersions = Invoke-ScriptBlockHandler -ComputerName $ComputerName `
                    -ScriptBlock ${Function:GetFolderFromExchangeInstallPath} `
                    -ArgumentList ("FIP-FS\Data\Engines\amd64\Microsoft\Bin") `
                    -CatchActionFunction ${Function:Invoke-CatchActions}

                if ($null -ne $scanEngineVersions) {
                    if ($scanEngineVersions.Failed) {
                        Write-Verbose "Failed to find the scan engine directory"
                    } else {
                        return [Int64]($scanEngineVersions.Name | Measure-Object -Maximum).Maximum
                    }
                } else {
                    Write-Verbose "No FIP-FS scan engine version(s) detected - GetFolderFromExchangeInstallPath returned null"
                }
            } catch {
                Write-Verbose "Error occurred while processing FIP-FS scan engine version(s)"
                Invoke-CatchActions
            }
            return $null
        }

        function IsFIPFSFixedBuild {
            param (
                [System.Version]
                $BuildNumber
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            $fixedFIPFSBuild = $false

            # Fixed on Exchange side with March 2022 Security update
            if ($BuildNumber.Major -eq 15) {
                if ($BuildNumber.Minor -eq 2) {
                    $fixedFIPFSBuild = ($BuildNumber.Build -gt 986) -or
                        (($BuildNumber.Build -eq 986) -and ($BuildNumber.Revision -ge 22)) -or
                        (($BuildNumber.Build -eq 922) -and ($BuildNumber.Revision -ge 27))
                } elseif ($BuildNumber.Minor -eq 1) {
                    $fixedFIPFSBuild = ($BuildNumber.Build -gt 2375) -or
                        (($BuildNumber.Build -eq 2375) -and ($BuildNumber.Revision -ge 24)) -or
                        (($BuildNumber.Build -eq 2308) -and ($BuildNumber.Revision -ge 27))
                } else {
                    Write-Verbose "Looks like we're on Exchange 2013 which is not affected by this FIP-FS issue"
                    $fixedFIPFSBuild = $true
                }
            } else {
                Write-Verbose "We are not on Exchange version 15"
                $fixedFIPFSBuild = $true
            }

            return $fixedFIPFSBuild
        }
    } process {
        $isAffectedByFIPFSUpdateIssue = $false
        try {

            if ($AffectedServerRole) {
                $highestScanEngineVersionNumber = GetHighestScanEngineVersionNumber -ComputerName $ComputerName
                $fipFsIssueFixedBuild = IsFIPFSFixedBuild -BuildNumber $ExSetupVersion

                if ($null -eq $highestScanEngineVersionNumber) {
                    Write-Verbose "No scan engine version found on the computer - this can cause issues still with some transport rules"
                } elseif ($highestScanEngineVersionNumber -ge 2201010000) {
                    if ($fipFsIssueFixedBuild) {
                        Write-Verbose "Scan engine: $highestScanEngineVersionNumber detected but Exchange runs a fixed build that doesn't crash"
                    } else {
                        Write-Verbose "Scan engine: $highestScanEngineVersionNumber will cause transport queue or pattern update issues"
                    }
                    $isAffectedByFIPFSUpdateIssue = $true
                } else {
                    Write-Verbose "Scan engine: $highestScanEngineVersionNumber is safe to use"
                }
            }
        } catch {
            Write-Verbose "Failed to check for the FIP-FS update issue"
            Invoke-CatchActions
            return $null
        }
    } end {
        return [PSCustomObject]@{
            FIPFSFixedBuild              = $fipFsIssueFixedBuild
            ServerRoleAffected           = $AffectedServerRole
            HighestVersionNumberDetected = $highestScanEngineVersionNumber
            BadVersionNumberDirDetected  = $isAffectedByFIPFSUpdateIssue
        }
    }
}
