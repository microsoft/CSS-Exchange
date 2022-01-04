# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

Function Get-FIPFSScanEngineVersionState {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,
        [Parameter(Mandatory = $false)]
        [scriptblock]
        $CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        function GetItemFromExchangeInstallPath {
            param(
                [Parameter(Mandatory = $true)]
                [string]
                $ExchangeSubItem
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            try {
                $exSetupPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction Stop).MsiInstallPath
            } catch {
                $exSetupPath = $env:ExchangeInstallPath
            }

            $finalPath = Join-Path $exSetupPath $ExchangeSubItem

            if ($ExchangeSubItem -notmatch '\.[a-zA-Z0-9]+$') {
                $getDir = Get-ChildItem -Path $finalPath -Attributes Directory
                if ($null -ne $getDir) {
                    return ([PSCustomObject]@{
                            Name             = $getDir.Name
                            LastWriteTimeUtc = $getDir.LastWriteTimeUtc
                        })
                }
                return $null
            } else {
                $getItem = Get-Item -Path $finalPath

                return ([PSCustomObject]@{
                        GetItem          = $getItem
                        LastWriteTimeUtc = $getItem.LastWriteTimeUtc
                        VersionInfo      = ([PSCustomObject]@{
                                ProductVersion  = $getItem.VersionInfo.ProductVersion
                                FileMajorPart   = $getItem.VersionInfo.FileMajorPart
                                FileMinorPart   = $getItem.VersionInfo.FileMinorPart
                                FileBuildPart   = $getItem.VersionInfo.FileBuildPart
                                FilePrivatePart = $getItem.VersionInfo.FilePrivatePart
                            })
                    })
            }
        }
        function TestPipeline2Version {
            param (
                [string]$ComputerName,
                [scriptblock]$CatchActionFunction
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            $pipeline2FileInfo = Invoke-ScriptBlockHandler -ComputerName $ComputerName `
                -ScriptBlock ${Function:GetItemFromExchangeInstallPath} `
                -ArgumentList ("FIP-FS\Bin\pipeline2.dll") `
                -CatchActionFunction $CatchActionFunction

            if ($null -ne $pipeline2FileInfo) {
                Write-Verbose "Testing pipeline2.dll version: $($pipeline2FileInfo.VersionInfo.ProductVersion)"

                $isPipeline2Affected = $false

                try {
                    [int]$fileMajor = $pipeline2FileInfo.VersionInfo.FileMajorPart
                    [int]$fileMinor = $pipeline2FileInfo.VersionInfo.FileMinorPart
                    [int]$fileBuild = $pipeline2FileInfo.VersionInfo.FileBuildPart
                    [int]$filePrivate = $pipeline2FileInfo.VersionInfo.FilePrivatePart

                    if ($fileMajor -eq 15) {

                        switch ($fileMinor) {
                            0 { Write-Verbose "Exchange 2013 pipeline2.dll is safe to use" }
                            1 { $isPipeline2Affected = (($fileBuild -le 2375) -and ($filePrivate -le 17)) }
                            2 { $isPipeline2Affected = (($fileBuild -le 986) -and ($filePrivate -le 14)) }
                            Default { Write-Verbose "Unexpected minor passed to the switch statement" }
                        }
                    } else {
                        Write-Verbose "Exchange server version is not affected by the FIP-FS update issue"
                    }
                } catch {
                    Write-Verbose "Error occured while detecting pipeline2.dll version"
                    & $CatchActionFunction
                }
            }
            return $isPipeline2Affected
        }

        function GetHighestScanEngineVersionNumber {
            param (
                [string]$ComputerName,
                [scriptblock]$CatchActionFunction
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            try {
                $scanEngineVersions = Invoke-ScriptBlockHandler -ComputerName $ComputerName `
                    -ScriptBlock ${Function:GetItemFromExchangeInstallPath} `
                    -ArgumentList ("FIP-FS\Data\Engines\amd64\Microsoft\Bin") `
                    -CatchActionFunction $CatchActionFunction

                if ($null -ne $scanEngineVersions) {
                    [Int64]$highestScanEngineVersion = ($scanEngineVersions.Name | Measure-Object -Maximum).Maximum
                } else {
                    Write-Verbose "No FIP-FS scan engine version(s) detected"
                }
            } catch {
                Write-Verbose "Error occured while processing FIP-FS scan engine version(s)"
                & $CatchActionFunction
            }
            return $highestScanEngineVersion
        }
    } process {
        $isAffectedByFIPFSUpdateIssue = $false
        try {
            $pipeline2Affected = TestPipeline2Version -ComputerName $ComputerName `
                -CatchActionFunction $CatchActionFunction

            $highestScanEngineVersionNumber = GetHighestScanEngineVersionNumber -ComputerName $ComputerName `
                -CatchActionFunction $CatchActionFunction

            if ($null -eq $highestScanEngineVersionNumber) {
                Write-Verbose "No scan engine found on the computer - no further testings required"
            } elseif ($pipeline2Affected) {
                if ($highestScanEngineVersionNumber -ge 2201010000) {
                    Write-Verbose "Scan engine: $highestScanEngineVersionNumber will cause transport queue issues"
                    $isAffectedByFIPFSUpdateIssue = $true
                } else {
                    Write-Verbose "Scan engine: $highestScanEngineVersionNumber is safe to use"
                }
            } elseif ($pipeline2Affected -eq $false) {
                if (($highestScanEngineVersionNumber -ge 2202010000) -or
                    ($highestScanEngineVersionNumber -lt 2201010000)) {
                    Write-Verbose "Scan engine: $highestScanEngineVersionNumber is safe to use"
                } else {
                    Write-Verbose "This Exchange server has applied FIP-FS update pattern with an invalid version number"
                    Write-Verbose "Scan engine: $highestScanEngineVersionNumber"
                    $isAffectedByFIPFSUpdateIssue = $true
                }
            } else {
                Write-Verbose "Unexpected scenario detected - logic re-work required"
            }
        } catch {
            Write-Verbose "Failed to check for the FIP-FS update issue"
            $isAffectedByFIPFSUpdateIssue = $null
            & $CatchActionFunction
        }
    } end {
        return $isAffectedByFIPFSUpdateIssue
    }
}
