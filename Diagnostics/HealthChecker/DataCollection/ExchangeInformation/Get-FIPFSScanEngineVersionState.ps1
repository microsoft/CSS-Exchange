# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

Function Get-FIPFSScanEngineVersionState {
    [CmdletBinding()]
    [OutputType("System.Bool")]
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
                [string]$ExchangeSubDir
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            $finalPathToQuery = Join-Path $env:ExchangeInstallPath $ExchangeSubDir
            $getItem = Get-Item -Path $finalPathToQuery

            $returnObject = ([PSCustomObject]@{
                    GetItem          = $getItem
                    LastWriteTimeUtc = $getItem.LastWriteTimeUtc
                    VersionInfo      = ([PSCustomObject]@{
                            ProductVersion  = $getItem.VersionInfo.ProductVersion.ToString()
                            FileMajorPart   = $getItem.VersionInfo.FileMajorPart
                            FileMinorPart   = $getItem.VersionInfo.FileMinorPart
                            FileBuildPart   = $getItem.VersionInfo.FileBuildPart
                            FilePrivatePart = $getItem.VersionInfo.FilePrivatePart
                        })
                })

            return $returnObject
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

                $pipeline2ReturnObject = ([PSCustomObject]@{
                        isE15    = $false
                        Affected = $false
                    })

                try {
                    [int]$fileMajor = $pipeline2FileInfo.VersionInfo.FileMajorPart
                    [int]$fileMinor = $pipeline2FileInfo.VersionInfo.FileMinorPart
                    [int]$fileBuild = $pipeline2FileInfo.VersionInfo.FileBuildPart
                    [int]$filePrivate = $pipeline2FileInfo.VersionInfo.FilePrivatePart

                    if ($fileMajor -eq 15) {

                        switch ($fileMinor) {
                            0 { $pipeline2ReturnObject.isE15 = $true }
                            1 { $pipeline2ReturnObject.Affected = (($fileBuild -le 2375) -and ($filePrivate -le 17)) }
                            2 { $pipeline2ReturnObject.Affected = (($fileBuild -le 986) -and ($filePrivate -le 14)) }
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
            return $pipeline2ReturnObject
        }

        function GetHighestScanEngineVersionNumber {
            param (
                [string]$ComputerName,
                [scriptblock]$CatchActionFunction
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            try {
                $scanEngineVersions = Invoke-ScriptBlockHandler -ComputerName $ComputerName `
                    -ScriptBlock { Get-ChildItem -Path (Join-Path $env:ExchangeInstallPath "FIP-FS\Data\Engines\amd64\Microsoft\Bin") -Attributes Directory } `
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
            $pipeline2 = TestPipeline2Version -ComputerName $ComputerName `
                -CatchActionFunction $CatchActionFunction

            if ($pipeline2.Affected -or
                $pipeline2.isE15) {
                $highesScanEngineVersionNumber = GetHighestScanEngineVersionNumber -ComputerName $ComputerName `
                    -CatchActionFunction $CatchActionFunction
                if (($null -ne $highesScanEngineVersionNumber) -and
                    ($highesScanEngineVersionNumber -ge 2201010000)) {
                    if ($pipeline2.isE15) {
                        Write-Verbose "This Exchange 2013 server has applied FIP-FS update pattern with an invalid version number"
                        Write-Verbose "Scan engine: $highesScanEngineVersionNumber"
                    } else {
                        Write-Verbose "Scan engine: $highesScanEngineVersionNumber will cause transport queue issues"
                    }
                    $isAffectedByFIPFSUpdateIssue = $true
                } else {
                    Write-Verbose "Scan engine: $highesScanEngineVersionNumber is safe to use"
                }
            } else {
                Write-Verbose "The current Exchange server version is not affected by the FIP-FS update issue"
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
