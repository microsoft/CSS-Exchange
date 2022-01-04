# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-CatchActions.ps1

Function Get-FIPFSScanEngineVersionState {
    [CmdletBinding()]
    [OutputType("System.Object")]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName
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
                Invoke-CatchActions
                $exSetupPath = $env:ExchangeInstallPath
            }

            $finalPath = Join-Path $exSetupPath $ExchangeSubDir

            if ($ExchangeSubDir -notmatch '\.[a-zA-Z0-9]+$') {
                $getDir = Get-ChildItem -Path $finalPath -Attributes Directory
                if ($null -ne $getDir) {
                    return ([PSCustomObject]@{
                            Name             = $getDir.Name
                            LastWriteTimeUtc = $getDir.LastWriteTimeUtc
                        })
                }
            }
            return $null
        }

        function GetHighestScanEngineVersionNumber {
            param (
                [string]$ComputerName
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            try {
                $scanEngineVersions = Invoke-ScriptBlockHandler -ComputerName $ComputerName `
                    -ScriptBlock ${Function:GetFolderFromExchangeInstallPath} `
                    -ArgumentList ("FIP-FS\Data\Engines\amd64\Microsoft\Bin") `
                    -CatchActionFunction ${Function:Invoke-CatchActions}

                if ($null -ne $scanEngineVersions) {
                    [Int64]$highestScanEngineVersion = ($scanEngineVersions.Name | Measure-Object -Maximum).Maximum
                } else {
                    Write-Verbose "No FIP-FS scan engine version(s) detected"
                }
            } catch {
                Write-Verbose "Error occured while processing FIP-FS scan engine version(s)"
                Invoke-CatchActions
            }
            return $highestScanEngineVersion
        }
    } process {
        $isAffectedByFIPFSUpdateIssue = $false
        try {

            $highestScanEngineVersionNumber = GetHighestScanEngineVersionNumber -ComputerName $ComputerName

            if ($null -eq $highestScanEngineVersionNumber) {
                Write-Verbose "No scan engine version found on the computer - no further testings required"
            } elseif ($highestScanEngineVersionNumber -ge 2201010000) {
                Write-Verbose "Scan engine: $highestScanEngineVersionNumber will cause transport queue or pattern update issues"
                $isAffectedByFIPFSUpdateIssue = $true
            } else {
                Write-Verbose "Scan engine: $highestScanEngineVersionNumber is safe to use"
            }
        } catch {
            Write-Verbose "Failed to check for the FIP-FS update issue"
            $isAffectedByFIPFSUpdateIssue = $null
            Invoke-CatchActions
        }
    } end {
        return $isAffectedByFIPFSUpdateIssue
    }
}
