# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AppPool.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-ExchangeAppPoolsInformation {
    param(
        [string]$Server = $env:COMPUTERNAME
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $appPool = $null
    Get-AppPool | Invoke-RemotePipelineHandler -Result ([ref]$appPool)
    $exchangeAppPoolsInfo = @{}

    $appPool |
        Where-Object { $_.add.name -like "MSExchange*" } |
        ForEach-Object {
            Write-Verbose "Working on App Pool: $($_.add.name)"
            $clrConfigFilePath = $_.add.CLRConfigFile

            if ((-not ([string]::IsNullOrEmpty($clrConfigFilePath))) -and (Test-Path $clrConfigFilePath)) {
                $configContent = (Get-Content $clrConfigFilePath -Raw -Encoding UTF8).Trim()
            } else {
                $configContent = [string]::Empty
            }

            $gcUnknown = $true
            $gcServerEnabled = $false

            if (-not ([string]::IsNullOrEmpty($configContent))) {
                $gcSetting = ([xml]$configContent).Configuration.Runtime.gcServer.Enabled
                $gcUnknown = $gcSetting -ne "true" -and $gcSetting -ne "false"
                $gcServerEnabled = $gcSetting -eq "true"
            }
            $exchangeAppPoolsInfo.Add($_.add.Name, [PSCustomObject]@{
                    ConfigContent   = $configContent
                    AppSettings     = $_
                    GCUnknown       = $gcUnknown
                    GCServerEnabled = $gcServerEnabled
                })
        }

    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $exchangeAppPoolsInfo
}
