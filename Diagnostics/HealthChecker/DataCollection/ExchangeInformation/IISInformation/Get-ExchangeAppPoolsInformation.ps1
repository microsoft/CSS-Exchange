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
            $scriptBlock = {
                param(
                    $FilePath
                )
                if (Test-Path $FilePath) {
                    return (Get-Content $FilePath -Raw -Encoding UTF8).Trim()
                }
                return [string]::Empty
            }

            $configContent = & $scriptBlock $_.add.CLRConfigFile
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
