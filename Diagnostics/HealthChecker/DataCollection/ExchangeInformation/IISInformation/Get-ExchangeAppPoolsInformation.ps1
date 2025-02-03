# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AppPool.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\..\Shared\ScriptBlock\Invoke-RemotePipelineHandler.ps1

function Get-ExchangeAppPoolsInformation {
    param(
        [string]$Server = $env:COMPUTERNAME
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    if ($PSSenderInfo) {
        $appPool = $null
        Get-AppPool | Invoke-RemotePipelineHandler -Result ([ref]$appPool)
    } else {
        $appPool = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock ${Function:Get-AppPool} `
            -ScriptBlockDescription "Getting App Pool information" `
            -CatchActionFunction ${Function:Invoke-CatchActions}
    }

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

            if ($PSSenderInfo) {
                $configContent = & $scriptBlock $_.add.CLRConfigFile
            } else {
                $configContent = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock $scriptBlock `
                    -ScriptBlockDescription "Getting Content file for $($_.add.name)" `
                    -ArgumentList $_.add.CLRConfigFile `
                    -CatchActionFunction ${Function:Invoke-CatchActions}
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
