# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-AppPool.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
Function Get-ExchangeAppPoolsInformation {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $appPool = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock ${Function:Get-AppPool} `
        -ScriptBlockDescription "Getting App Pool information" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    $exchangeAppPoolsInfo = @{}

    $appPool |
        Where-Object { $_.add.name -like "MSExchange*" } |
        ForEach-Object {
            $configContent = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock {
                param(
                    $FilePath
                )
                if (Test-Path $FilePath) {
                    return (Get-Content $FilePath)
                }
                return [string]::Empty
            } `
                -ScriptBlockDescription "Getting Content file for $($_.add.name)" `
                -ArgumentList $_.add.CLRConfigFile `
                -CatchActionFunction ${Function:Invoke-CatchActions}

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
