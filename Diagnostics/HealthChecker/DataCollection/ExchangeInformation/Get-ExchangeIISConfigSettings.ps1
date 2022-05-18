# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

function Get-ExchangeIISConfigSettings {
    [CmdletBinding()]
    param(
        [string]$MachineName,
        [string]$ExchangeInstallPath,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Write-Verbose "Passed ExchangeInstallPath: $ExchangeInstallPath"
        function GetExchangeIISConfigSettings {
            param(
                [string]$ExchangeInstallPath
            )
            $iisConfigLocations = @("ClientAccess\Autodiscover\web.config",
                "ClientAccess\ecp\web.config",
                "ClientAccess\exchweb\ews\web.config",
                "ClientAccess\mapi\emsmdb\web.config",
                "ClientAccess\mapi\nspi\web.config",
                "ClientAccess\OAB\web.config",
                "ClientAccess\Owa\web.config",
                "ClientAccess\PowerShell\web.config",
                "ClientAccess\PowerShell-Proxy\web.config",
                "ClientAccess\RpcProxy\web.config",
                "ClientAccess\Sync\web.config",
                "FrontEnd\HttpProxy\autodiscover\web.config",
                "FrontEnd\HttpProxy\ecp\web.config",
                "FrontEnd\HttpProxy\ews\web.config",
                "FrontEnd\HttpProxy\mapi\web.config",
                "FrontEnd\HttpProxy\oab\web.config",
                "FrontEnd\HttpProxy\owa\web.config",
                "FrontEnd\HttpProxy\powershell\web.config",
                "FrontEnd\HttpProxy\pushnotifications\web.config",
                "FrontEnd\HttpProxy\ReportingWebService\web.config",
                "FrontEnd\HttpProxy\rpc\web.config",
                "FrontEnd\HttpProxy\sync\web.config",
                "ClientAccess\SharedWebConfig.config",
                "FrontEnd\HttpProxy\SharedWebConfig.config")
            $binSearchFolderPaths = @("bin", "bin\CmdletExtensionAgents", "ClientAccess\Owa\bin")
            $results = New-Object 'System.Collections.Generic.List[object]'

            foreach ($location in $iisConfigLocations) {
                $binSearchFoldersNotFound = $false
                $fullPath = [System.IO.Path]::Combine($ExchangeInstallPath, $location)

                if ((Test-Path $fullPath)) {
                    $exist = $true
                    $defaultVariable = $null -ne (Get-ChildItem $fullPath | Select-String "%ExchangeInstallDir%")
                } else {
                    $exist = $false
                    $defaultVariable = $false
                }
                # not sure if we need to check for this, because I think the %ExchangeInstallDir% will be set still
                # but going to add this check as well either way.
                if ($location -eq "ClientAccess\ecp\web.config" -and
                    $exist) {

                    $BinSearchFolders = Get-ChildItem $fullPath | Select-String "BinSearchFolders" | Select-Object -ExpandProperty Line
                    $startIndex = $BinSearchFolders.IndexOf("value=`"") + 7
                    $paths = $BinSearchFolders.Substring($startIndex, $BinSearchFolders.LastIndexOf("`"") - $startIndex).Split(";").Trim().ToLower()
                    $paths | ForEach-Object { Write-Verbose "BinSearchFolder: $($_)" }
                    foreach ($binTestPath in $binSearchFolderPaths) {
                        $testPath = [System.IO.Path]::Combine($ExchangeInstallPath, $binTestPath).ToLower()
                        Write-Verbose "Testing path: $testPath"
                        if (-not ($paths.Contains($testPath))) {
                            $binSearchFoldersNotFound = $true
                        }
                    }
                }
                $results.Add([PSCustomObject]@{
                        Location                 = $fullPath
                        Exist                    = $exist
                        DefaultVariable          = $defaultVariable
                        BinSearchFoldersNotFound = $binSearchFoldersNotFound
                    })
            }
            return $results
        }
    } process {
        $params = @{
            ComputerName        = $MachineName
            ScriptBlock         = ${Function:GetExchangeIISConfigSettings}
            ArgumentList        = $ExchangeInstallPath
            CatchActionFunction = $CatchActionFunction
        }
        return Invoke-ScriptBlockHandler @params
    }
}
