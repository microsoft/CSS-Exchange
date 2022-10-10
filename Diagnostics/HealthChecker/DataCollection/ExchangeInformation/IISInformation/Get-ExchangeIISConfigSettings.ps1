# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

function Get-ExchangeIISConfigSettings {
    [CmdletBinding()]
    param(
        [string]$MachineName,
        [string[]]$FilePath,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        function GetExchangeIISConfigSettings {
            param(
                [string[]]$FilePath
            )

            $results = New-Object 'System.Collections.Generic.List[object]'
            $sharedConfigure = @()
            $ca = "ClientAccess\"
            $hp = "HttpProxy\"
            $sharedWebConfig = "SharedWebConfig.config"

            foreach ($location in $FilePath) {

                Write-Verbose "Working on location: $location"
                $exist = Test-Path $location
                $content = $null
                $sharedLocation = $null

                if ($exist) {
                    Write-Verbose "File exists. Getting content"
                    $content = Get-Content $location
                    $linkedConfiguration = ($content | Select-String linkedConfiguration).Line

                    if ($null -ne $linkedConfiguration) {
                        Write-Verbose "Found linkedConfiguration"
                        $clientAccessSharedIndex = $location.IndexOf($ca)
                        $httpProxySharedIndex = $location.IndexOf($hp)

                        if ($clientAccessSharedIndex -ne -1) {
                            $sharedLocation = [System.IO.Path]::Combine($location.Substring(0, $clientAccessSharedIndex + $ca.Length), $sharedWebConfig)
                        } elseif ($httpProxySharedIndex -ne -1) {
                            $sharedLocation = [System.IO.Path]::Combine($location.Substring(0, $httpProxySharedIndex + $hp.Length), $sharedWebConfig)
                        }
                    }

                    if ($null -ne $sharedLocation -and
                        (-not ($sharedConfigure.Contains($sharedLocation)))) {
                        Write-Verbose "Adding Shared Location of: $sharedLocation"
                        $sharedConfigure += $sharedLocation
                        $results.Add([PSCustomObject]@{
                                Location = $sharedLocation
                                Content  = if (Test-Path $sharedLocation) { Get-Content $sharedLocation } else { $null }
                                Exist    = $(Test-Path $sharedLocation)
                            })
                    }
                }

                $results.Add([PSCustomObject]@{
                        Location = $location
                        Content  = $content
                        Exist    = $exist
                    })
            }
            return $results
        }
    } process {
        $params = @{
            ComputerName        = $MachineName
            ScriptBlock         = ${Function:GetExchangeIISConfigSettings}
            ArgumentList        = $FilePath
            CatchActionFunction = $CatchActionFunction
        }
        return Invoke-ScriptBlockHandler @params
    }
}
