# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Add-AnalyzedResultInformation.ps1

function Invoke-AnalyzerSecurityIISModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$SecurityObject,

        [Parameter(Mandatory = $true)]
        [object]$DisplayGroupingKey
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInformation = $SecurityObject.ExchangeInformation
    $moduleInformation = $exchangeInformation.IISSettings.IISModulesInformation

    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = $DisplayGroupingKey
    }

    # Description: Check for modules which are loaded by IIS and not signed by Microsoft or not signed at all
    if ($SecurityObject.IsEdgeServer -eq $false) {
        if ($null -ne $moduleInformation) {
            $iisModulesOutputList = New-Object 'System.Collections.Generic.List[object]'
            $modulesWriteType = "Grey"

            foreach ($m in $moduleInformation.ModuleList) {
                if ($m.Signed -eq $false) {
                    $modulesWriteType = "Red"

                    $iisModulesOutputList.Add([PSCustomObject]@{
                            Module = $m.Name
                            Path   = $m.Path
                            Signer = "N/A"
                            Status = "Not signed"
                        })
                } elseif (($m.SignatureDetails.IsMicrosoftSigned -eq $false) -or
                    ($m.SignatureDetails.SignatureStatus -ne 0) -and
                    ($m.SignatureDetails.SignatureStatus -ne -1)) {
                    if ($modulesWriteType -ne "Red") {
                        $modulesWriteType = "Yellow"
                    }

                    $iisModulesOutputList.Add([PSCustomObject]@{
                            Module = $m.Name
                            Path   = $m.Path
                            Signer = $m.SignatureDetails.Signer
                            Status = $m.SignatureDetails.SignatureStatus
                        })
                }
            }
            $params = $baseParams + @{
                Name             = "IIS module anomalies detected"
                Details          = ($iisModulesOutputList.Count -ge 1)
                DisplayWriteType = $modulesWriteType
            }
            Add-AnalyzedResultInformation @params

            if ($iisModulesOutputList.Count -ge 1) {
                if ($moduleInformation.AllModulesSigned -eq $false) {
                    $params = $baseParams + @{
                        Details                = "Modules that are loaded by IIS but NOT SIGNED - possibly a security risk"
                        DisplayCustomTabNumber = 2
                        DisplayWriteType       = "Red"
                    }
                    Add-AnalyzedResultInformation @params
                }

                if (($moduleInformation.AllSignedModulesSignedByMSFT -eq $false) -or
                    ($moduleInformation.AllSignaturesValid -eq $false)) {
                    $params = $baseParams + @{
                        Details                = "Modules that are loaded but NOT SIGNED BY Microsoft OR that have a problem with their signature"
                        DisplayCustomTabNumber = 2
                        DisplayWriteType       = "Yellow"
                    }
                    Add-AnalyzedResultInformation @params
                }

                $iisModulesConfig = {
                    param ($o, $p)
                    if ($p -eq "Signer") {
                        if ($o.$p -eq "N/A") {
                            "Red"
                        } else {
                            "Yellow"
                        }
                    } elseif ($p -eq "Status") {
                        if ($o.$p -eq "Not signed") {
                            "Red"
                        } elseif ($o.$p -ne 0) {
                            "Yellow"
                        }
                    }
                }

                $iisModulesParams = $baseParams + @{
                    Name       = "IIS Modules"
                    OutColumns = ([PSCustomObject]@{
                            DisplayObject      = $iisModulesOutputList
                            ColorizerFunctions = @($iisModulesConfig)
                            IndentSpaces       = 8
                        })
                }
                Add-AnalyzedResultInformation @iisModulesParams
            }
        } else {
            Write-Verbose "No modules were returned by previous call"
        }
    } else {
        Write-Verbose "IIS is not available on Edge Transport Server - check will be skipped"
    }
}
