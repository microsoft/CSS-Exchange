# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-TextExtractionOverride {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [string[]]$ConfigureOverride,

        [string]$Action,

        [switch]$Rollback
    )
    begin {
        $remoteScriptBlockExecute = {
            param($ArgumentList)
            . $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
            . $PSScriptRoot\..\..\Shared\Invoke-StartStopService.ps1
            . $PSScriptRoot\..\..\Shared\Invoke-XmlConfigurationRemoteAction.ps1

            $VerbosePreference = $Using:VerbosePreference # To be able to write back to the host screen if -Verbose is used.
            $successfulExecution = $false
            $errorContext = New-Object System.Collections.Generic.List[object]
            $activityBase = "[$env:COMPUTERNAME]"
            $writeProgressParams = @{
                Activity = "$activityBase Getting FIP FS Database Path"
                Id       = [Math]::Abs(($env:COMPUTERNAME).GetHashCode())
            }

            try {

                if ($null -eq $ArgumentList -or
                    (($null -eq $ArgumentList.Rollback -or $false -eq $ArgumentList.Rollback) -and
                    ($null -eq $ArgumentList.ConfigureOverride -or $null -eq $ArgumentList.Action))) {
                    throw "Invalid ArgumentList provided to remote execution."
                }

                # We need to hard code this, which isn't ideal. But this is the best option that we have at the moment.
                $defaultTypeLocations = @{
                    "XlsbOfficePackage" = "Excel"
                    "XlsmOfficePackage" = "Excel"
                    "XlsxOfficePackage" = "Excel"
                    "ExcelStorage"      = "Excel"
                    "DocmOfficePackage" = "PreferIFilters"
                    "DocxOfficePackage" = "PreferIFilters"
                    "PptmOfficePackage" = "PreferIFilters"
                    "PptxOfficePackage" = "PreferIFilters"
                    "WordStorage"       = "PreferIFilters"
                    "PowerPointStorage" = "PreferIFilters"
                    "VisioStorage"      = "PreferIFilters"
                    "Rtf"               = "PreferIFilters"
                    "Xml"               = "PreferIFilters"
                    "OdfTextDocument"   = "PreferIFilters"
                    "OdfSpreadsheet"    = "PreferIFilters"
                    "OdfPresentation"   = "PreferIFilters"
                    "OneNote"           = "PreferIFilters"
                    "Pdf"               = "PreferOutsideIn"
                    "Html"              = "PreferOutsideIn"
                    "AutoCad"           = "OutsideInOnly"
                    "Jpeg"              = "OutsideInOnly"
                    "Tiff"              = "OutsideInOnly"
                }

                $baseXPathFilter = "//*[local-name()='Configuration']/*[local-name()='System']/*[local-name()='TextExtractionSettings']"
                $outsideInOnlyModuleXPathFilter = $baseXPathFilter +
                "/*[local-name()='ModuleLists']/*[local-name()='ModuleList'][@TypeList='OutsideInOnly']/*[local-name()='Module'][contains(., 'OutsideInModule.dll')]"
                $typeListBaseXPathFilter = $baseXPathFilter + "/*[local-name()='TypeLists']/*[local-name()='TypeList'][@Name='{0}']"
                $getTypeBaseTypeListXPathFilter = $baseXPathFilter +
                "/*[local-name()='TypeLists']/*[local-name()='TypeList']/*[local-name()='Type'][starts-with(@Name, '{0}')]"
                Write-Progress @writeProgressParams

                $fipFsDatabaseParams = @{
                    MachineName = $env:COMPUTERNAME
                    SubKey      = "SOFTWARE\Microsoft\ExchangeServer\v15\FIP-FS"
                    GetValue    = "DatabasePath"
                }
                $fipFsDatabasePath = Get-RemoteRegistryValue @fipFsDatabaseParams

                if (([string]::IsNullOrEmpty($fipFsDatabasePath))) {
                    throw "Unable to find FIP FS Database Path"
                }

                $path = (Join-Path $fipFsDatabasePath "Configuration.xml")
                Write-Verbose "Using the database path of '$path' to adjust"

                $xmlConfigurationRemoteAction = [PSCustomObject]@{
                    FilePath       = $path
                    BackupFileName = "TextExtractionOverride"
                    Actions        = (New-Object System.Collections.Generic.List[object])
                }

                $writeProgressParams.Activity = $activityBase + " Stopping MSExchangeTransport and FMS Services"
                Write-Progress @writeProgressParams
                # Always Stop the services first
                # TODO: Determine if we need to stop the services or need to restart
                $serviceResult = Invoke-StartStopService -ServiceName "MSExchangeTransport", "FMS" -Action "Stop"

                if ($true -eq $serviceResult) {

                    if (-not $ArgumentList.Rollback) {
                        # If we got a true result, we stopped the service
                        # Now create the actions list
                        foreach ($configureActionOverride in $ArgumentList.ConfigureOverride) {
                            if ($configureActionOverride -eq "OutsideInModule") {
                                # If configureActionOverride is OutsideInModule then we are setting that path only.
                                $actionOperation = [PSCustomObject]@{
                                    SelectNodesFilter = $outsideInOnlyModuleXPathFilter
                                    OperationType     = [string]::Empty
                                    Operation         = [PSCustomObject]@{
                                        AttributeName = "#text"
                                        Value         = "|NO"
                                        ReplaceValue  = [string]::Empty
                                    }
                                }

                                if ($ArgumentList.Action -eq "Allow") {
                                    $actionOperation.OperationType = "AppendAttribute"
                                    $xmlConfigurationRemoteAction.Actions.Add($actionOperation)
                                } elseif ($ArgumentList.Action -eq "Block") {
                                    $actionOperation.OperationType = "ReplaceAttributeValue"
                                    $xmlConfigurationRemoteAction.Actions.Add($actionOperation)
                                }
                            } else {
                                # Now everything else is attempting to do the following on the Type:
                                # Either set or remove the |NO flag
                                # Move the Type to the TypeList OutsideInOnly as that is the only location where the |NO flag is honored
                                $baseFilter = $getTypeBaseTypeListXPathFilter -f $configureActionOverride

                                if ($ArgumentList.Action -eq "Allow") {

                                    $xmlConfigurationRemoteAction.Actions.Add(([PSCustomObject]@{
                                                SelectNodesFilter = $baseFilter
                                                OperationType     = "MoveNode"
                                                Operation         = [PSCustomObject]@{
                                                    MoveToSelectNodesFilter          = ($typeListBaseXPathFilter -f "OutsideInOnly")
                                                    ParentNodeAttributeNameFilterAdd = "Name"
                                                }
                                            }))

                                    $xmlConfigurationRemoteAction.Actions.Add(([PSCustomObject]@{
                                                SelectNodesFilter = $baseFilter
                                                OperationType     = "AppendAttribute"
                                                Operation         = [PSCustomObject]@{
                                                    AttributeName = "Name"
                                                    Value         = "|NO"
                                                }
                                            }))
                                } elseif ($ArgumentList.Action -eq "Block") {
                                    $xmlConfigurationRemoteAction.Actions.Add(([PSCustomObject]@{
                                                SelectNodesFilter = $baseFilter
                                                OperationType     = "ReplaceAttributeValue"
                                                Operation         = [PSCustomObject]@{
                                                    AttributeName = "Name"
                                                    Value         = "|NO"
                                                    ReplaceValue  = [string]::Empty
                                                }
                                            }))

                                    $xmlConfigurationRemoteAction.Actions.Add(([PSCustomObject]@{
                                                SelectNodesFilter = $baseFilter
                                                OperationType     = "MoveNode"
                                                Operation         = [PSCustomObject]@{
                                                    MoveToSelectNodesFilter          = ($typeListBaseXPathFilter -f $defaultTypeLocations[$configureActionOverride])
                                                    ParentNodeAttributeNameFilterAdd = "Name"
                                                }
                                            }))
                                }
                            }
                        }
                    } else {
                        $xmlConfigurationRemoteAction | Add-Member -MemberType NoteProperty -Name "Restore" -Value ([PSCustomObject]@{
                                FileName = $xmlConfigurationRemoteAction.BackupFileName
                            })
                    }

                    # Now that we have the list of actions, we need to execute the results then determine if we were successful or not.
                    $writeProgressParams.Activity = $activityBase + " updating the Xml Configuration file"
                    Write-Progress @writeProgressParams
                    $results = Invoke-XmlConfigurationRemoteAction -InputObject $xmlConfigurationRemoteAction
                    Write-Host ""

                    if ($results.SuccessfulExecution) {
                        Write-Host "[$env:COMPUTERNAME] Successfully completed the configuration for FIP FS Text Extraction Override"
                        $successfulExecution = $true
                    } else {
                        Write-Warning "$env:COMPUTERNAME Failed to execution configuration action for FIP FS Text Extraction Override"
                    }

                    Write-Host ""
                }

                # Attempt to start the service again, even if we failed to stop. One could have worked.
                $writeProgressParams.Activity = $activityBase + " Starting MSExchangeTransport and FMS Services"
                Write-Progress @writeProgressParams
                $serviceResult = Invoke-StartStopService -ServiceName "MSExchangeTransport", "FMS" -Action "Start"
            } catch {
                Write-Verbose "Caught an exception while trying to execute actions for Text EXtraction Override. Inner Exception: $_"
                $errorContext.Add($_)
            } finally {
                Write-Progress @writeProgressParams -Completed
                [PSCustomObject]@{
                    ServerName          = $env:COMPUTERNAME
                    SuccessfulExecution = $successfulExecution
                    ErrorContext        = $errorContext
                    ServicesStarted     = $true -eq $serviceResult
                }
            }
        }
    }
    process {
        $results = Invoke-Command -ComputerName $ComputerName -ScriptBlock $remoteScriptBlockExecute -ArgumentList ([PSCustomObject]@{
                ConfigureOverride = $ConfigureOverride
                Action            = $Action
                Rollback          = $Rollback
            })

        $successServers = @($results | Where-Object { $_.SuccessfulExecution -eq $true -and $_.ErrorContext.Count -eq 0 })
        $failedServers = @($results | Where-Object { $_.SuccessfulExecution -eq $false -or $_.ErrorContext.Count -ne 0 })
        $failedServiceStart = @($results | Where-Object { $_.ServicesStarted -eq $false })

        Write-Host ""
        Write-Host ""

        if ($null -ne $failedServers -and
            $failedServers.Count -gt 0) {
            Write-Warning "Failed to complete Text Extraction Override on the following servers: $([string]::Join(", ", $failedServers.ServerName))"
        }

        if ($null -ne $failedServiceStart -and
            $failedServiceStart.Count -gt 0) {
            Write-Warning "Failed to start the MSExchangeTransport and/or FMS services on the following servers: $([string]::Join(", ", $failedServiceStart.ServerName))"
        }

        if ($null -ne $successServers -and
            $successServers.Count -gt 0) {
            Write-Host "Successfully completed Text Extraction Override on the following servers: $([string]::Join(", ", $successServers.ServerName))" -ForegroundColor "Green"
        }

        Write-Host ""
    }
}
