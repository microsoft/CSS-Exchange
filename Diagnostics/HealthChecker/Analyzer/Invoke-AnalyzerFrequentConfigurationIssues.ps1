# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\Helpers\CompareExchangeBuildLevel.ps1
function Invoke-AnalyzerFrequentConfigurationIssues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [int]$Order
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation
    $tcpKeepAlive = $osInformation.RegistryValues.TCPKeepAlive
    $organizationInformation = $HealthServerObject.OrganizationInformation

    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = (Get-DisplayResultsGroupingKey -Name "Frequent Configuration Issues"  -DisplayOrder $Order)
    }

    if ($tcpKeepAlive -eq 0) {
        $displayValue = "Not Set `r`n`t`tError: Without this value the KeepAliveTime defaults to two hours, which can cause connectivity and performance issues between network devices such as firewalls and load balancers depending on their configuration. `r`n`t`tMore details: https://aka.ms/HC-TcpIpSettingsCheck"
        $displayWriteType = "Red"
    } elseif ($tcpKeepAlive -lt 900000 -or
        $tcpKeepAlive -gt 1800000) {
        $displayValue = "$tcpKeepAlive `r`n`t`tWarning: Not configured optimally, recommended value between 15 to 30 minutes (900000 and 1800000 decimal). `r`n`t`tMore details: https://aka.ms/HC-TcpIpSettingsCheck"
        $displayWriteType = "Yellow"
    } else {
        $displayValue = $tcpKeepAlive
        $displayWriteType = "Green"
    }

    $params = $baseParams + @{
        Name                = "TCP/IP Settings"
        Details             = $displayValue
        DisplayWriteType    = $displayWriteType
        DisplayTestingValue = $tcpKeepAlive
        HtmlName            = "TCPKeepAlive"
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name                = "RPC Min Connection Timeout"
        Details             = "$($osInformation.RegistryValues.RpcMinConnectionTimeout) `r`n`t`tMore Information: https://aka.ms/HC-RPCSetting"
        DisplayTestingValue = $osInformation.RegistryValues.RpcMinConnectionTimeout
        HtmlName            = "RPC Minimum Connection Timeout"
    }
    Add-AnalyzedResultInformation @params

    if ($exchangeInformation.RegistryValues.DisableGranularReplication -ne 0) {
        $params = $baseParams + @{
            Name                = "DisableGranularReplication"
            Details             = "$($exchangeInformation.RegistryValues.DisableGranularReplication) - Error this can cause work load management issues."
            DisplayWriteType    = "Red"
            DisplayTestingValue = $true
        }
        Add-AnalyzedResultInformation @params
    }

    $params = $baseParams + @{
        Name     = "FIPS Algorithm Policy Enabled"
        Details  = $exchangeInformation.RegistryValues.FipsAlgorithmPolicyEnabled
        HtmlName = "FipsAlgorithmPolicy-Enabled"
    }
    Add-AnalyzedResultInformation @params

    $displayValue = $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
    $displayWriteType = "Green"

    if ($exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage -ne 0) {
        $displayWriteType = "Red"
        $displayValue = "{0} `r`n`t`tError: This can cause an impact to the server's search performance. This should only be used a temporary fix if no other options are available vs a long term solution." -f $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
    }

    $params = $baseParams + @{
        Name                = "CTS Processor Affinity Percentage"
        Details             = $displayValue
        DisplayWriteType    = $displayWriteType
        DisplayTestingValue = $exchangeInformation.RegistryValues.CtsProcessorAffinityPercentage
        HtmlName            = "CtsProcessorAffinityPercentage"
    }
    Add-AnalyzedResultInformation @params

    $displayValue = $exchangeInformation.RegistryValues.DisableAsyncNotification
    $displayWriteType = "Grey"

    if ($displayValue -ne 0) {
        $displayWriteType = "Yellow"
        $displayValue = "$($exchangeInformation.RegistryValues.DisableAsyncNotification) Warning: This value should be set back to 0 after you no longer need it for the workaround described in http://support.microsoft.com/kb/5013118"
    }

    $params = $baseParams + @{
        Name                = "Disable Async Notification"
        Details             = $displayValue
        DisplayWriteType    = $displayWriteType
        DisplayTestingValue = $displayValue -ne 0
    }
    Add-AnalyzedResultInformation @params

    $displayValue = $credentialGuardValue = $osInformation.RegistryValues.CredentialGuard -ne 0
    $displayWriteType = "Grey"

    if ($credentialGuardValue) {
        $displayValue = "{0} `r`n`t`tError: Credential Guard is not supported on an Exchange Server. This can cause a performance hit on the server." -f $credentialGuardValue
        $displayWriteType = "Red"
    }

    $params = $baseParams + @{
        Name                = "Credential Guard Enabled"
        Details             = $displayValue
        DisplayTestingValue = $credentialGuardValue
        DisplayWriteType    = $displayWriteType
    }
    Add-AnalyzedResultInformation @params

    if ($null -ne $exchangeInformation.ApplicationConfigFileStatus -and
        $exchangeInformation.ApplicationConfigFileStatus.Count -ge 1) {

        foreach ($configKey in $exchangeInformation.ApplicationConfigFileStatus.Keys) {
            $configStatus = $exchangeInformation.ApplicationConfigFileStatus[$configKey]
            $writeType = "Green"
            $writeValue = $configStatus.Present

            if (!$configStatus.Present) {
                $writeType = "Red"
                $writeValue = "{0} --- Error" -f $writeValue
            }

            $params = $baseParams + @{
                Name             = "$configKey Present"
                Details          = $writeValue
                DisplayWriteType = $writeType
            }
            Add-AnalyzedResultInformation @params
        }
    }

    $displayWriteType = "Yellow"
    $displayValue = "Unknown - Unable to run Get-AcceptedDomain"
    $additionalDisplayValue = [string]::Empty

    if ($null -ne $organizationInformation.GetAcceptedDomain -and
        $organizationInformation.GetAcceptedDomain -ne "Unknown") {

        $wildCardAcceptedDomain = $organizationInformation.GetAcceptedDomain | Where-Object { $_.DomainName.ToString() -eq "*" }

        if ($null -eq $wildCardAcceptedDomain) {
            $displayValue = "Not Set"
            $displayWriteType = "Grey"
        } else {
            $displayWriteType = "Red"
            $displayValue = "Error --- Accepted Domain `"$($wildCardAcceptedDomain.Id)`" is set to a Wild Card (*) Domain Name with a domain type of $($wildCardAcceptedDomain.DomainType.ToString()). This is not recommended as this is an open relay for the entire environment.`r`n`t`tMore Information: https://aka.ms/HC-OpenRelayDomain"

            if ($wildCardAcceptedDomain.DomainType.ToString() -eq "InternalRelay" -and
                ((Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2016" -CU "CU22") -or
                (Test-ExchangeBuildGreaterOrEqualThanBuild -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -Version "Exchange2019" -CU "CU11"))) {
                $additionalDisplayValue = "`r`n`t`tERROR: You have an open relay set as Internal Replay Type and on a CU that is known to cause issues with transport services crashing. Follow the above article for more information."
            } elseif ($wildCardAcceptedDomain.DomainType.ToString() -eq "InternalRelay") {
                $additionalDisplayValue = "`r`n`t`tWARNING: You have an open relay set as Internal Relay Type. You are not on a CU yet that is having issue, recommended to change this prior to upgrading. Follow the above article for more information."
            }
        }
    }

    $params = $baseParams + @{
        Name             = "Open Relay Wild Card Domain"
        Details          = $displayValue
        DisplayWriteType = $displayWriteType
    }
    Add-AnalyzedResultInformation @params

    if ($additionalDisplayValue -ne [string]::Empty) {
        $params = $baseParams + @{
            Details          = $additionalDisplayValue
            DisplayWriteType = "Red"
        }
        Add-AnalyzedResultInformation @params
    }

    $params = $baseParams + @{
        Name    = "DisablePreservation"
        Details = $exchangeInformation.RegistryValues.DisablePreservation
    }
    Add-AnalyzedResultInformation @params

    if ($null -ne $exchangeInformation.IISSettings.IISWebApplication -or
        $null -ne $exchangeInformation.IISSettings.IISWebSite -or
        $null -ne $exchangeInformation.IISSettings.IISSharedWebConfig) {
        $iisWebSettings = @($exchangeInformation.IISSettings.IISWebApplication)
        $iisWebSettings += @($exchangeInformation.IISSettings.IISWebSite)
        $iisConfigurationSettings = @($exchangeInformation.IISSettings.IISWebApplication.ConfigurationFileInfo)
        $iisConfigurationSettings += $iisWebSiteConfigs = @($exchangeInformation.IISSettings.IISWebSite.ConfigurationFileInfo)
        $iisConfigurationSettings += @($exchangeInformation.IISSettings.IISSharedWebConfig)

        # Invalid configuration files are ones that we can't convert to xml.
        $invalidConfigurationFile = $iisConfigurationSettings | Where-Object { $_.Valid -eq $false -and $_.Exist -eq $true }
        # If a web application config file doesn't truly exists, we end up using the parent web.config file
        # If any of the web application config file paths match a parent path, that is a problem.
        # only collect the ones that are valid, if not valid we will assume that the child web apps will point to it and can be misleading.
        $siteConfigPaths = $iisWebSiteConfigs |
            Where-Object { $_.Valid -eq $true -and $_.Exist -eq $true } |
            ForEach-Object { $_.Location.ToLower() }

        if ($null -ne $siteConfigPaths) {
            $missingWebApplicationConfigFile = $exchangeInformation.IISSettings.IISWebApplication |
                Where-Object { $siteConfigPaths.Contains($_.ConfigurationFileInfo.Location.ToLower()) }
        }

        # Missing config file should really only occur for SharedWebConfig files, as the web application would go back to the parent site.
        $missingSharedConfigFile = @($exchangeInformation.IISSettings.IISSharedWebConfig) | Where-Object { $_.Exist -eq $false }
        $missingConfigFiles = $iisWebSettings | Where-Object { $_.ConfigurationFileInfo.Exist -eq $false }
        $defaultVariableDetected = $iisConfigurationSettings | Where-Object { $null -ne ($_.Content | Select-String "%ExchangeInstallDir%") }
        $binSearchFoldersNotFound = $iisConfigurationSettings |
            Where-Object { $_.Location -like "*\ClientAccess\ecp\web.config" -and $_.Exist -eq $true -and $_.Valid -eq $true } |
            Where-Object {
                $binSearchFolders = (([xml]($_.Content)).configuration.appSettings.add | Where-Object {
                        $_.key -eq "BinSearchFolders"
                    }).value
                $paths = $binSearchFolders.Split(";").Trim().ToLower()
                $paths | ForEach-Object { Write-Verbose "BinSearchFolder: $($_)" }
                $installPath = $exchangeInformation.RegistryValues.MsiInstallPath
                foreach ($binTestPath in  @("bin", "bin\CmdletExtensionAgents", "ClientAccess\Owa\bin")) {
                    $testPath = [System.IO.Path]::Combine($installPath, $binTestPath).ToLower()
                    Write-Verbose "Testing path: $testPath"
                    if (-not ($paths.Contains($testPath))) {
                        return $_
                    }
                }
            }
        $iisWebSitesWithHstsSettings = $iisWebSettings | Where-Object { $null -ne $_.hsts }

        if ($null -ne $missingWebApplicationConfigFile) {
            $params = $baseParams + @{
                Name                = "Missing Web Application Configuration File"
                DisplayWriteType    = "Red"
                DisplayTestingValue = $true
            }
            Add-AnalyzedResultInformation @params

            foreach ($webApp in $missingWebApplicationConfigFile) {
                $params = $baseParams + @{
                    Details                = "Web Application: '$($webApp.FriendlyName)' Attempting to use config: '$($webApp.ConfigurationFileInfo.Location)'"
                    DisplayWriteType       = "Red"
                    DisplayCustomTabNumber = 2
                    TestingName            = "Web Application: '$($webApp.FriendlyName)'"
                    DisplayTestingValue    = $($webApp.ConfigurationFileInfo.Location)
                }
                Add-AnalyzedResultInformation @params
            }
        }

        if ($null -ne $invalidConfigurationFile) {
            $params = $baseParams + @{
                Name                = "Invalid Configuration File"
                DisplayWriteType    = "Red"
                DisplayTestingValue = $true
            }
            Add-AnalyzedResultInformation @params

            $alreadyDisplayConfigs = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($configFile in $invalidConfigurationFile) {
                if ($alreadyDisplayConfigs.Add($configFile.Location)) {
                    $params = $baseParams + @{
                        Details                = "Invalid: $($configFile.Location)"
                        DisplayWriteType       = "Red"
                        DisplayCustomTabNumber = 2
                        TestingName            = "Invalid: $($configFile.Location)"
                        DisplayTestingValue    = $true
                    }
                    Add-AnalyzedResultInformation @params
                }
            }
        }

        if ($null -ne $missingSharedConfigFile) {
            $params = $baseParams + @{
                Name                = "Missing Shared Configuration File"
                DisplayWriteType    = "Red"
                DisplayTestingValue = $true
            }
            Add-AnalyzedResultInformation @params

            foreach ($file in $missingSharedConfigFile) {
                $params = $baseParams + @{
                    Details                = "Missing: $($file.Location)"
                    DisplayWriteType       = "Red"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }

            $params = $baseParams + @{
                Details                = "More Information: https://aka.ms/HC-MissingConfig"
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        if ($null -ne $missingConfigFiles) {
            $params = $baseParams + @{
                Name                = "Couldn't Find Config File"
                DisplayWriteType    = "Red"
                DisplayTestingValue = $true
            }
            Add-AnalyzedResultInformation @params

            foreach ($file in $missingConfigFiles) {
                $params = $baseParams + @{
                    Details                = "Friendly Name: $($file.FriendlyName)"
                    DisplayWriteType       = "Red"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }
        }

        if ($null -ne $defaultVariableDetected) {
            $params = $baseParams + @{
                Name                = "Default Variable Detected"
                DisplayWriteType    = "Red"
                DisplayTestingValue = $true
            }
            Add-AnalyzedResultInformation @params

            foreach ($file in $defaultVariableDetected) {
                $params = $baseParams + @{
                    Details                = "$($file.Location)"
                    DisplayWriteType       = "Red"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }

            $params = $baseParams + @{
                Details                = "More Information: https://aka.ms/HC-DefaultVariableDetected"
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        if ($null -ne $binSearchFoldersNotFound) {
            $params = $baseParams + @{
                Name                = "Bin Search Folder Not Found"
                DisplayWriteType    = "Red"
                DisplayTestingValue = $true
            }
            Add-AnalyzedResultInformation @params

            foreach ($file in $binSearchFoldersNotFound) {
                $params = $baseParams + @{
                    Details                = "$($file.Location)"
                    DisplayWriteType       = "Red"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }

            $params = $baseParams + @{
                Details                = "More Information: https://aka.ms/HC-BinSearchFolder"
                DisplayWriteType       = "Yellow"
                DisplayCustomTabNumber = 2
            }
            Add-AnalyzedResultInformation @params
        }

        # TODO: Move this check to the new IIS section that we'll add to HC in near future - See issue: 1363
        if (($iisWebSitesWithHstsSettings.Hsts.NativeHstsSettings.enabled -notcontains $true) -and
            ($iisWebSitesWithHstsSettings.Hsts.HstsViaCustomHeader.enabled -notcontains $true)) {
            $params = $baseParams + @{
                Name    = "HSTS Enabled"
                Details = $false
            }
            Add-AnalyzedResultInformation @params
        } else {
            $showAdditionalHstsInformation = $false
            foreach ($webSite in $iisWebSitesWithHstsSettings) {
                $hstsConfiguration = $null
                $isExchangeBackEnd = $webSite.Name -eq "Exchange Back End"
                $hstsMaxAgeWriteType = "Green"

                if (($webSite.Hsts.NativeHstsSettings.enabled) -or
                    ($webSite.Hsts.HstsViaCustomHeader.enabled)) {
                    $params = $baseParams + @{
                        Name                = "HSTS Enabled"
                        Details             = "$($webSite.Name)"
                        TestingName         = "hsts-Enabled-$($webSite.Name)"
                        DisplayTestingValue = $true
                        DisplayWriteType    = if ($isExchangeBackEnd) { "Red" } else { "Green" }
                    }
                    Add-AnalyzedResultInformation @params

                    if ($isExchangeBackEnd) {
                        $showAdditionalHstsInformation = $true
                        $params = $baseParams + @{
                            Details                = "HSTS on 'Exchange Back End' is not supported and can cause issues"
                            DisplayWriteType       = "Red"
                            TestingName            = "hsts-BackendNotSupported"
                            DisplayTestingValue    = $true
                            DisplayCustomTabNumber = 2
                        }
                        Add-AnalyzedResultInformation @params
                    }

                    if (($webSite.Hsts.NativeHstsSettings.enabled) -and
                    ($webSite.Hsts.HstsViaCustomHeader.enabled)) {
                        $showAdditionalHstsInformation = $true
                        Write-Verbose "HSTS conflict detected"
                        $params = $baseParams + @{
                            Details                = ("HSTS configured via customHeader and native IIS control - please remove one configuration" +
                                "`r`n`t`tHSTS native IIS control has a higher weight than the customHeader and will be used")
                            DisplayWriteType       = "Yellow"
                            TestingName            = "hsts-conflict"
                            DisplayTestingValue    = $true
                            DisplayCustomTabNumber = 2
                        }
                        Add-AnalyzedResultInformation @params
                    }

                    if ($webSite.Hsts.NativeHstsSettings.enabled) {
                        Write-Verbose "HSTS configured via native IIS control"
                        $hstsConfiguration = $webSite.Hsts.NativeHstsSettings
                    } else {
                        Write-Verbose "HSTS configured via customHeader"
                        $hstsConfiguration = $webSite.Hsts.HstsViaCustomHeader
                    }

                    $maxAgeValue = $hstsConfiguration.'max-age'
                    if ($maxAgeValue -lt 31536000) {
                        $showAdditionalHstsInformation = $true
                        $hstsMaxAgeWriteType = "Yellow"
                    }
                    $params = $baseParams + @{
                        Details                = "max-age: $maxAgeValue"
                        DisplayWriteType       = $hstsMaxAgeWriteType
                        TestingName            = "hsts-max-age-$($webSite.Name)"
                        DisplayTestingValue    = $maxAgeValue
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params

                    $params = $baseParams + @{
                        Details                = "includeSubDomains: $($hstsConfiguration.includeSubDomains)"
                        TestingName            = "hsts-includeSubDomains-$($webSite.Name)"
                        DisplayTestingValue    = $hstsConfiguration.includeSubDomains
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params

                    $params = $baseParams + @{
                        Details                = "preload: $($hstsConfiguration.preload)"
                        TestingName            = "hsts-preload-$($webSite.Name)"
                        DisplayTestingValue    = $hstsConfiguration.preload
                        DisplayCustomTabNumber = 2
                    }
                    Add-AnalyzedResultInformation @params

                    $redirectHttpToHttpsConfigured = $hstsConfiguration.redirectHttpToHttps
                    $params = $baseParams + @{
                        Details                = "redirectHttpToHttps: $redirectHttpToHttpsConfigured"
                        TestingName            = "hsts-redirectHttpToHttps-$($webSite.Name)"
                        DisplayTestingValue    = $redirectHttpToHttpsConfigured
                        DisplayCustomTabNumber = 2
                    }
                    if ($redirectHttpToHttpsConfigured) {
                        $showAdditionalHstsInformation = $true
                        $params.Add("DisplayWriteType", "Red")
                    }
                    Add-AnalyzedResultInformation @params
                }
            }

            if ($showAdditionalHstsInformation) {
                $params = $baseParams + @{
                    Details                = "`r`n`t`tMore Information about HSTS: https://aka.ms/HC-HSTS"
                    DisplayWriteType       = "Yellow"
                    TestingName            = 'hsts-MoreInfo'
                    DisplayTestingValue    = $true
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }
        }
    } elseif ($null -ne $exchangeInformation.IISSettings.ApplicationHostConfig) {
        Write-Verbose "Wasn't able find any other IIS settings, likely due to application host config file being messed up."
        try {
            [xml]$exchangeInformation.IISSettings.ApplicationHostConfig | Out-Null
            Write-Verbose "Application Host Config file is in a readable file, not sure how we got here."
        } catch {
            Invoke-CatchActions
            Write-Verbose "Confirmed Application Host Config file isn't in a readable xml format."
            $params = $baseParams + @{
                Name                = "Invalid Configuration File"
                Details             = "Application Host Config File: '$($env:WINDIR)\System32\inetSrv\config\applicationHost.config'"
                DisplayWriteType    = "Red"
                TestingName         = "Invalid Configuration File - Application Host Config File"
                DisplayTestingValue = $true
            }
            Add-AnalyzedResultInformation @params
        }
    }
}
