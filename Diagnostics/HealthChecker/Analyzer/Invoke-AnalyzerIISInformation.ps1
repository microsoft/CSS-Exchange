﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\Get-IISAuthenticationType.ps1
. $PSScriptRoot\Get-IPFilterSetting.ps1
. $PSScriptRoot\Get-URLRewriteRule.ps1
function Invoke-AnalyzerIISInformation {
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
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = (Get-DisplayResultsGroupingKey -Name "Exchange IIS Information"  -DisplayOrder $Order)
    }

    if ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $true) {
        Write-Verbose "No IIS information to review on an Edge Server"
        return
    }

    if ($null -eq $exchangeInformation.IISSettings.IISWebApplication -and
        $null -eq $exchangeInformation.IISSettings.IISWebSite -and
        $null -eq $exchangeInformation.IISSettings.IISSharedWebConfig) {
        Write-Verbose "Wasn't able find any other IIS settings, likely due to application host config file being messed up."

        if ($null -ne $exchangeInformation.IISSettings.ApplicationHostConfig) {
            Write-Verbose "Wasn't able find any other IIS settings, likely due to application host config file being messed up."
            try {
                [xml]$exchangeInformation.IISSettings.ApplicationHostConfig | Out-Null
                Write-Verbose "Application Host Config file is in a readable file, not sure how we got here."
                $displayIISIssueToReport = $true
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
        } else {
            Write-Verbose "No application host config file was collected either. not sure how we got here."
            $displayIISIssueToReport = $true
        }

        if ($displayIISIssueToReport) {
            $params = $baseParams + @{
                Name             = "Unknown IIS configuration"
                Details          = "Please report this to ExToolsFeedback@microsoft.com"
                DisplayWriteType = "Red"
            }
            Add-AnalyzedResultInformation @params
        }
        # Nothing to process if we don't have the information.
        return
    }

    ###################################
    # IIS Web Sites - Standard Display
    ###################################

    Write-Verbose "Working on IIS Web Sites"
    $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]
    $iisWebSites = $exchangeInformation.IISSettings.IISWebSite | Sort-Object ID
    $bindingsPropertyName = "Protocol - Bindings - Certificate"

    foreach ($webSite in $iisWebSites) {
        $protocolLength = 0
        $bindingInformationLength = 0

        $webSite.Bindings.Protocol |
            ForEach-Object { if ($protocolLength -lt $_.Length) { $protocolLength = $_.Length } }
        $webSite.Bindings.bindingInformation |
            ForEach-Object { if ($bindingInformationLength -lt $_.Length) { $bindingInformationLength = $_.Length } }

        $hstsEnabled = $webSite.Hsts.NativeHstsSettings.enabled -eq $true -or $webSite.Hsts.HstsViaCustomHeader.enabled -eq $true

        $value = @($webSite.Bindings | ForEach-Object {
                $certHash = $(if ($null -ne $_.certificateHash) { $_.certificateHash } else { "NULL" })
                $pSpace = [string]::Empty
                $biSpace = [string]::Empty
                1..(($protocolLength - $_.Protocol.Length) + 1) | ForEach-Object { $pSpace += " " }
                1..(($bindingInformationLength - $_.bindingInformation.Length) + 1 ) | ForEach-Object { $biSpace += " " }
                return "$($_.Protocol)$($pSpace)- $($_.bindingInformation)$($biSpace)- $certHash"
            })

        $outputObjectDisplayValue.Add([PSCustomObject]@{
                Name                  = $webSite.Name
                State                 = $webSite.State
                "HSTS Enabled"        = $hstsEnabled
                $bindingsPropertyName = $value
            })
    }

    #Used for Web App Pools as well
    $sbStarted = { param($o, $p) if ($p -eq "State") { if ($o."$p" -eq "Started") { "Green" } else { "Red" } } }

    $params = $baseParams + @{
        OutColumns       = ([PSCustomObject]@{
                DisplayObject      = $outputObjectDisplayValue
                ColorizerFunctions = @($sbStarted)
                IndentSpaces       = 8
            })
        AddHtmlDetailRow = $false
    }
    Add-AnalyzedResultInformation @params

    ########################
    # IIS Web Sites - Issues
    ########################

    if (($iisWebSites.Hsts.NativeHstsSettings.enabled -notcontains $true) -and
        ($iisWebSites.Hsts.HstsViaCustomHeader.enabled -notcontains $true)) {
        Write-Verbose "Skipping over HSTS issues, as it isn't enabled"
    } else {
        $showAdditionalHstsInformation = $false

        foreach ($webSite in $iisWebSites) {
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

    ########################
    # IIS Web App Pools
    ########################

    Write-Verbose "Working on Exchange Web App GC Mode"

    $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]

    foreach ($webAppKey in $exchangeInformation.ApplicationPools.Keys) {

        $appPool = $exchangeInformation.ApplicationPools[$webAppKey]
        $appRestarts = $appPool.AppSettings.add.recycling.periodicRestart
        $appRestartSet = ($appRestarts.PrivateMemory -ne "0" -or
            $appRestarts.Memory -ne "0" -or
            $appRestarts.Requests -ne "0" -or
            $null -ne $appRestarts.Schedule -or
            ($appRestarts.Time -ne "00:00:00" -and
                ($webAppKey -ne "MSExchangeOWAAppPool" -and
            $webAppKey -ne "MSExchangeECPAppPool")))

        $outputObjectDisplayValue.Add(([PSCustomObject]@{
                    AppPoolName         = $webAppKey
                    State               = $appPool.AppSettings.state
                    GCServerEnabled     = $appPool.GCServerEnabled
                    RestartConditionSet = $appRestartSet
                })
        )
    }

    $sbRestart = { param($o, $p) if ($p -eq "RestartConditionSet") { if ($o."$p") { "Red" } else { "Green" } } }
    $params = $baseParams + @{
        OutColumns       = ([PSCustomObject]@{
                DisplayObject      = $outputObjectDisplayValue
                ColorizerFunctions = @($sbStarted, $sbRestart)
                IndentSpaces       = 8
            })
        AddHtmlDetailRow = $false
    }
    Add-AnalyzedResultInformation @params

    $periodicStartAppPools = $outputObjectDisplayValue | Where-Object { $_.RestartConditionSet -eq $true }

    if ($null -ne $periodicStartAppPools) {

        $outputObjectDisplayValue = New-Object System.Collections.Generic.List[object]

        foreach ($appPool in $periodicStartAppPools) {
            $periodicRestart = $exchangeInformation.ApplicationPools[$appPool.AppPoolName].AppSettings.add.recycling.periodicRestart
            $schedule = $periodicRestart.Schedule

            if ([string]::IsNullOrEmpty($schedule)) {
                $schedule = "null"
            }

            $outputObjectDisplayValue.Add(([PSCustomObject]@{
                        AppPoolName   = $appPool.AppPoolName
                        PrivateMemory = $periodicRestart.PrivateMemory
                        Memory        = $periodicRestart.Memory
                        Requests      = $periodicRestart.Requests
                        Schedule      = $schedule
                        Time          = $periodicRestart.Time
                    }))
        }

        $sbColorizer = {
            param($o, $p)
            switch ($p) {
                { $_ -in "PrivateMemory", "Memory", "Requests" } {
                    if ($o."$p" -eq "0") { "Green" } else { "Red" }
                }
                "Time" {
                    if ($o."$p" -eq "00:00:00") { "Green" } else { "Red" }
                }
                "Schedule" {
                    if ($o."$p" -eq "null") { "Green" } else { "Red" }
                }
            }
        }

        $params = $baseParams + @{
            OutColumns       = ([PSCustomObject]@{
                    DisplayObject      = $outputObjectDisplayValue
                    ColorizerFunctions = @($sbColorizer)
                    IndentSpaces       = 8
                })
            AddHtmlDetailRow = $false
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Details          = "Error: The above app pools currently have the periodic restarts set. This restart will cause disruption to end users."
            DisplayWriteType = "Red"
            AddHtmlDetailRow = $false
        }
        Add-AnalyzedResultInformation @params
    }

    ########################################
    # Virtual Directories - Standard display
    ########################################

    $applicationHostConfig = $exchangeInformation.IISSettings.ApplicationHostConfig
    $iisWebSettings = @($exchangeInformation.IISSettings.IISWebApplication)
    $iisWebSettings += @($exchangeInformation.IISSettings.IISWebSite)
    $iisConfigurationSettings = @($exchangeInformation.IISSettings.IISWebApplication.ConfigurationFileInfo)
    $iisConfigurationSettings += $iisWebSiteConfigs = @($exchangeInformation.IISSettings.IISWebSite.ConfigurationFileInfo)
    $iisConfigurationSettings += @($exchangeInformation.IISSettings.IISSharedWebConfig)
    $extendedProtectionConfiguration = $exchangeInformation.ExtendedProtectionConfig.ExtendedProtectionConfiguration
    $displayMainSitesList = @("Default Web Site", "API", "Autodiscover", "ecp", "EWS", "mapi", "Microsoft-Server-ActiveSync", "OAB", "owa",
        "PowerShell", "Rpc", "Exchange Back End", "emsmdb", "nspi", "RpcWithCert")
    $iisVirtualDirectoriesDisplay = New-Object 'System.Collections.Generic.List[System.Object]'
    $iisWebConfigContent = @{}
    $iisLocations = ([xml]$applicationHostConfig).configuration.Location | Sort-Object Path

    $iisWebSettings | ForEach-Object {
        $key = if ($null -ne $_.FriendlyName) { $_.FriendlyName } else { $_.Name }
        $iisWebConfigContent.Add($key, $_.ConfigurationFileInfo.Content)
    }

    $ruleParams = @{
        ApplicationHostConfig = [xml]$applicationHostConfig
        WebConfigContent      = $iisWebConfigContent
    }

    $urlRewriteRules = Get-URLRewriteRule @ruleParams
    $ipFilterSettings = Get-IPFilterSetting -ApplicationHostConfig ([xml]$applicationHostConfig)
    $authTypeSettings = Get-IISAuthenticationType -ApplicationHostConfig ([xml]$applicationHostConfig)
    $failedLocationsForAuth = @()
    Write-Verbose "Evaluating the IIS Locations for display"

    foreach ($location in $iisLocations) {

        if ([string]::IsNullOrEmpty($location.Path)) { continue }

        if ($displayMainSitesList -notcontains ($location.Path.Split("/")[-1])) { continue }

        Write-Verbose "Working on IIS Path: $($location.Path)"
        $sslFlag = [string]::Empty
        $displayRewriteRules = [string]::Empty
        #TODO: This is not 100% accurate because you can have a disabled rule here.
        # However, not sure how common this is going to be so going to ignore this for now.
        $ipFilterEnabled = $ipFilterSettings[$location.Path].Count -ne 0
        $epValue = "None"
        $ep = $extendedProtectionConfiguration | Where-Object { $_.VirtualDirectoryName -eq $location.Path }
        $currentRewriteRules = $urlRewriteRules[$location.Path]
        $authentication = $authTypeSettings[$location.Path]

        if ($currentRewriteRules.Count -ne 0) {
            # Need to loop through all the rules first to find the excluded rules
            # then find the rules to display
            $excludeRules = @()
            foreach ($rule in $currentRewriteRules) {
                $remove = $rule.Remove

                if ($null -ne $remove) {
                    $excludeRules += $remove.Name
                }
            }

            $displayRewriteRules = ($currentRewriteRules.rule | Where-Object { $_.enabled -ne "false" }).name |
                Where-Object { $_ -notcontains $excludeRules }
        }

        if ($null -ne $ep) {
            Write-Verbose "Using EP settings to determine sslFlags"
            $sslSettings = $ep.Configuration.SslSettings
            $sslFlag = "$($sslSettings.RequireSSL) $(if($sslSettings.Ssl128Bit) { "(128-bit)" })".Trim()

            if ($sslSettings.ClientCertificate -ne "Ignore") {
                $sslFlag = @($sslFlag, "Cert($($sslSettings.ClientCertificate))")
            }

            $epValue = $ep.ExtendedProtection
        } else {
            Write-Verbose "Not using EP settings to determine sslFlags, skipping over cert auth logic."
            $ssl = $location.'system.webServer'.security.access.SslFlags
            $sslFlag = "$($ssl -contains "ssl") $(if(($ssl -contains "ssl128")) { "(128-bit)" })".Trim()
        }

        $iisVirtualDirectoriesDisplay.Add([PSCustomObject]@{
                Name               = $location.Path
                ExtendedProtection = $epValue
                SslFlags           = $sslFlag
                IPFilteringEnabled = $ipFilterEnabled
                URLRewrite         = $displayRewriteRules
                Authentication     = $authentication
            })
    }

    $params = $baseParams + @{
        OutColumns       = ([PSCustomObject]@{
                DisplayObject = $iisVirtualDirectoriesDisplay
                IndentSpaces  = 8
            })
        AddHtmlDetailRow = $false
    }
    Add-AnalyzedResultInformation @params

    if ($failedLocationsForAuth.Count -gt 0) {
        $params = $baseParams + @{
            Name             = "Inaccurate display of authentication types"
            Details          = $failedLocationsForAuth -join ","
            DisplayWriteType = "Yellow"
        }

        Add-AnalyzedResultInformation @params
    }

    ###############################
    # Virtual Directories - Issues
    ###############################

    # Invalid configuration files are ones that we can't convert to xml.
    $invalidConfigurationFile = $iisConfigurationSettings | Where-Object { $_.Valid -eq $false -and $_.Exist -eq $true }
    # If a web application config file doesn't truly exists, we end up using the parent web.config file
    # If any of the web application config file paths match a parent path, that is a problem.
    # only collect the ones that are valid, if not valid we will assume that the child web apps will point to it and can be misleading.
    $siteConfigPaths = $iisWebSiteConfigs |
        Where-Object { $_.Valid -eq $true -and $_.Exist -eq $true } |
        ForEach-Object { $_.Location }

    if ($null -ne $siteConfigPaths) {
        $missingWebApplicationConfigFile = $exchangeInformation.IISSettings.IISWebApplication |
            Where-Object { $siteConfigPaths -contains "$($_.ConfigurationFileInfo.Location)" }
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
            $paths = $binSearchFolders.Split(";").Trim()
            $paths | ForEach-Object { Write-Verbose "BinSearchFolder: $($_)" }
            $installPath = $exchangeInformation.RegistryValues.MsiInstallPath
            foreach ($binTestPath in  @("bin", "bin\CmdletExtensionAgents", "ClientAccess\Owa\bin")) {
                $testPath = [System.IO.Path]::Combine($installPath, $binTestPath)
                Write-Verbose "Testing path: $testPath"
                if (-not ($paths -contains $testPath)) {
                    return $_
                }
            }
        }

    # Display URL Rewrite Rules.
    # To save on space, don't display rules that are on multiple vDirs by same name.
    # Use 'DisplayKey' for the display results.
    $alreadyDisplayedUrlRewriteRules = @{}
    $alreadyDisplayedUrlKey = "DisplayKey"
    $alreadyDisplayedUrlRewriteRules.Add($alreadyDisplayedUrlKey, (New-Object System.Collections.Generic.List[object]))

    foreach ($key in $urlRewriteRules.Keys) {
        $currentSection = $urlRewriteRules[$key]

        if ($currentSection.Count -ne 0) {
            foreach ($rule in $currentSection.rule) {

                if ($null -eq $rule) {
                    Write-Verbose "Rule is NULL skipping."
                    continue
                } elseif ($rule.enabled -eq "false") {
                    # skip over disabled rules.
                    Write-Verbose "skipping over disabled rule: $($rule.Name) for vDir '$key'"
                    continue
                }

                #multiple match type possibilities, but should only be one per rule.
                $propertyType = ($rule.match | Get-Member | Where-Object { $_.MemberType -eq "Property" }).Name
                $matchProperty = "$propertyType - $($rule.match.$propertyType)"

                $displayObject = [PSCustomObject]@{
                    RewriteRuleName = $rule.name
                    Pattern         = $rule.conditions.add.pattern
                    MatchProperty   = $matchProperty
                    ActionType      = $rule.action.type
                }

                #.ContainsValue() and .ContainsKey() doesn't find the complex object it seems. Need to find it by a key and a simple name.
                if (-not ($alreadyDisplayedUrlRewriteRules.ContainsKey((($displayObject.RewriteRuleName))))) {
                    $alreadyDisplayedUrlRewriteRules.Add($displayObject.RewriteRuleName, $displayObject)
                    $alreadyDisplayedUrlRewriteRules[$alreadyDisplayedUrlKey].Add($displayObject)
                }
            }
        }
    }

    if ($alreadyDisplayedUrlRewriteRules[$alreadyDisplayedUrlKey].Count -gt 0) {
        $params = $baseParams + @{
            OutColumns       = ([PSCustomObject]@{
                    DisplayObject = $alreadyDisplayedUrlRewriteRules[$alreadyDisplayedUrlKey]
                    IndentSpaces  = 8
                })
            AddHtmlDetailRow = $false
        }
        Add-AnalyzedResultInformation @params
    }

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

    ########################
    # IIS Module Information
    ########################

    Write-Verbose "Working on IIS Module information"

    # If TokenCacheModule is not loaded, we highlight that it could be added back again as Windows provided a fix to address CVE-2023-36434 (also tracked as CVE-2023-21709)
    if ($null -eq $exchangeInformation.IISSettings.IISModulesInformation.ModuleList.Name) {
        Write-Verbose "Module List is null, unable to provide accurate check for this."
    } elseif ($exchangeInformation.IISSettings.IISModulesInformation.ModuleList.Name -notcontains "TokenCacheModule") {
        Write-Verbose "TokenCacheModule wasn't detected (vulnerability mitigated) and as a result, system is not vulnerable to CVE-2023-21709 / CVE-2023-36434"

        $params = $baseParams + @{
            Name                = "TokenCacheModule loaded"
            Details             = ("$false
                `r`t`tThe module wasn't found and as a result, CVE-2023-21709 and CVE-2023-36434 are mitigated. Windows has released a Security Update that addresses the vulnerability.
                `r`t`tIt should be installed on all Exchange servers and then, the TokenCacheModule can be added back to IIS (by running .\CVE-2023-21709.ps1 -Rollback).
                `r`t`tMore Information: https://aka.ms/CVE-2023-21709ScriptDoc"
            )
            DisplayWriteType    = "Yellow"
            AddHtmlDetailRow    = $true
            DisplayTestingValue = $true
        }
        Add-AnalyzedResultInformation @params
    }
}
