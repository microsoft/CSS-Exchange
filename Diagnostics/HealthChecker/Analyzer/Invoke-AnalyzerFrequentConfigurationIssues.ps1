# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\ValidatorFunctions\Test-IanaTimeZoneMapping.ps1
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

    # cSpell:disable
    $eopDomainRegExPattern = "^[^.]+\.mail\.protection\.(outlook\.com|partner\.outlook\.cn|office365\.us)$"
    $remoteRoutingDomainRegExPattern = "^[^.]+\.mail\.(onmicrosoft\.com|partner\.onmschina\.cn|onmicrosoft\.us)$"
    $serviceDomainRegExPattern = "^mail\.protection\.(outlook\.com|partner\.outlook\.cn|office365\.us)$"
    # cSpell:enable

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

    $detailsValue = $exchangeInformation.RegistryValues.EnableEccCertificateSupport
    $displayWriteType = "Grey"

    if (-not (Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $exchangeInformation.BuildInformation.VersionInformation -SUName "Nov24SU") -and $detailsValue -eq "1") {
        $detailsValue = "1 --- Warning: On a build that doesn't support this configuration yet.`r`n`t`tMore Information: https://aka.ms/HC-EccCertificateChange"
        $displayWriteType = "Yellow"
    }

    $params = $baseParams + @{
        Name             = "EnableEccCertificateSupport Registry Value"
        Details          = $detailsValue
        DisplayWriteType = $displayWriteType
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

    $credGuardRunning = $false
    $credGuardUnknown = $osInformation.CredentialGuardCimInstance -eq "Unknown"

    if (-not ($credGuardUnknown)) {
        # CredentialGuardCimInstance is an array type and not sure if we can have multiple here, so just going to loop thru and handle it this way.
        $credGuardRunning = $null -ne ($osInformation.CredentialGuardCimInstance | Where-Object { $_ -eq 1 })
    }

    $displayValue = $credentialGuardValue = $osInformation.RegistryValues.CredentialGuard -ne 0 -or $credGuardRunning
    $displayWriteType = "Grey"

    if ($credentialGuardValue) {
        $displayValue = "{0} `r`n`t`tError: Credential Guard is not supported on an Exchange Server. This can cause a performance hit on the server." -f $credentialGuardValue
        $displayWriteType = "Red"
    }

    if ($credGuardUnknown -and (-not ($credentialGuardValue))) {
        $displayValue = "Unknown `r`n`t`tWarning: Unable to determine Credential Guard status. If enabled, this can cause a performance hit on the server."
        $displayWriteType = "Yellow"
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

        # Only need to display a particular list all the time. Don't need every config that we want to possibly look at for issues.
        $alwaysDisplayConfigs = @("EdgeTransport.exe.config")
        $skipEdgeOnlyConfigs = @("noderunner.exe.config")
        $keyList = $exchangeInformation.ApplicationConfigFileStatus.Keys | Sort-Object

        foreach ($configKey in $keyList) {

            $configStatus = $exchangeInformation.ApplicationConfigFileStatus[$configKey]
            $fileName = $configStatus.FileName
            $writeType = "Green"
            [string]$writeValue = $configStatus.Present

            if ($exchangeInformation.GetExchangeServer.IsEdgeServer -eq $true -and
                $skipEdgeOnlyConfigs -contains $fileName) {
                continue
            }

            if (-not $configStatus.Present) {
                $writeType = "Red"
                $writeValue += " --- Error"
            }

            $params = $baseParams + @{
                Name             = "$fileName Present"
                Details          = $writeValue
                DisplayWriteType = $writeType
            }

            if ($alwaysDisplayConfigs -contains $fileName -or
                -not $configStatus.Present) {
                Add-AnalyzedResultInformation @params
            }

            # if not a valid configuration file, provide that.
            try {
                if ($configStatus.Present) {
                    $content = [xml]($configStatus.Content)

                    # Additional checks of configuration files.
                    if ($fileName -eq "noderunner.exe.config") {
                        $memoryLimitMegabytes = $content.configuration.nodeRunnerSettings.memoryLimitMegabytes
                        $writeValue = "$memoryLimitMegabytes MB"
                        $writeType = "Green"

                        if ($null -eq $memoryLimitMegabytes) {
                            $writeType = "Yellow"
                            $writeValue = "Unconfigured. This may cause problems."
                        } elseif ($memoryLimitMegabytes -ne 0) {
                            $writeType = "Yellow"
                            $writeValue = "$memoryLimitMegabytes MB will limit the performance of search and can be more impactful than helpful if not configured correctly for your environment."
                        }

                        $params = $baseParams + @{
                            Name             = "NodeRunner.exe memory limit"
                            Details          = $writeValue
                            DisplayWriteType = $writeType
                        }

                        Add-AnalyzedResultInformation @params

                        if ($writeType -ne "Green") {
                            $params = $baseParams + @{
                                Details                = "More Information: https://aka.ms/HC-NodeRunnerMemoryCheck"
                                DisplayWriteType       = "Yellow"
                                DisplayCustomTabNumber = 2
                            }

                            Add-AnalyzedResultInformation @params
                        }
                    }
                }
            } catch {
                $params = $baseParams + @{
                    Name                = "$fileName Invalid Config Format"
                    Details             = "True --- Error: Not able to convert to xml which means it is in an incorrect format that will cause problems with the process."
                    DisplayTestingValue = $true
                    DisplayWriteType    = "Red"
                }

                Add-AnalyzedResultInformation @params
            }
        }
    }

    if ($null -ne $exchangeInformation.IanaTimeZoneMappingsRaw) {

        try {
            [xml]$ianaTimeZoneMappingXml = $exchangeInformation.IanaTimeZoneMappingsRaw

            # Test IanaTimeZoneMapping.xml content to ensure it doesn't contain invalid or duplicate entries
            $ianaTimeZoneMappingStatus = Test-IanaTimeZoneMapping -IanaMappingFile $ianaTimeZoneMappingXml

            $ianaTimeZoneStatusMissingAttributes = $ianaTimeZoneMappingStatus.NodeMissingAttributes
            $ianaTimeZoneStatusDuplicateEntries = $ianaTimeZoneMappingStatus.DuplicateEntries

            $ianaTimeZoneInvalidEntriesList = New-Object System.Collections.Generic.List[string]

            foreach ($invalid in $ianaTimeZoneStatusMissingAttributes) {
                $ianaTimeZoneInvalidEntriesList.Add("[Invalid entry] - IANA: $($invalid.IANA) Win: $($invalid.Win)")
            }

            foreach ($dupe in $ianaTimeZoneStatusDuplicateEntries) {
                $ianaTimeZoneInvalidEntriesList.Add("[Duplicate entry] - IANA: $($dupe.IANA) Win: $($dupe.Win)")
            }

            if ($ianaTimeZoneInvalidEntriesList.Count -ge 1) {
                $params = $baseParams + @{
                    Name             = "IanaTimeZoneMappings.xml invalid"
                    Details          = "`r`n`t`t$([System.String]::Join("`r`n`t`t", $ianaTimeZoneInvalidEntriesList))`r`n`t`tMore information: https://aka.ms/ExchangeIanaTimeZoneIssue"
                    DisplayWriteType = "Red"
                }
                Add-AnalyzedResultInformation @params
            }
        } catch {
            Write-Verbose "Unable to convert IanaTimeZoneMappings.xml to Xml - Exception: $_"
            Invoke-CatchActions
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

    if ($osInformation.RegistryValues.SuppressExtendedProtection -ne 0) {
        $params = $baseParams + @{
            Name             = "SuppressExtendedProtection"
            Details          = "Value set to $($osInformation.RegistryValues.SuppressExtendedProtection), which disables EP resulting it to not work correctly and causes problems. --- ERROR"
            DisplayWriteType = "Red"
        }
        Add-AnalyzedResultInformation @params
    }

    # Detect Send Connector sending to EXO
    $exoConnector = New-Object System.Collections.Generic.List[object]
    $sendConnectors = $exchangeInformation.ExchangeConnectors | Where-Object { $_.ConnectorType -eq "Send" }

    foreach ($sendConnector in $sendConnectors) {
        $smartHostMatch = ($sendConnector.SmartHosts -match $eopDomainRegExPattern).Count -gt 0
        $dnsMatch = $sendConnector.SmartHosts -eq 0 -and ($sendConnector.AddressSpaces.Address -match $remoteRoutingDomainRegExPattern).Count -gt 0

        if ($dnsMatch -or $smartHostMatch) {
            $exoConnector.Add($sendConnector)
        }
    }

    $params = $baseParams + @{
        Name    = "EXO Connector Present"
        Details = ($exoConnector.Count -gt 0)
    }
    Add-AnalyzedResultInformation @params
    $showMoreInfo = $false

    foreach ($connector in $exoConnector) {

        # If CloudServiceMailEnabled is not set to true it means the connector is misconfigured
        # If no Fqdn is set on the connector, the Fqdn of the computer is used to perform best matching certificate selection
        # There is a risk that the Fqdn is an internal one (e.g., server.contoso.local) which will lead to a broken hybrid mail flow in case that TlsCertificateName is not set
        if (($connector.CloudEnabled -eq $false) -or
            ($null -eq $connector.Fqdn -and
            $connector.CertificateDetails.TlsCertificateNameStatus -eq "TlsCertificateNameEmpty")) {
            $params = $baseParams + @{
                Name                   = "Send Connector - $($connector.Identity.ToString())"
                Details                = "Misconfigured to send authenticated internal mail to M365" +
                "`r`n`t`t`tFqdn set: $($null -ne $connector.Fqdn)" +
                "`r`n`t`t`tCloudServicesMailEnabled: $($connector.CloudEnabled)" +
                "`r`n`t`t`tTLSCertificateName set: $($connector.CertificateDetails.TlsCertificateNameStatus -ne "TlsCertificateNameEmpty")"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
            $showMoreInfo = $true
        }

        if ($connector.TlsAuthLevel -ne "DomainValidation" -and
            $connector.TlsAuthLevel -ne "CertificateValidation") {
            $params = $baseParams + @{
                Name                   = "Send Connector - $($connector.Identity.ToString())"
                Details                = "TlsAuthLevel not set to CertificateValidation or DomainValidation"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
            $showMoreInfo = $true
        }

        if ($connector.TlsDomain -notmatch $serviceDomainRegExPattern -and
            $connector.TlsAuthLevel -eq "DomainValidation") {
            $params = $baseParams + @{
                Name                   = "Send Connector - $($connector.Identity.ToString())"
                Details                = "TLSDomain not set to service domain (e.g.,mail.protection.outlook.com)"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }
            Add-AnalyzedResultInformation @params
            $showMoreInfo = $true
        }
    }

    if ($showMoreInfo) {
        $params = $baseParams + @{
            Details                = "More Information: https://aka.ms/HC-ExoConnectorIssue"
            DisplayWriteType       = "Yellow"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    if ($null -ne $exchangeInformation.GetTransportService) {
        if ($exchangeInformation.GetTransportService.MaxPerDomainOutboundConnections -lt 40) {
            $params = $baseParams + @{
                Name             = "MaxPerDomainOutboundConnections"
                Details          = "Value set to $($exchangeInformation.GetTransportService.MaxPerDomainOutboundConnections), which is less than the recommended value of 40. `r`n`t`tMore details: https://aka.ms/HC-TransportRetryConfigCheck"
                DisplayWriteType = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }

        if ($exchangeInformation.GetTransportService.MessageRetryInterval -gt [System.TimeSpan]::FromMinutes(5)) {
            $params = $baseParams + @{
                Name             = "MessageRetryInterval"
                Details          = "Value set to $($exchangeInformation.GetTransportService.MessageRetryInterval), which is greater than the recommended value of 5 minutes. `r`n`t`tMore details: https://aka.ms/HC-TransportRetryConfigCheck"
                DisplayWriteType = "Yellow"
            }
            Add-AnalyzedResultInformation @params
        }
    }

    $edgeKey = $exchangeInformation.ApplicationConfigFileStatus.Keys | Where-Object { $_ -like "*\EdgeTransport.exe.config" }
    $antiMalwareKey = $exchangeInformation.FileContentInformation.Keys | Where-Object { $_ -like "*\Monitoring\Config\AntiMalware.xml" }

    if ($null -ne $edgeKey -and
        $null -ne $antiMalwareKey -and
        $exchangeInformation.ApplicationConfigFileStatus[$edgeKey].Present -and
        $exchangeInformation.FileContentInformation[$antiMalwareKey].Present) {
        $params = $baseParams + @{
            Name             = "UnifiedContent Auto Cleanup Configured"
            Details          = "Unknown"
            DisplayWriteType = "Red"
        }
        try {
            $temporaryStoragePath = (([xml]$exchangeInformation.ApplicationConfigFileStatus[$edgeKey].Content).configuration.appSettings.add |
                    Where-Object { $_.key -eq "TemporaryStoragePath" }).value
            $edgeKeySuccessful = $true
            $cleanupFolderResponderFolderPaths = (([xml]$exchangeInformation.FileContentInformation[$antiMalwareKey].Content).Definition.MaintenanceDefinition.ExtensionAttributes.CleanupFolderResponderFolderPaths)
            $cleanupPathsExists = $cleanupFolderResponderFolderPaths -like "*$temporaryStoragePath\UnifiedContent*"

            if ($cleanupPathsExists) {
                $params.DisplayWriteType = "Green"
            }

            $params.Details = $cleanupPathsExists
            Add-AnalyzedResultInformation @params

            if ($cleanupPathsExists -eq $false) {
                $params = $baseParams + @{
                    Details                = "More Information: https://aka.ms/HC-UnifiedContentCleanup"
                    DisplayWriteType       = "Yellow"
                    DisplayCustomTabNumber = 2
                }
                Add-AnalyzedResultInformation @params
            }
        } catch {
            if ($edgeKeySuccessful) {
                $params.Details = "AntiMalware.xml Invalid Config Format"
            } else {
                $params.Details = "Error - EdgeTransport.exe.config Invalid Config Format"
            }
            Add-AnalyzedResultInformation @params
        }
    }
}
