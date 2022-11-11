# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
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
    $tcpKeepAlive = $osInformation.NetworkInformation.TCPKeepAlive
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
        Details             = "$($osInformation.NetworkInformation.RpcMinConnectionTimeout) `r`n`t`tMore Information: https://aka.ms/HC-RPCSetting"
        DisplayTestingValue = $osInformation.NetworkInformation.RpcMinConnectionTimeout
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
        DisplayTestingValue = $true
    }
    Add-AnalyzedResultInformation @params

    $displayValue = $osInformation.CredentialGuardEnabled
    $displayWriteType = "Grey"

    if ($osInformation.CredentialGuardEnabled) {
        $displayValue = "{0} `r`n`t`tError: Credential Guard is not supported on an Exchange Server. This can cause a performance hit on the server." -f $osInformation.CredentialGuardEnabled
        $displayWriteType = "Red"
    }

    $params = $baseParams + @{
        Name                = "Credential Guard Enabled"
        Details             = $displayValue
        DisplayTestingValue = $osInformation.CredentialGuardEnabled
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

    $displayWriteType = "Grey"
    $displayValue = "Not Set"
    $additionalDisplayValue = [string]::Empty

    if ($null -ne $organizationInformation.WildCardAcceptedDomain) {

        if ($organizationInformation.WildCardAcceptedDomain -eq "Unknown") {
            $displayValue = "Unknown - Unable to run Get-AcceptedDomain"
            $displayWriteType = "Yellow"
        } else {
            $displayWriteType = "Red"
            $domain = $organizationInformation.WildCardAcceptedDomain
            $displayValue = "Error --- Accepted Domain `"$($domain.Id)`" is set to a Wild Card (*) Domain Name with a domain type of $($domain.DomainType.ToString()). This is not recommended as this is an open relay for the entire environment.`r`n`t`tMore Information: https://aka.ms/HC-OpenRelayDomain"

            if ($domain.DomainType.ToString() -eq "InternalRelay" -and
                (($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016 -and
                    $exchangeInformation.BuildInformation.CU -ge [HealthChecker.ExchangeCULevel]::CU22) -or
                ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019 -and
                $exchangeInformation.BuildInformation.CU -ge [HealthChecker.ExchangeCULevel]::CU11))) {

                $additionalDisplayValue = "`r`n`t`tERROR: You have an open relay set as Internal Replay Type and on a CU that is known to cause issues with transport services crashing. Follow the above article for more information."
            } elseif ($domain.DomainType.ToString() -eq "InternalRelay") {
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

    if ($null -ne $exchangeInformation.IISSettings.IISConfigurationSettings) {
        $iisConfigurationSettings = $exchangeInformation.IISSettings.IISConfigurationSettings |
            Where-Object {
                if ($exchangeInformation.BuildInformation.MajorVersion -ge [HealthChecker.ExchangeMajorVersion]::Exchange2016 -or
                    $exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::MultiRole) {
                    return $_
                } elseif ($exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::Mailbox -and
                    $_.Location -like "*ClientAccess*") {
                    return $_
                } elseif ($exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::ClientAccess -and
                    $_.Location -like "*FrontEnd\HttpProxy*") {
                    return $_
                }
            } |
            Where-Object {
                # these are locations that don't by default have configuration files.
                $_.Location -notlike "*\ClientAccess\web.config" -and $_.Location -notlike "*\ClientAccess\exchweb\EWS\bin\web.config" -and
                $_.Location -notlike "*\ClientAccess\Autodiscover\bin\web.config" -and $_.Location -notlike "*\ClientAccess\Autodiscover\help\web.config"
            }

        $missingConfigFile = $iisConfigurationSettings | Where-Object { $_.Exist -eq $false }
        $defaultVariableDetected = $iisConfigurationSettings | Where-Object { $null -ne ($_.Content | Select-String "%ExchangeInstallDir%") }
        $binSearchFoldersNotFound = $iisConfigurationSettings |
            Where-Object { $_.Location -like "*\ClientAccess\ecp\web.config" -and $_.Exist -eq $true } |
            Where-Object {
                $binSearchFolders = $_.Content | Select-String "BinSearchFolders" | Select-Object -ExpandProperty Line
                $startIndex = $binSearchFolders.IndexOf("value=`"") + 7
                $paths = $binSearchFolders.Substring($startIndex, $binSearchFolders.LastIndexOf("`"") - $startIndex).Split(";").Trim().ToLower()
                $paths | ForEach-Object { Write-Verbose "BinSearchFolder: $($_)" }
                $installPath = $exchangeInformation.RegistryValues.MisInstallPath
                foreach ($binTestPath in  @("bin", "bin\CmdletExtensionAgents", "ClientAccess\Owa\bin")) {
                    $testPath = [System.IO.Path]::Combine($installPath, $binTestPath).ToLower()
                    Write-Verbose "Testing path: $testPath"
                    if (-not ($paths.Contains($testPath))) {
                        return $_
                    }
                }
            }

        if ($null -ne $missingConfigFile) {
            $params = $baseParams + @{
                Name                = "Missing Configuration File"
                DisplayWriteType    = "Red"
                DisplayTestingValue = $true
            }
            Add-AnalyzedResultInformation @params

            foreach ($file in $missingConfigFile) {
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
    }
}
