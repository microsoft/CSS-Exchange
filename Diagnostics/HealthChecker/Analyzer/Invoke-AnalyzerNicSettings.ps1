# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
Function Invoke-AnalyzerNicSettings {
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
    $keyNICSettings = Get-DisplayResultsGroupingKey -Name "NIC Settings Per Active Adapter"  -DisplayOrder $Order -DefaultTabNumber 2
    $osInformation = $HealthServerObject.OSInformation
    $hardwareInformation = $HealthServerObject.HardwareInformation

    foreach ($adapter in $osInformation.NetworkInformation.NetworkAdapters) {

        if ($adapter.Description -eq "Remote NDIS Compatible Device") {
            Write-Verbose "Remote NDSI Compatible Device found. Ignoring NIC."
            continue
        }

        $value = "{0} [{1}]" -f $adapter.Description, $adapter.Name
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Interface Description" -Details $value `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayCustomTabNumber 1

        if ($osInformation.BuildInformation.MajorVersion -ge [HealthChecker.OSServerVersion]::Windows2012R2) {
            Write-Verbose "On Windows 2012 R2 or new. Can provide more details on the NICs"

            $driverDate = $adapter.DriverDate
            $detailsValue = $driverDate

            if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or
                $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2) {

                if ($null -eq $driverDate -or
                    $driverDate -eq [DateTime]::MaxValue) {
                    $detailsValue = "Unknown"
                } elseif ((New-TimeSpan -Start $date -End $driverDate).Days -lt [int]-365) {
                    $AnalyzeResults | Add-AnalyzedResultInformation -Details "Warning: NIC driver is over 1 year old. Verify you are at the latest version." `
                        -DisplayGroupingKey $keyNICSettings `
                        -DisplayWriteType "Yellow" `
                        -AddHtmlDetailRow $false
                }
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Driver Date" -Details $detailsValue `
                -DisplayGroupingKey $keyNICSettings

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Driver Version" -Details ($adapter.DriverVersion) `
                -DisplayGroupingKey $keyNICSettings

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "MTU Size" -Details ($adapter.MTUSize) `
                -DisplayGroupingKey $keyNICSettings

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Max Processors" -Details ($adapter.NetAdapterRss.MaxProcessors) `
                -DisplayGroupingKey $keyNICSettings

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Max Processor Number" -Details ($adapter.NetAdapterRss.MaxProcessorNumber) `
                -DisplayGroupingKey $keyNICSettings

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Number of Receive Queues" -Details ($adapter.NetAdapterRss.NumberOfReceiveQueues) `
                -DisplayGroupingKey $keyNICSettings

            $writeType = "Yellow"
            $testingValue = $null

            if ($adapter.RssEnabledValue -eq 0) {
                $detailsValue = "False --- Warning: Enabling RSS is recommended."
                $testingValue = $false
            } elseif ($adapter.RssEnabledValue -eq 1) {
                $detailsValue = "True"
                $testingValue = $true
                $writeType = "Green"
            } else {
                $detailsValue = "No RSS Feature Detected."
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "RSS Enabled" -Details $detailsValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType $writeType `
                -DisplayTestingValue $testingValue
        } else {
            Write-Verbose "On Windows 2012 or older and can't get advanced NIC settings"
        }

        $linkSpeed = $adapter.LinkSpeed
        $displayValue = "{0} --- This may not be accurate due to virtualized hardware" -f $linkSpeed

        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or
            $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2) {
            $displayValue = $linkSpeed
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Link Speed" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayTestingValue $linkSpeed

        $displayValue = "{0}" -f $adapter.IPv6Enabled
        $displayWriteType = "Grey"
        $testingValue = $adapter.IPv6Enabled

        if ($osInformation.NetworkInformation.IPv6DisabledComponents -ne 255 -and
            $adapter.IPv6Enabled -eq $false) {
            $displayValue = "{0} --- Warning" -f $adapter.IPv6Enabled
            $displayWriteType = "Yellow"
            $testingValue = $false
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "IPv6 Enabled" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayWriteType $displayWriteType `
            -DisplayTestingValue $TestingValue

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "IPv4 Address" `
            -DisplayGroupingKey $keyNICSettings

        foreach ($address in $adapter.IPv4Addresses) {
            $displayValue = "{0}\{1}" -f $address.Address, $address.Subnet

            if ($address.DefaultGateway -ne [string]::Empty) {
                $displayValue += " Gateway: {0}" -f $address.DefaultGateway
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Address" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayCustomTabNumber 3
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "IPv6 Address" `
            -DisplayGroupingKey $keyNICSettings

        foreach ($address in $adapter.IPv6Addresses) {
            $displayValue = "{0}\{1}" -f $address.Address, $address.Subnet

            if ($address.DefaultGateway -ne [string]::Empty) {
                $displayValue += " Gateway: {0}" -f $address.DefaultGateway
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Address" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayCustomTabNumber 3
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "DNS Server" -Details $adapter.DnsServer `
            -DisplayGroupingKey $keyNICSettings

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Registered In DNS" -Details $adapter.RegisteredInDns `
            -DisplayGroupingKey $keyNICSettings

        #Assuming that all versions of Hyper-V doesn't allow sleepy NICs
        if (($hardwareInformation.ServerType -ne [HealthChecker.ServerType]::HyperV) -and ($adapter.PnPCapabilities -ne "MultiplexorNoPnP")) {
            $displayWriteType = "Grey"
            $displayValue = $adapter.SleepyNicDisabled

            if (!$adapter.SleepyNicDisabled) {
                $displayWriteType = "Yellow"
                $displayValue = "False --- Warning: It's recommended to disable NIC power saving options`r`n`t`t`tMore Information: https://aka.ms/HC-NICPowerManagement"
            }

            $AnalyzeResults | Add-AnalyzedResultInformation -Name "Sleepy NIC Disabled" -Details $displayValue `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType $displayWriteType `
                -DisplayTestingValue $adapter.SleepyNicDisabled
        }

        $adapterDescription = $adapter.Description
        $cookedValue = 0
        $foundCounter = $false

        if ($null -eq $osInformation.NetworkInformation.PacketsReceivedDiscarded) {
            Write-Verbose "PacketsReceivedDiscarded is null"
            continue
        }

        foreach ($prdInstance in $osInformation.NetworkInformation.PacketsReceivedDiscarded) {
            $instancePath = $prdInstance.Path
            $startIndex = $instancePath.IndexOf("(") + 1
            $charLength = $instancePath.Substring($startIndex, ($instancePath.IndexOf(")") - $startIndex)).Length
            $instanceName = $instancePath.Substring($startIndex, $charLength)
            $possibleInstanceName = $adapterDescription.Replace("#", "_")

            if ($instanceName -eq $adapterDescription -or
                $instanceName -eq $possibleInstanceName) {
                $cookedValue = $prdInstance.CookedValue
                $foundCounter = $true
                break
            }
        }

        $displayWriteType = "Yellow"
        $displayValue = $cookedValue
        $baseDisplayValue = "{0} --- {1}: This value should be at 0."
        $knownIssue = $false

        if ($foundCounter) {

            if ($cookedValue -eq 0) {
                $displayWriteType = "Green"
            } elseif ($cookedValue -lt 1000) {
                $displayValue = $baseDisplayValue -f $cookedValue, "Warning"
            } else {
                $displayWriteType = "Red"
                $displayValue = [string]::Concat(($baseDisplayValue -f $cookedValue, "Error"), "We are also seeing this value being rather high so this can cause a performance impacted on a system.")
            }

            if ($adapterDescription -like "*vmxnet3*" -and
                $cookedValue -gt 0) {
                $knownIssue = $true
            }
        } else {
            $displayValue = "Couldn't find value for the counter."
            $cookedValue = $null
            $displayWriteType = "Grey"
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Packets Received Discarded" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayTestingValue $cookedValue `
            -DisplayWriteType $displayWriteType

        if ($knownIssue) {
            $AnalyzeResults | Add-AnalyzedResultInformation -Details "Known Issue with vmxnet3: 'Large packet loss at the guest operating system level on the VMXNET3 vNIC in ESXi (2039495)' - https://aka.ms/HC-VMwareLostPackets" `
                -DisplayGroupingKey $keyNICSettings `
                -DisplayWriteType "Yellow" `
                -DisplayCustomTabNumber 3 `
                -AddHtmlDetailRow $false
        }
    }

    if ($osInformation.NetworkInformation.NetworkAdapters.Count -gt 1) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details "Multiple active network adapters detected. Exchange 2013 or greater may not need separate adapters for MAPI and replication traffic.  For details please refer to https://aka.ms/HC-PlanHA#network-requirements" `
            -DisplayGroupingKey $keyNICSettings `
            -AddHtmlDetailRow $false
    }

    if ($osInformation.NetworkInformation.IPv6DisabledOnNICs) {
        $displayWriteType = "Grey"
        $displayValue = "True"
        $testingValue = $true

        if ($osInformation.NetworkInformation.IPv6DisabledComponents -eq -1) {
            $displayWriteType = "Red"
            $testingValue = $false
            $displayValue = "False `r`n`t`tError: IPv6 is disabled on some NIC level settings but not correctly disabled via DisabledComponents registry value. It is currently set to '-1'. `r`n`t`tThis setting cause a system startup delay of 5 seconds. For details please refer to: `r`n`t`thttps://aka.ms/HC-ConfigureIPv6"
        } elseif ($osInformation.NetworkInformation.IPv6DisabledComponents -ne 255) {
            $displayWriteType = "Red"
            $testingValue = $false
            $displayValue = "False `r`n`t`tError: IPv6 is disabled on some NIC level settings but not fully disabled. DisabledComponents registry value currently set to '{0}'. For details please refer to the following articles: `r`n`t`thttps://aka.ms/HC-DisableIPv6`r`n`t`thttps://aka.ms/HC-ConfigureIPv6" -f $osInformation.NetworkInformation.IPv6DisabledComponents
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Disable IPv6 Correctly" -Details $displayValue `
            -DisplayGroupingKey $keyNICSettings `
            -DisplayWriteType $displayWriteType `
            -DisplayCustomTabNumber 1
    }
}
