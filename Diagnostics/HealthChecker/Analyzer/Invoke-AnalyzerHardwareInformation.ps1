# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
Function Invoke-AnalyzerHardwareInformation {
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
    $keyHardwareInformation = Get-DisplayResultsGroupingKey -Name "Processor/Hardware Information"  -DisplayOrder $Order
    $exchangeInformation = $HealthServerObject.ExchangeInformation
    $osInformation = $HealthServerObject.OSInformation
    $hardwareInformation = $HealthServerObject.HardwareInformation

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Type" -Details ($hardwareInformation.ServerType) `
        -DisplayGroupingKey $keyHardwareInformation `
        -AddHtmlOverviewValues $true `
        -HtmlName "Hardware Type"

    if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::Physical -or
        $hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Manufacturer" -Details ($hardwareInformation.Manufacturer) `
            -DisplayGroupingKey $keyHardwareInformation

        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Model" -Details ($hardwareInformation.Model) `
            -DisplayGroupingKey $keyHardwareInformation
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Processor" -Details ($hardwareInformation.Processor.Name) `
        -DisplayGroupingKey $keyHardwareInformation

    $value = $hardwareInformation.Processor.NumberOfProcessors
    $processorName = "Number of Processors"

    if ($hardwareInformation.ServerType -ne [HealthChecker.ServerType]::Physical) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name $processorName -Details $value `
            -DisplayGroupingKey $keyHardwareInformation

        <# Comment out for now. Not sure if we have a lot of value here as i believe this changed in newer vmware hosts versions.
        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::VMWare) {
            $AnalyzeResults = Add-AnalyzedResultInformation -Details "Note: Please make sure you are following VMware's performance recommendation to get the most out of your guest machine. VMware blog 'Does corespersocket Affect Performance?' https://blogs.vmware.com/vsphere/2013/10/does-corespersocket-affect-performance.html" `
                -DisplayGroupingKey $keyHardwareInformation `
                -DisplayCustomTabNumber 2 `
                -AnalyzedInformation $AnalyzeResults
        }
    #>
    } elseif ($value -gt 2) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name $processorName -Details ("{0} - Error: Recommended to only have 2 Processors" -f $value) `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -DisplayTestingValue $value `
            -HtmlDetailsCustomValue $value
    } else {
        $AnalyzeResults | Add-AnalyzedResultInformation -Name $processorName -Details $value `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Green"
    }

    $physicalValue = $hardwareInformation.Processor.NumberOfPhysicalCores
    $logicalValue = $hardwareInformation.Processor.NumberOfLogicalCores
    $displayWriteType = "Green"

    if (($logicalValue -gt 24 -and
            $exchangeInformation.BuildInformation.MajorVersion -lt [HealthChecker.ExchangeMajorVersion]::Exchange2019) -or
        $logicalValue -gt 48) {
        $displayWriteType = "Yellow"
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Number of Physical Cores" -Details $physicalValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Number of Logical Cores" -Details $logicalValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -AddHtmlOverviewValues $true

    $displayValue = "Disabled"
    $displayWriteType = "Green"
    $displayTestingValue = $false
    $additionalDisplayValue = [string]::Empty
    $additionalWriteType = "Red"

    if ($logicalValue -gt $physicalValue) {

        if ($hardwareInformation.ServerType -ne [HealthChecker.ServerType]::HyperV) {
            $displayValue = "Enabled --- Error: Having Hyper-Threading enabled goes against best practices and can cause performance issues. Please disable as soon as possible."
            $displayTestingValue = $true
            $displayWriteType = "Red"
        } else {
            $displayValue = "Enabled --- Not Applicable"
            $displayTestingValue = $true
            $displayWriteType = "Grey"
        }

        if ($hardwareInformation.ServerType -eq [HealthChecker.ServerType]::AmazonEC2) {
            $additionalDisplayValue = "Error: For high-performance computing (HPC) application, like Exchange, Amazon recommends that you have Hyper-Threading Technology disabled in their service. More information: https://aka.ms/HC-EC2HyperThreading"
        }

        if ($hardwareInformation.Processor.Name.StartsWith("AMD")) {
            $additionalDisplayValue = "This script may incorrectly report that Hyper-Threading is enabled on certain AMD processors. Check with the manufacturer to see if your model supports SMT."
            $additionalWriteType = "Yellow"
        }
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Hyper-Threading" -Details $displayValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $displayTestingValue

    if (!([string]::IsNullOrEmpty($additionalDisplayValue))) {
        $AnalyzeResults | Add-AnalyzedResultInformation -Details $additionalDisplayValue `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType $additionalWriteType `
            -DisplayCustomTabNumber 2 `
            -AddHtmlDetailRow $false
    }

    #NUMA BIOS CHECK - AKA check to see if we can properly see all of our cores on the box
    $displayWriteType = "Yellow"
    $testingValue = "Unknown"
    $displayValue = [string]::Empty

    if ($hardwareInformation.Model.Contains("ProLiant")) {
        $name = "NUMA Group Size Optimization"

        if ($hardwareInformation.Processor.EnvironmentProcessorCount -eq -1) {
            $displayValue = "Unknown `r`n`t`tWarning: If this is set to Clustered, this can cause multiple types of issues on the server"
        } elseif ($hardwareInformation.Processor.EnvironmentProcessorCount -ne $logicalValue) {
            $displayValue = "Clustered `r`n`t`tError: This setting should be set to Flat. By having this set to Clustered, we will see multiple different types of issues."
            $testingValue = "Clustered"
            $displayWriteType = "Red"
        } else {
            $displayValue = "Flat"
            $testingValue = "Flat"
            $displayWriteType = "Green"
        }
    } else {
        $name = "All Processor Cores Visible"

        if ($hardwareInformation.Processor.EnvironmentProcessorCount -eq -1) {
            $displayValue = "Unknown `r`n`t`tWarning: If we aren't able to see all processor cores from Exchange, we could see performance related issues."
        } elseif ($hardwareInformation.Processor.EnvironmentProcessorCount -ne $logicalValue) {
            $displayValue = "Failed `r`n`t`tError: Not all Processor Cores are visible to Exchange and this will cause a performance impact"
            $displayWriteType = "Red"
            $testingValue = "Failed"
        } else {
            $displayWriteType = "Green"
            $displayValue = "Passed"
            $testingValue = "Passed"
        }
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name $name -Details $displayValue `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayWriteType $displayWriteType `
        -DisplayTestingValue $testingValue

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Max Processor Speed" -Details ($hardwareInformation.Processor.MaxMegacyclesPerCore) `
        -DisplayGroupingKey $keyHardwareInformation

    if ($hardwareInformation.Processor.ProcessorIsThrottled) {
        $currentSpeed = $hardwareInformation.Processor.CurrentMegacyclesPerCore
        $AnalyzeResults | Add-AnalyzedResultInformation -Name "Current Processor Speed" -Details ("{0} --- Error: Processor appears to be throttled." -f $currentSpeed) `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -DisplayTestingValue $currentSpeed

        $displayValue = "Error: Power Plan is NOT set to `"High Performance`". This change doesn't require a reboot and takes affect right away. Re-run script after doing so"

        if ($osInformation.PowerPlan.HighPerformanceSet) {
            $displayValue = "Error: Power Plan is set to `"High Performance`", so it is likely that we are throttling in the BIOS of the computer settings."
        }

        $AnalyzeResults | Add-AnalyzedResultInformation -Details $displayValue `
            -DisplayGroupingKey $keyHardwareInformation `
            -DisplayWriteType "Red" `
            -TestingName "HighPerformanceSet" `
            -DisplayTestingValue $osInformation.PowerPlan.HighPerformanceSet `
            -AddHtmlDetailRow $false
    }

    $totalPhysicalMemory = [System.Math]::Round($hardwareInformation.TotalMemory / 1024 / 1024 / 1024)
    $displayWriteType = "Yellow"
    $displayDetails = [string]::Empty

    if ($exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2019) {

        if ($totalPhysicalMemory -gt 256) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 256 GB of Memory" -f $totalPhysicalMemory
        } elseif ($totalPhysicalMemory -lt 64 -and
            $exchangeInformation.BuildInformation.ServerRole -eq [HealthChecker.ExchangeServerRole]::Edge) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to have a minimum of 64GB of RAM installed on the machine." -f $totalPhysicalMemory
        } elseif ($totalPhysicalMemory -lt 128) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to have a minimum of 128GB of RAM installed on the machine." -f $totalPhysicalMemory
        } else {
            $displayDetails = "{0} GB" -f $totalPhysicalMemory
            $displayWriteType = "Grey"
        }
    } elseif ($totalPhysicalMemory -gt 192 -and
        $exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2016) {
        $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 192 GB of Memory." -f $totalPhysicalMemory
    } elseif ($totalPhysicalMemory -gt 96 -and
        $exchangeInformation.BuildInformation.MajorVersion -eq [HealthChecker.ExchangeMajorVersion]::Exchange2013) {
        $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 96GB of Memory." -f $totalPhysicalMemory
    } else {
        $displayDetails = "{0} GB" -f $totalPhysicalMemory
        $displayWriteType = "Grey"
    }

    $AnalyzeResults | Add-AnalyzedResultInformation -Name "Physical Memory" -Details $displayDetails `
        -DisplayGroupingKey $keyHardwareInformation `
        -DisplayTestingValue $totalPhysicalMemory `
        -DisplayWriteType $displayWriteType `
        -AddHtmlOverviewValues $true
}
