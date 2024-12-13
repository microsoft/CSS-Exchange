# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1
. $PSScriptRoot\..\..\..\Shared\VisualCRedistributableVersionFunctions.ps1
function Invoke-AnalyzerHardwareInformation {
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
    $hardwareInformation = $HealthServerObject.HardwareInformation
    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = (Get-DisplayResultsGroupingKey -Name "Processor/Hardware Information"  -DisplayOrder $Order)
    }

    $params = $baseParams + @{
        Name                  = "Type"
        Details               = $hardwareInformation.ServerType
        AddHtmlOverviewValues = $true
        HtmlName              = "Hardware Type"
    }
    Add-AnalyzedResultInformation @params

    if ($hardwareInformation.ServerType -eq "Physical" -or
        $hardwareInformation.ServerType -eq "AmazonEC2") {
        $params = $baseParams + @{
            Name    = "Manufacturer"
            Details = $hardwareInformation.Manufacturer
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Name    = "Model"
            Details = $hardwareInformation.Model
        }
        Add-AnalyzedResultInformation @params
    }

    $params = $baseParams + @{
        Name    = "Processor"
        Details = $hardwareInformation.Processor.Name
    }
    Add-AnalyzedResultInformation @params

    if ($null -ne $osInformation.PerformanceCounters) {
        $counter = $osInformation.PerformanceCounters | Where-Object { $_.OriginalCounterLookup -eq "\Processor(_Total)\% Processor Time" }

        if ($null -ne $counter) {
            $params = $baseParams + @{
                Name    = "Current Total Processor Usage"
                Details = [System.Math]::Round($counter.CookedValue, 2)
            }
            Add-AnalyzedResultInformation @params
        }
    }

    $numberOfProcessors = $hardwareInformation.Processor.NumberOfProcessors
    $displayWriteType = "Green"
    $displayValue = $numberOfProcessors

    if ($hardwareInformation.ServerType -ne "Physical") {
        $displayWriteType = "Grey"
    } elseif ($numberOfProcessors -gt 2) {
        $displayWriteType = "Red"
        $displayValue = "$numberOfProcessors - Error: Recommended to only have 2 Processors"
    }

    $params = $baseParams + @{
        Name                = "Number of Processors"
        Details             = $displayValue
        DisplayWriteType    = $displayWriteType
        DisplayTestingValue = $numberOfProcessors
    }
    Add-AnalyzedResultInformation @params

    $physicalValue = $hardwareInformation.Processor.NumberOfPhysicalCores
    $logicalValue = $hardwareInformation.Processor.NumberOfLogicalCores
    $physicalValueDisplay = $physicalValue
    $logicalValueDisplay = $logicalValue
    $displayWriteTypeLogic = $displayWriteTypePhysical = "Green"

    if (($logicalValue -gt 24 -and
            $exchangeInformation.BuildInformation.VersionInformation.BuildVersion -lt "15.2.0.0") -or
        $logicalValue -gt 48) {
        $displayWriteTypeLogic = "Red"

        if (($physicalValue -gt 24 -and
                $exchangeInformation.BuildInformation.VersionInformation.BuildVersion -lt "15.2.0.0") -or
            $physicalValue -gt 48) {
            $physicalValueDisplay = "$physicalValue - Error"
            $displayWriteTypePhysical = "Red"
        }

        $logicalValueDisplay = "$logicalValue - Error"
    }

    $params = $baseParams + @{
        Name             = "Number of Physical Cores"
        Details          = $physicalValueDisplay
        DisplayWriteType = $displayWriteTypePhysical
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name                  = "Number of Logical Cores"
        Details               = $logicalValueDisplay
        DisplayWriteType      = $displayWriteTypeLogic
        AddHtmlOverviewValues = $true
    }
    Add-AnalyzedResultInformation @params

    $displayValue = "Disabled"
    $displayWriteType = "Green"
    $displayTestingValue = $false
    $additionalDisplayValue = [string]::Empty
    $additionalWriteType = "Red"

    if ($logicalValue -gt $physicalValue) {

        if ($hardwareInformation.ServerType -ne "HyperV") {
            $displayValue = "Enabled --- Error: Having Hyper-Threading enabled goes against best practices and can cause performance issues. Please disable as soon as possible."
            $displayTestingValue = $true
            $displayWriteType = "Red"
        } else {
            $displayValue = "Enabled --- Not Applicable"
            $displayTestingValue = $true
            $displayWriteType = "Grey"
        }

        if ($hardwareInformation.ServerType -eq "AmazonEC2") {
            $additionalDisplayValue = "Error: For high-performance computing (HPC) application, like Exchange, Amazon recommends that you have Hyper-Threading Technology disabled in their service. More information: https://aka.ms/HC-EC2HyperThreading"
        }

        if ($hardwareInformation.Processor.Name.StartsWith("AMD")) {
            $additionalDisplayValue = "This script may incorrectly report that Hyper-Threading is enabled on certain AMD processors. Check with the manufacturer to see if your model supports SMT."
            $additionalWriteType = "Yellow"
        }
    }

    $params = $baseParams + @{
        Name                = "Hyper-Threading"
        Details             = $displayValue
        DisplayWriteType    = $displayWriteType
        DisplayTestingValue = $displayTestingValue
    }
    Add-AnalyzedResultInformation @params

    if (!([string]::IsNullOrEmpty($additionalDisplayValue))) {
        $params = $baseParams + @{
            Details                = $additionalDisplayValue
            DisplayWriteType       = $additionalWriteType
            DisplayCustomTabNumber = 2
            AddHtmlDetailRow       = $false
        }
        Add-AnalyzedResultInformation @params
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

    $params = $baseParams + @{
        Name                = $name
        Details             = $displayValue
        DisplayWriteType    = $displayWriteType
        DisplayTestingValue = $testingValue
    }
    Add-AnalyzedResultInformation @params

    if ($displayWriteType -ne "Green") {
        $params = $baseParams + @{
            Details                = "More Information: https://aka.ms/HC-NUMA"
            DisplayWriteType       = "Yellow"
            DisplayCustomTabNumber = 2
        }
        Add-AnalyzedResultInformation @params
    }

    $params = $baseParams + @{
        Name    = "Max Processor Speed"
        Details = $hardwareInformation.Processor.MaxMegacyclesPerCore
    }
    Add-AnalyzedResultInformation @params

    if ($hardwareInformation.Processor.ProcessorIsThrottled) {
        $params = $baseParams + @{
            Name                = "Current Processor Speed"
            Details             = "$($hardwareInformation.Processor.CurrentMegacyclesPerCore) --- Error: Processor appears to be throttled."
            DisplayWriteType    = "Red"
            DisplayTestingValue = $hardwareInformation.Processor.CurrentMegacyclesPerCore
        }
        Add-AnalyzedResultInformation @params

        $displayValue = "Error: Power Plan is NOT set to `"High Performance`". This change doesn't require a reboot and takes affect right away. Re-run script after doing so"

        if ($osInformation.PowerPlan.HighPerformanceSet) {
            $displayValue = "Error: Power Plan is set to `"High Performance`", so it is likely that we are throttling in the BIOS of the computer settings."
        }

        $params = $baseParams + @{
            Details             = $displayValue
            DisplayWriteType    = "Red"
            TestingName         = "HighPerformanceSet"
            DisplayTestingValue = $osInformation.PowerPlan.HighPerformanceSet
            AddHtmlDetailRow    = $false
        }
        Add-AnalyzedResultInformation @params
    }

    $totalPhysicalMemory = [System.Math]::Round($hardwareInformation.TotalMemory / 1024 / 1024 / 1024)
    $totalPhysicalMemoryNotRounded = $hardwareInformation.TotalMemory / 1GB
    $displayWriteType = "Yellow"
    $displayDetails = [string]::Empty

    if ($exchangeInformation.BuildInformation.VersionInformation.BuildVersion -ge "15.2.0.0") {

        if ($totalPhysicalMemory -gt 256) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 256 GB of Memory" -f $totalPhysicalMemory
        } elseif ($totalPhysicalMemory -lt 64 -and
            $exchangeInformation.GetExchangeServer.IsEdgeServer -eq $true) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to have a minimum of 64GB of RAM installed on the machine." -f $totalPhysicalMemory
        } elseif ($totalPhysicalMemory -lt 128) {
            $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to have a minimum of 128GB of RAM installed on the machine." -f $totalPhysicalMemory
        } else {
            $displayDetails = "{0} GB" -f $totalPhysicalMemory
            $displayWriteType = "Grey"
        }
    } elseif ($totalPhysicalMemory -gt 192 -and
        $exchangeInformation.BuildInformation.MajorVersion -eq "Exchange2016") {
        $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 192 GB of Memory." -f $totalPhysicalMemory
    } elseif ($totalPhysicalMemory -gt 96 -and
        $exchangeInformation.BuildInformation.MajorVersion -eq "Exchange2013") {
        $displayDetails = "{0} GB `r`n`t`tWarning: We recommend for the best performance to be scaled at or below 96GB of Memory." -f $totalPhysicalMemory
    } else {
        $displayDetails = "{0} GB" -f $totalPhysicalMemory
        $displayWriteType = "Grey"
    }

    $params = $baseParams + @{
        Name                  = "Physical Memory"
        Details               = $displayDetails
        DisplayWriteType      = $displayWriteType
        DisplayTestingValue   = $totalPhysicalMemory
        AddHtmlOverviewValues = $true
    }
    Add-AnalyzedResultInformation @params

    if ($hardwareInformation.ServerType -eq "HyperV" -or
        $hardwareInformation.ServerType -eq "VMware") {
        $params = $baseParams + @{
            Name             = "Dynamic Memory Detected"
            Details          = $false
            DisplayWriteType = "Green"
        }

        if ($null -eq $osInformation.PerformanceCounters) {
            $params.Details = "Unknown - No Performance Counters was able to be collected"
            $params.DisplayWriteType = "Yellow"
        } else {
            if ($hardwareInformation.ServerType -eq "HyperV") {
                $counterName = "\Hyper-V Dynamic Memory Integration Service\Maximum Memory, MBytes"
            } else {
                $counterName = "\VM Memory\Memory Reservation in MB"
            }
            $counter = $osInformation.PerformanceCounters | Where-Object { $_.OriginalCounterLookup -eq $counterName }

            if ($null -eq $counter) {
                $params.Details = "Unknown - Required Counter Not Loaded. Missing Counter: $($counterName)"
                $params.DisplayWriteType = "Yellow"
            } elseif (($counter.CookedValue / 1024) -ne $totalPhysicalMemory -and
            ($counter.CookedValue / 1024) -ne $totalPhysicalMemoryNotRounded) {
                $params.Details = "$true $($counter.CookedValue / 1024)GB is the allowed dynamic memory of the server. Not supported to have dynamic memory configured."
                $params.DisplayWriteType = "Red"
            }
        }

        Add-AnalyzedResultInformation @params
    }
}
