# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function global:New-ExPerfWiz {
    <#

    .SYNOPSIS
    Creates a data collector set for investigating performance related issues.

    .DESCRIPTION
    Creates a performance monitor data collector set from an XML template for the purpose of investigating server performance issues.

    Allows for configuration of the counter set at the time of running the creation command.

    Will overwrite any existing Counter Sets that have the same name.

    .PARAMETER Circular
    Enabled or Disable circular logging

    Default is false (Disabled)

    .PARAMETER Duration
    Sets how long should the performance data be collected
    Provided in time span format hh:mm:ss

    Default is 8 hours (08:00:00)

    .PARAMETER FolderPath
    Output Path for performance logs.
    The folder path should exist.

    This parameter is required.

    .PARAMETER Interval
    How often the performance data should be collected.

    Default is 5s (5)

    .PARAMETER MaxSize
    Maximum size of the PerfMon log in MegaBytes
    Default is 1024MB

    .PARAMETER Name
    The name of the data collector set

    Default is Exchange_PerfWiz

    .PARAMETER Server
    Name of the server where the PerfMon collector should be created

    Default is Localhost

    .PARAMETER StartOnCreate
    Starts the counter set as soon as it is created

    Default is False

    .PARAMETER Template
    XML PerfMon template file that should be loaded to create the data collector set.

    Default is to prompt to select a Template from the XMLs provided with this module.

    .PARAMETER Threads
    Includes threads in the counter set.
    *** Including Threads significantly increase the size of PerfMon data ***

    Default is False

    .PARAMETER StartTime
    Time of day to start the data collector set
    It will start at this time EVERY day until removed.

    Default is <not set>

    .OUTPUTS
    Creates a data collector set in PerfMon based on the provided XML file

    Logs all activity into $env:LOCALAPPDATA\ExPerfWiz.log file

    .EXAMPLE
    Create a standard ExPerfWiz data collector for troubleshooting performance issues on the local machine.

    New-ExPerfWiz -FolderPath C:\PerfData

    This will prompt the end user to select a template from the provided set and create a default data collector set using that Template.
    The PerfMon data will be stored in the C:\PerfData folder

    .EXAMPLE
    Create a custom ExPerfWiz data collector on the local machine from a custom template

    New-ExPerfWiz -Name "My Collector" -Duration "01:00:00" -Interval 1 -MaxSize 500 -Template C:\Temp\MyTemplate.xml -Circular $true -Threads $True

    Creates a collector named "My Collector" From the template MyTemplate.xml.
    Circular logging will be enabled along with Threads.
    When started the collector will run for 1 hour.
    It will have a maximum file size of 500MB

    .EXAMPLE
    Create an ExPerfWiz data collector on another server

    New-ExPerfWiz -FolderPath C:\temp\ExPerfWiz -Server OtherServer-01

    Will prompt for template to use.
    Will create a PerfMon counter set on the remove server OtherServer-01 with the output folder being C:\temp\ExPerfWiz on that server

    #>

    ### Creates a new ExPerfWiz collector
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]
        $Circular,

        [TimeSpan]
        $Duration = [TimeSpan]::Parse('8:00:00'),

        [Parameter(Mandatory = $true, HelpMessage = "Please provide a valid folder path for output")]
        [string]
        $FolderPath,

        [int]
        $Interval = 5,

        [int]
        $MaxSize = 1024,

        [string]
        $Name = "Exchange_PerfWiz",

        [Parameter(ValueFromPipeline)]
        [string]
        $Server = $env:ComputerName,

        [switch]
        $StartOnCreate,

        [string]
        $Template,

        [switch]
        $Threads = $false,

        [string]
        $StartTime

    )

    begin {
        # Check for new version of ExPerfWiz
    }

    process {

        # If no template provided then we use the default one
        if ([string]::IsNullOrEmpty($Template)) {
            Write-SimpleLogFile "Using default template" -Name "ExPerfWiz.log"

            # Put the default xml into template
            $Template = Join-Path $env:LOCALAPPDATA "Exch_13_16_19_Full.xml"
        }

        # Test the template path and log it as good or throw an error
        if (Test-Path $Template) {
            Write-SimpleLogFile -string ("Using Template:" + $Template) -Name "ExPerfWiz.log"
        } else {
            throw "Cannot find template xml file provided.  Please provide a valid PerfMon template file. $Template"
        }

        ### Manipulate Template ###

        # Load the provided template
        [xml]$XML = Get-Content $Template

        # Set Output Location
        $XML.DataCollectorSet.OutputLocation = $FolderPath
        $XML.DataCollectorSet.RootPath = $FolderPath
        $XML.DataCollectorSet.Subdirectory = ($Name -replace '\s+', '')
        $XML.DataCollectorSet.PerformanceCounterDataCollector.Filename = ($Name -replace '\s+', '')
        $XML.DataCollectorSet.PerformanceCounterDataCollector.Name = ($Name -replace '\s+', '')

        # Set overall Duration
        $XML.DataCollectorSet.Duration = [string]$Duration.TotalSeconds

        # Set segment to restart when limit reached
        $XML.DataCollectorSet.Segment = "-1"

        # Make sure segment duration is NOT set we want overall duration to win here
        $XML.DataCollectorSet.SegmentMaxDuration = "0"

        # Set Max File size
        $XML.DataCollectorSet.SegmentMaxSize = [string]$MaxSize

        # Circular logging state
        if ($Circular) {
            $XML.DataCollectorSet.PerformanceCounterDataCollector.LogCircular = "1"
            $XML.DataCollectorSet.PerformanceCounterDataCollector.LogAppend = "1"
            $XML.DataCollectorSet.PerformanceCounterDataCollector.Filename = (($Name -replace '\s+', '') + "_Circular")
        }
        # Need to update the file name to reflect if it is circular
        else {
            $XML.DataCollectorSet.PerformanceCounterDataCollector.LogCircular = "0"
            $XML.DataCollectorSet.PerformanceCounterDataCollector.LogAppend = "0"
        }

        # Sample Interval
        $XML.DataCollectorSet.PerformanceCounterDataCollector.SampleInterval = [string]$Interval

        # Make sure the XML schedule is set to reflect if we are setting up a scheduled task
        if ($PSBoundParameters.ContainsKey("StartTime".ToLower())) {
            $XML.DataCollectorSet.SchedulesEnabled = "1"
            # Set the schedule date and time to reflect the values in the scheduled task
            $XML.DataCollectorSet.Schedule.StartDate = (Get-Date -Format MM\/dd\/yyyy).ToString()
            $XML.DataCollectorSet.Schedule.EndDate = (Get-Date -Day 1 -Month 1 -Year 2100 -Format MM\/dd\/yyyy).ToString()
            $XML.DataCollectorSet.Schedule.StartTime = (Get-Date $StartTime -Format HH:mm).ToString()
        } else {
            $XML.DataCollectorSet.SchedulesEnabled = "0"
            # Since not schedule we are going to set the date / time to 1900
            $XML.DataCollectorSet.Schedule.StartDate = (Get-Date -Day 1 -Month 1 -Year 1900 -Format MM\/dd\/yyyy).ToString()
            $XML.DataCollectorSet.Schedule.EndDate = (Get-Date -Day 1 -Month 1 -Year 1900 -Format MM\/dd\/yyyy).ToString()
            $XML.DataCollectorSet.Schedule.StartTime = (Get-Date -Hour 12 -Minute 0 -Format HH:mm ).ToString()
        }

        # If -threads is specified we need to add it to the counter set
        if ($Threads) {

            Write-SimpleLogFile -string "Adding threads to counter set" -Name "ExPerfWiz.log"

            # Create and set the XML element
            $threadCounter = $XML.CreateElement("Counter")
            $threadCounter.InnerXml = "\Thread(*)\*"

            # Add the XML element
            $XML.DataCollectorSet.PerformanceCounterDataCollector.AppendChild($threadCounter)
        } else {}

        # Write the XML to disk
        $xmlFile = Join-Path $env:TEMP ExPerfWiz.xml
        Write-SimpleLogFile -string ("Writing Configuration to: " + $xmlFile) -Name "ExPerfWiz.log"
        $XML.Save($xmlFile)
        Write-SimpleLogFile -string ("Importing Collector Set " + $xmlFile + " for " + $server) -Name "ExPerfWiz.log"

        # Taking a proactive approach on possible conflicts with creating the collector
        $currentCollector = Get-ExPerfWiz -Name $Name -Server $Server -ErrorAction SilentlyContinue

        # Check the status of the collectors and take the correct action
        switch ($currentCollector.status) {
            Running {
                Write-SimpleLogFile "Running Duplicate Found" -Name "ExPerfWiz.log"
                if ($PSCmdlet.ShouldProcess("$Server\$Name", "Stop Running Collector Set and Replace")) {
                    Stop-ExPerfWiz -Name $Name -Server $Server
                }
                Remove-ExPerfWiz -Name $Name -Server $server -Confirm:$false
            }
            Stopped {
                Write-SimpleLogFile "Duplicate Found" -Name "ExPerfWiz.log"
                #Remove-ExPerfWiz -Name $Name -Server $server -Confirm:$false
            }
            default {
                Write-SimpleLogFile "No Conflicts Found" -Name "ExPerfWiz.log"
            }
        }

        # Import the XML with our configuration
        [string]$logman = logman import -xml $xmlFile -name $Name -s $server

        # Check if we have an error and throw if needed
        if ($null -eq ($logman | Select-String "Error:")) {
            Write-SimpleLogFile "Collector Successfully Created" -Name "ExPerfWiz.log"
        } else {
            throw $logman
        }

        ## Implement Start time
        # Scenarios supported:
        # 1) Start PerfMon at time X daily run for time outlined in rest of settings
        # 2) Setup PerfMon without scheduled start time
        if ($PSBoundParameters.ContainsKey("StartTime".ToLower())) {
            Set-ExPerfWiz -Name $Name -Server $server -StartTime $startTime -Quiet
        } else {
            Write-SimpleLogFile -string "No Start time provided" -Name "ExPerfWiz.log"
        }

        # Need to start the counter set if asked to do so
        if ($StartOnCreate) {
            Start-ExPerfWiz -Server $Server -Name $Name
        } else {}

        # Display back the newly created object
        Get-ExPerfWiz -Name $Name -Server $Server
    }
}
