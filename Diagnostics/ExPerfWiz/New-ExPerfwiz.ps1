Function New-ExPerfwiz {
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

    This paramater is required.

    .PARAMETER Interval
    How often the performance data should be collected.

    Default is 5s (5)

    .PARAMETER MaxSize
    Maximum size of the perfmon log in MegaBytes
    Default is 1024MB

    .PARAMETER Name
    The name of the data collector set

    Default is Exchange_Perfwiz

    .PARAMETER Server
    Name of the server where the perfmon collector should be created

    Default is Localhost

    .PARAMETER StartOnCreate
    Starts the counter set as soon as it is created

    Default is False

    .PARAMETER Template
    XML perfmon template file that should be loaded to create the data collector set.

    Default is to prompt to select a Template from the XMLs provided with this module.

    .PARAMETER Threads
    Includes threads in the counter set.
    *** Including Threads significantly increase the size of perfmon data ***

    Default is False

    .PARAMETER StartTime
    Time of day to start the data collector set
    It will start at this time EVERY day until removed.

    Default is <not set>

    .OUTPUTS
    Creates a data collector set in Perfmon based on the provided XML file

    Logs all activity into $env:LOCALAPPDATA\ExPefwiz.log file

    .EXAMPLE
    Create a standard ExPerfwiz data collector for troubleshooting performane issues on the local machine.

    New-ExPerfwiz -FolderPath C:\PerfData

    This will prompt the end user to select a template from the provided set and create a default data collector set using that Template.
    The perfmon data will be stored in the C:\PerfData folder

    .EXAMPLE
    Create a custom ExPefwiz data collector on the local machine from a custom template

    New-ExPerfwiz -Name "My Collector" -Duration "01:00:00" -Interval 1 -MaxSize 500 -Template C:\Temp\MyTemplate.xml -Circular $true -Threads $True

    Creates a collector named "My Collector" From the template MyTemplate.xml.
    Circular logging will be enabled along with Threads.
    When started the collector will run for 1 hour.
    It will have a maximum file size of 500MB

    .EXAMPLE
    Create an ExPerfwiz data collector on another server

    New-ExPerfwiz -FolderPath C:\temp\experfwiz -Server OtherServer-01

    Will prompt for template to use.
    Will create a perfmon counter set on the remove server OtherServer-01 with the output folder being C:\temp\experfwiz on that server

    #>

    ### Creates a new experfwiz collector
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param(
        [switch]
        $Circular,

        [timespan]
        $Duration = [timespan]::Parse('8:00:00'),

        [Parameter(Mandatory = $true, HelpMessage = "Please provide a valid folder path for output")]
        [string]
        $FolderPath,

        [int]
        $Interval = 5,

        [int]
        $MaxSize = 1024,

        [string]
        $Name = "Exchange_Perfwiz",

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

    Begin {
        # Check for new version of Experfwiz
        Get-ExperfwizUpdate
    }

    Process {

        # Build path to templates
        $templatePath = join-path (split-path (Get-Module experfwiz | Sort-Object -Property Version -Descending)[0].path -Parent) Templates

        # If no template provided then we use the default one
        While ([string]::IsNullOrEmpty($Template)) {
            Write-Logfile "Using default template"

            # Put the selected xml into template
            $Template = join-path $templatePath "Exch_13_16_19_Full.xml"
        }

        # Test the template path and log it as good or throw an error
        If (Test-Path $Template) {
            Write-Logfile -string ("Using Template:" + $Template)
        }
        Else {
            Throw "Cannot find template xml file provided.  Please provide a valid Perfmon template file. $Template"
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
        if ($PSBoundParameters.ContainsKey("starttime")) {
            $XML.DataCollectorSet.SchedulesEnabled = "1"
            # Set the schedule date and time to reflect the values in the scheduled task
            $XML.DataCollectorSet.Schedule.StartDate = (Get-date -Format MM\/dd\/yyyy).tostring()
            $XML.DataCollectorSet.Schedule.EndDate = (Get-Date -Day 1 -Month 1 -Year 2100 -Format MM\/dd\/yyyy).tostring()
            $XML.DataCollectorSet.Schedule.StartTime = (Get-Date $StartTime -Format HH:mm).tostring()        
        }
        else {
            $XML.DataCollectorSet.SchedulesEnabled = "0"
            # Since not schedule we are going to set the date / time to 1900
            $XML.DataCollectorSet.Schedule.StartDate = (Get-date -Day 1 -Month 1 -Year 1900 -Format MM\/dd\/yyyy).tostring()
            $XML.DataCollectorSet.Schedule.EndDate = (Get-Date -Day 1 -Month 1 -Year 1900 -Format MM\/dd\/yyyy).tostring()
            $XML.DataCollectorSet.Schedule.StartTime = (Get-Date -Hour 12 -Minute 0 -Format HH:mm ).tostring()
        }

        # If -threads is specified we need to add it to the counter set
        If ($Threads) {

            Write-Logfile -string "Adding threads to counter set"

            # Create and set the XML element
            $threadCounter = $XML.CreateElement("Counter")
            $threadCounter.InnerXml = "\Thread(*)\*"

            # Add the XML element
            $XML.DataCollectorSet.PerformanceCounterDataCollector.AppendChild($threadCounter)

        }
        else {}

        # Write the XML to disk
        $xmlfile = Join-Path $env:TEMP ExPerfwiz.xml
        Write-Logfile -string ("Writing Configuration to: " + $xmlfile)
        $XML.Save($xmlfile)
        Write-Logfile -string ("Importing Collector Set " + $xmlfile + " for " + $server)

        # Taking a proactive approach on possible conflicts with creating the collector
        $currentcollector = get-experfwiz -Name $Name -Server $Server -ErrorAction SilentlyContinue

        # Check the status of the collectors and take the correct action
        switch ($currentcollector.status) {
            Running {
                Write-LogFile "Running Duplicate Found"                
                if ($PSCmdlet.ShouldProcess("$Server\$Name", "Stop Running Collector Set and Replace")) {
                    Stop-ExPerfwiz -Name $Name -Server $Server
                }
                Remove-ExPerfwiz -Name $Name -Server $server -Confirm:$false
            }
            Stopped {
                Write-LogFile "Duplicate Found"
                #Remove-ExPerfwiz -Name $Name -Server $server -Confirm:$false
            }
            Default {
                Write-Logfile "No Comflicts Found"
            }
        }        

        # Import the XML with our configuration
        [string]$logman = logman import -xml $xmlfile -name $Name -s $server

        # Check if we have an error and throw if needed
        if ($null -eq ($logman | Select-String "Error:")) {
            Write-LogFile "Collector Successfully Created"
        }
        else {
            Throw $logman
        }
        
        ## Implement Start time
        # Scenarios supported:
        # 1) Start Perfmon at time X daily run for time outlined in rest of settings
        # 2) Setup perfmon without scheduled start time
        if ($PSBoundParameters.ContainsKey("starttime")) {
            Set-Experfwiz -name $Name -server $server -starttime $startTime -quiet
        }
        else {
            Write-Logfile -string "No Start time provided"
        }

        # Need to start the counter set if asked to do so
        If ($StartOnCreate) {
            Start-ExPerfwiz -server $Server -Name $Name
        }
        else {}
    
        # Display back the newly created object
        Get-ExPerfwiz -Name $Name -Server $Server
    }
}