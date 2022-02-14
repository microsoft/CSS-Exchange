Function Get-ExPerfwiz {
    <#

    .SYNOPSIS
    Get information about a data collector set.

    .DESCRIPTION
    Gets information about a data collector set on the local or remote server.

    .PARAMETER Name
    Name of the Data Collector set

    Default Exchange_Perfwiz

    .PARAMETER Server
    Name of the server

    Default LocalHost

    .PARAMETER ShowLog
    Shows the experfwiz log file on the server

	.OUTPUTS
    Logs all activity into $env:LOCALAPPDATA\ExPefwiz.log file

    .EXAMPLE
    Get info on the default collector set

    Get-ExPerfwiz

    .EXAMPLE
    Get info on a collector set on a remote server

    Get-ExPerfwiz -Name "My Collector Set" -Server RemoteServer-01

    #>
    [cmdletbinding()]
    param (
        [string]
        $Name,

        [string]
        $Server = $env:ComputerName,

        [switch]
        $ShowLog

    )

    if ($ShowLog) { Notepad (Join-path $env:LOCALAPPDATA ExPefwiz.log); return }
    
    Write-Logfile -string ("Getting ExPerfwiz: " + $server)

    # If no name was provided then we need to return all collectors logman finds
    if ([string]::IsNullOrEmpty($Name)) {

        # Returns all found collector sets
        $logmanAll = logman query -s $server

        If (!([string]::isnullorempty(($logmanAll | select-string "Error:")))) {
            throw $logmanAll[-1]
        }

        # Process the string return into a set of collector names
        $i = -3
        [array]$perfLogNames = $null

        While (!($logmanAll[$i] | select-string "---")) {

            # pull the first 40 characters then trim and trailing spaces
            [array]$perfLogNames += $logmanAll[$i].substring(0, 40).trimend()
            $i--
        }

    }
    # If a name was provided put just that into the array
    else {
        [array]$perfLogNames += $Name
    }

    # Query each collector found in turn to get their details
    foreach ($collectorname in $perfLogNames) {

        $logman = logman query $collectorname -s $Server

        # Quick error check
        If (!([string]::isnullorempty(($logman | select-string "Error:")))) {
            throw $logman[-1]
        }

        # Convert the output of logman into an object
        $logmanObject = New-Object -TypeName PSObject

        # Go thru each line and determine what the value should be
        foreach ($line in $logman) {

            $linesplit = $line.split(":").trim()

            switch (($linesplit)[0]) {
                'Name' {
                    # Skip the path to the perfmon inside the counter set
                    if ($linesplit[1] -like "*\*") {}
                    # Set the name and push it into a variable to use later
                    else {
                        $name = $linesplit[1]
                    }
                }
                'Status' { $status = $linesplit[1] }
                'Root Path' {
                    if ($linesplit[1].contains("%")) {
                        $rootPath = $linesplit[1]
                        $outputPath = $linesplit[1]
                    }
                    else {
                        $rootPath = (Resolve-path ($linesplit[1] + ":" + $linesplit[2]))
                        $outputPath = (Join-path (($linesplit[1] + ":" + $linesplit[2])) ($env:ComputerName + "_" + $name))
                    }
                }
                'Segment' { $segment = $linesplit[1] }
                'Schedules' { $schedules = $linesplit[1] }
                'Duration' { $duration = (New-TimeSpan -Seconds ([int]($linesplit[1].split(" "))[0])) }
                'Segment Max Size' { $maxSize = (($linesplit[1].replace(" ", "")) / 1MB) }
                'Run As' { $runAs = $linesplit[1] }
                'Start Date' { $startDate = $linesplit[1] }
                'Start Time' { $startTime = ($line.split(" ")[-2] + " " + $line.split(" ")[-1]) }
                'End Date' { $endDate = $linesplit[1] }
                'Days' { $days = $linesplit[1] }
                'Type' { $type = $linesplit[1] }
                'Append' { $append = (Convert-OnOffBool($linesplit[1])) }
                'Circular' { $circular = (Convert-OnOffBool($linesplit[1])) }
                'Overwrite' { $overwrite = (Convert-OnOffBool($linesplit[1])) }
                'Sample Interval' { $sampleInterval = (($linesplit[1].split(" "))[0]) }
                Default {}
            }

            

        }

        $logmanObject = New-Object PSObject -Property @{
            Name           = $name
            Status         = $status
            RootPath       = $rootPath
            OutputPath     = $outputPath
            Segment        = $segment
            Schedules      = $schedules
            Duration       = $duration
            MaxSize        = $maxSize
            RunAs          = $runAs
            StartDate      = $startDate
            StartTime      = $startTime
            EndDate        = $endDate
            Days           = $days
            Type           = $type
            Append         = $append
            Circular       = $circular
            OverWrite      = $overwrite
            SampleInterval = $sampleInterval 
        }

        # Add customer PS Object type for use with formatting files
        $logmanObject.pstypenames.insert(0, 'Experfwiz.Counter')

        # Add each object to the return array
        $logmanObject
    }
}