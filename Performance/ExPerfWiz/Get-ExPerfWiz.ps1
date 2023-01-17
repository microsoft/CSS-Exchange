# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function global:Get-ExPerfWiz {
    <#

    .SYNOPSIS
    Get information about a data collector set.

    .DESCRIPTION
    Gets information about a data collector set on the local or remote server.

    .PARAMETER Name
    Name of the Data Collector set

    Default Exchange_PerfWiz

    .PARAMETER Server
    Name of the server

    Default LocalHost

    .PARAMETER ShowLog
    Shows the ExPerfWiz log file on the server

	.OUTPUTS
    Logs all activity into $env:LOCALAPPDATA\ExPerfWiz.log file

    .EXAMPLE
    Get info on the default collector set

    Get-ExPerfWiz

    .EXAMPLE
    Get info on a collector set on a remote server

    Get-ExPerfWiz -Name "My Collector Set" -Server RemoteServer-01

    #>
    [CmdletBinding()]
    param (
        [string]
        $Name,

        [string]
        $Server = $env:ComputerName,

        [switch]
        $ShowLog

    )

    if ($ShowLog) { Notepad (Join-Path $env:LOCALAPPDATA ExPerfWiz.log); return }

    Write-SimpleLogFile -string ("Getting ExPerfWiz: " + $server) -Name "ExPerfWiz.log"

    # If no name was provided then we need to return all collectors logman finds
    if ([string]::IsNullOrEmpty($Name)) {

        # Returns all found collector sets
        $logmanAll = logman query -s $server

        if (!([string]::IsNullOrEmpty(($logmanAll | Select-String "Error:")))) {
            throw $logmanAll[-1]
        }

        # Process the string return into a set of collector names
        $i = -3
        [array]$perfLogNames = $null

        while (!($logmanAll[$i] | Select-String "---")) {

            # pull the first 40 characters then trim and trailing spaces
            [array]$perfLogNames += $logmanAll[$i].substring(0, 40).TrimEnd()
            $i--
        }
    }
    # If a name was provided put just that into the array
    else {
        [array]$perfLogNames += $Name
    }

    # Query each collector found in turn to get their details
    foreach ($collectorName in $perfLogNames) {

        $logman = logman query $collectorName -s $Server

        # Quick error check
        if (!([string]::IsNullOrEmpty(($logman | Select-String "Error:")))) {
            throw $logman[-1]
        }

        # Convert the output of logman into an object
        $logmanObject = New-Object -TypeName PSObject

        # Go thru each line and determine what the value should be
        foreach ($line in $logman) {

            $lineSplit = $line.split(":").trim()

            switch (($lineSplit)[0]) {
                'Name' {
                    # Skip the path to the perfmon inside the counter set
                    if ($lineSplit[1] -like "*\*") {}
                    # Set the name and push it into a variable to use later
                    else {
                        $name = $lineSplit[1]
                    }
                }
                'Status' { $status = $lineSplit[1] }
                'Root Path' {
                    if ($lineSplit[1].contains("%")) {
                        $rootPath = $lineSplit[1]
                        $outputPath = $lineSplit[1]
                    } else {
                        $rootPath = ($lineSplit[1] + ":" + $lineSplit[2])
                        $outputPath = (Join-Path (($lineSplit[1] + ":" + $lineSplit[2])) ($env:ComputerName + "_" + $name))
                    }
                }
                'Segment' { $segment = $lineSplit[1] }
                'Schedules' { $schedules = $lineSplit[1] }
                'Duration' { $duration = (New-TimeSpan -Seconds ([int]($lineSplit[1].split(" "))[0])) }
                'Segment Max Size' { $maxSize = (($lineSplit[1].replace(" ", "")) / 1MB) }
                'Run As' { $runAs = $lineSplit[1] }
                'Start Date' { $startDate = $lineSplit[1] }
                'Start Time' { $startTime = ($line.split(" ")[-2] + " " + $line.split(" ")[-1]) }
                'End Date' { $endDate = $lineSplit[1] }
                'Days' { $days = $lineSplit[1] }
                'Type' { $type = $lineSplit[1] }
                'Append' { $append = (Convert-OnOffBool($lineSplit[1])) }
                'Circular' { $circular = (Convert-OnOffBool($lineSplit[1])) }
                'Overwrite' { $overwrite = (Convert-OnOffBool($lineSplit[1])) }
                'Sample Interval' { $sampleInterval = (($lineSplit[1].split(" "))[0]) }
                default {}
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
        $logmanObject.PsTypeNames.insert(0, 'ExPerfWiz.Counter')

        # Add each object to the return array
        $logmanObject
    }
}
