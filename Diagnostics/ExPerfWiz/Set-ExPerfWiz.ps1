# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function global:Set-ExPerfWiz {
    <#

    .SYNOPSIS
    Modifiy the configuration of an existing data collector set.

    .DESCRIPTION
    Allow for th emodification of some parameters of a data collector set once created.

    .PARAMETER Name
    The Name of the Data Collector set to update.

    Default Exchange_Perfwiz

    .PARAMETER Server
    Name of the remote server to update the data collector set on.

    Default LocalHost

    .PARAMETER Duration
    Sets how long should the performance data be collected
    Provided in time span format hh:mm:ss

    .PARAMETER Interval
    How often the performance data should be collected.

    .PARAMETER Maxsize
    Maximum size of the perfmon log in MegaBytes

    .PARAMETER StartTime
    Time of day to start the data collector set
    It will start at this time EVERY day until removed.

    .PARAMETER Quiet
    Suppress output

	.OUTPUTS
     Logs all activity into $env:LOCALAPPDATA\ExPerfWiz.log file

	.EXAMPLE
    Set the default data collector set to start at 1pm on the local server.

    Set-Experfwiz -StartTime 13:00:00

    .EXAMPLE
    Set the duration to 4 hours and the interval to 1 second on a remove server

    Set-ExPerfwiz -Server RemoteServer-01 -Duration 04:00:00 -Interval 1

    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name = "Exchange_Perfwiz",

        [timespan]
        $Duration,

        [int]
        $Interval,

        [int]
        $MaxSize,

        [string]
        $Server = $env:ComputerName,

        [string]
        $StartTime,

        [switch]
        $Quiet

    )
    begin {
        # Get the existing experfwiz object so that we can maintain settings
        $settings = Get-ExPerfwiz -Name $Name -Server $Server

        # If a duration is passed process the change
        if (!($PSBoundParameters.ContainsKey("Duration"))) { $Duration = [timespan]$settings.Duration }

        # if Interval is passed set the new interval
        if (!($PSBoundParameters.ContainsKey("Interval"))) { $Interval = $settings.SampleInterval }

        # If maxsize is passed set max size
        if (!($PSBoundParameters.ContainsKey("maxsize"))) { $MaxSize = $settings.MaxSize }

        # If StartTime is passed set the start time
        if (!($PSBoundParameters.ContainsKey("starttime"))) { $StartTime = (Get-Date ($settings.StartDate + " " + $settings.starttime) -Format 'M/d/yyyy HH:mm:ss').tostring }
        else { $StartTime = (Get-Date $StartTime -Format 'M/d/yyyy HH:mm:ss').tostring() }
    }


    Process {

        Write-SimpleLogFile -string "Updating experfwiz $name on $server" -Name "ExPerfWiz.log"

        # Update the collector
        if ($PSCmdlet.ShouldProcess("$Server\$Name", "Updating ExPerfwiz Data Collector")) {
            [string]$logman = logman update -name $Name -s $Server -rf $Duration.TotalSeconds -si $Interval -max $MaxSize -b $StartTime
        }

        # Check if we generated and error on update
        If ($null -eq ($logman | Select-String "Error:")) {
            Write-SimpleLogFile "Update Successful" -Name "ExPerfWiz.log"
        } else {
            Write-SimpleLogFile -string "[ERROR] - Problem updating perfwiz:" -Name "ExPerfWiz.log"
            Write-SimpleLogFile -string $logman -Name "ExPerfWiz.log"
            Throw $logman
        }
    }
    End {
        # Return the new object and values
        if ($quiet) {}
        else { Get-ExPerfwiz -Name $name -Server $server }
    }
}

