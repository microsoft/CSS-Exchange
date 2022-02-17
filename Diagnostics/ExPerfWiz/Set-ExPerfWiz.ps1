# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function global:Set-ExPerfwiz {
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
        $Duration = [timespan]::Parse('8:00:00'),

        [int]
        $Interval = 5,

        [int]
        $MaxSize = 1024,

        [string]
        $Server = $env:ComputerName,

        [string]
        $StartTime,

        [switch]
        $Quiet

    )

    Process {

        Write-SimpleLogFile -string "Updating experfwiz $name on $server" -Name "ExPerfWiz.log"

        # Update the collector
        if ($PSCmdlet.ShouldProcess("$Server\$Name", "Updating ExPerfwiz Data Collector")) {
            [string]$logman = logman update -name $Name -s $Server -rf $Duration.TotalSeconds -si $Interval -max $MaxSize
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

