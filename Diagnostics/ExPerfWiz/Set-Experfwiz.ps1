Function Set-ExPerfwiz {
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
     Logs all activity into $env:LOCALAPPDATA\ExPefwiz.log file

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

    Process {

        # Build the logman command based on the inputs
        $logmancmd = $null

        # Base command
        $logmancmd = "logman update -name " + $Name + " -s " + $Server

        # If a duration is passed process the change
        if ($PSBoundParameters.ContainsKey("Duration")) { $logmancmd = $logmancmd + " -rf " + [string]$Duration.TotalSeconds }
        
        # if Interval is passed set the new interval
        if ($PSBoundParameters.ContainsKey("Interval")) { $logmancmd = $logmancmd + " -si " + $Interval }

        # If maxsize is passed set max size
        if ($PSBoundParameters.ContainsKey("maxsize")) { $logmancmd = $logmancmd + " -max " + $MaxSize }

        # If StartTime is passed set the start time
        if ($PSBoundParameters.ContainsKey("starttime")) {
            # -b <M/d/yyyy h:mm:ss[AM|PM]>  Begin the data collector at specified time.
            $logmancmd = $logmancmd + " -b " + (Get-Date $StartTime -Format 'M/d/yyyy HH:mm:ss').tostring()
        }
        
        Write-Logfile -string "Updating experfwiz $name on $server"
        Write-Logfile $logmancmd

        # Import the XML with our configuration
        if ($PSCmdlet.ShouldProcess("$Server\$Name", "Updating ExPerfwiz Data Collector")) {
            [string]$logman = Invoke-Expression $logmancmd
        }

        # Check if we generated and error on update
        If ($null -eq ($logman | select-string "Error:")) {
            Write-Logfile "Update Successful"
        }
        else {
            Write-Logfile -string "[ERROR] - Problem updating perfwiz:"
            Write-Logfile -string $logman
            Throw $logman
        }
    }
    End {
        # Return the new object and values
        if ($quiet) {}
        else { Get-ExPerfwiz -name $name -Server $server }
    }

}