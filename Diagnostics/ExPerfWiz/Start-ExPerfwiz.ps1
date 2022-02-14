Function Start-ExPerfwiz {
    <#

    .SYNOPSIS
    Starts a data collector set

    .DESCRIPTION
    Starts a data collector set on the local server or a remote server.

    .PARAMETER Name
    The Name of the Data Collector set to start

    Default Exchange_Perfwiz

    .PARAMETER Server
    Name of the remote server to start the data collector set on.

    Default LocalHost

	.OUTPUTS
     Logs all activity into $env:LOCALAPPDATA\ExPefwiz.log file

	.EXAMPLE
    Start the default data collector set on this server.

    Start-ExPerfwiz

    .EXAMPLE
    Start a collector set on another server.

    Start-ExPerfwiz -Name "My Collector Set" -Server RemoteServer-01

    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param (        
        [Parameter(ValueFromPipelineByPropertyName)]    
        [string]
        $Name = "Exchange_Perfwiz",

        [string]
        $Server = $env:ComputerName
    )

    Process {
        Write-Logfile -string ("Starting ExPerfwiz: " + $Server)

        # Check if we have an error and throw and error if needed.
        $i = 0
        $repeat = $false
        do {
            # Start the experfwiz counter set
            if ($PSCmdlet.ShouldProcess("$Server\$Name", "Staring ExPerfwiz Data Collection")) {
                [string]$logman = logman start -name $Name -s $Server
            }            

            # We know "unable to create the specified log file" can be worked around by incrementing the size and trying again
            # so incrementing the size and trying again.
            if ($logman | select-string "Unable to create the specified log file") {
                Write-Warning "Starting Experfwiz Failed ... Incrementing size and trying again. [Attempt $i/3]"
                Write-Logfile "Retrying Start-Experfwiz"
                Step-ExPerfwizSize -Name $Name -Server $Server
                $i++
                $repeat = $true
            }
            else { $repeat = $false }
            # Repeat up to three times
        } while ($repeat -and ($i -lt 3))

        # If we have an error then we need to throw else continue
        If ($logman | select-string "Error:") {
            # Don't throw an error if the collector is already started
            if ($logman | select-string "administrator has refused the request") {
                Write-Logfile "Collector already Started"
            }
            else {
                Write-Logfile "[ERROR] - Unable to Start Collector"
                Write-Logfile $logman
                Throw $logman        
            }
        }
        else {
            Write-Logfile "ExPerfwiz Started"
        }
    }
}