Function Remove-ExPerfwiz {
    <#

    .SYNOPSIS
    Removes data collector sets from perfmon

    .DESCRIPTION
    Used to remove data collector sets from perfmon.

    .PARAMETER Name
    Name of the Perfmon Collector set

    Default Exchange_Perfwiz

    .PARAMETER Server
    Name of the server to remove the collector set from

    Default LocalHost

    .OUTPUTS
    Logs all activity into $env:LOCALAPPDATA\ExPefwiz.log file

    .EXAMPLE
    Remove a collector set on the local machine

    Remove-ExPerfwiz -Name "My Collector Set"

    .EXAMPLE
    Remove a collect set on another server

    Remove-ExPerfwiz -Server RemoteServer-01


    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (

        [Parameter(ValueFromPipelineByPropertyName)]    
        [string]
        $Name = "Exchange_Perfwiz",

        [string]
        $Server = $env:ComputerName
    )

    Process {

        Write-Logfile -string ("Removing Experfwiz for: " + $server)

        # Remove the experfwiz counter set
        if ($PSCmdlet.ShouldProcess("$Server\$Name", "Removing Performance Monitor Data Collector")) {
            [string]$logman = logman delete -name $Name -s $server
        }

        # Check if we have an error and throw and error if needed.
        If ([string]::isnullorempty(($logman | select-string "Error:"))) {
            Write-Logfile "ExPerfwiz removed"
        }
        else {
            Write-Logfile "[ERROR] - Unable to remove Collector"
            Write-Logfile $logman
            Throw $logman
        }
    }

}