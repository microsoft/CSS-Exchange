# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function global:Stop-ExPerfWiz {
    <#

    .SYNOPSIS
    Stop a data collector set.

    .DESCRIPTION
    Stops a data collector set on the local or remote server.

    .PARAMETER Name
    Name of the data collector set to stop.

    Default Exchange_PerfWiz

    .PARAMETER Server
    Name of the server to stop the collector set on.

    Default LocalHost

	.OUTPUTS
    Logs all activity into $env:LOCALAPPDATA\ExPerfWiz.log file

    .EXAMPLE
    Stop the default data collector set on the local server

    Stop-ExPerfWiz

    .EXAMPLE
    Stop a data collector set on a remote server

    Stop-ExPerfWiz -Name "My Collector Set" -Server RemoteServer-01

    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $Name = "Exchange_PerfWiz",

        [string]
        $Server = $env:ComputerName
    )

    process {
        Write-SimpleLogFile -string ("Stopping ExPerfWiz: " + $server + "\" + $Name) -Name "ExPerfWiz.log"

        # Remove the exPerfWiz counter set
        if ($PSCmdlet.ShouldProcess("$Server\$Name", "Stopping ExPerfWiz Data Collection")) {
            [string]$logman = logman stop -name $Name -s $server
        }

        # Check if we have an error and throw and error if needed.
        if ($logman | Select-String "Error:") {
            # if we are not running already then just move on
            if ($logman | Select-String "is not running") {
                Write-SimpleLogFile "Collector Not Running" -Name "ExPerfWiz.log"
            } else {
                Write-SimpleLogFile "[ERROR] - Unable to Stop Collector" -Name "ExPerfWiz.log"
                Write-SimpleLogFile $logman -Name "ExPerfWiz.log"
                throw $logman
            }
        } else {
            Write-SimpleLogFile "ExPerfWiz Stopped" -Name "ExPerfWiz.log"
        }
    }
}
