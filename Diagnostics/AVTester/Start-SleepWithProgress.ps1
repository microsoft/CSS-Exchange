# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Start-SleepWithProgress.ps1
	Requires: NA
    Major Release History:
        06/22/2021 - Initial Release

.SYNOPSIS
Sleep with a progress bar managing the bar and the countdown.

.DESCRIPTION
Sleeps X amount of time showing a progress bar.

.PARAMETER SleepTime
Amount of time to sleep.

.PARAMETER Message
Message to display on the progress bar.

.OUTPUTS
Progress bar to screen

.EXAMPLE
Start-SleepWithProgress -SleepTime 60 -Message "Waiting on Process to complete"

Creates a Progress bar with the message "Waiting on Process to complete"
Counts down 60 seconds and updates the Progress bar during the proess.

#>
Function Start-SleepWithProgress {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Start-Sleep does not use -WhatIf')]
    Param(
        [Parameter(Mandatory = $true)]
        [int]$SleepTime,

        [string]$Message = "Sleeping"

    )

    # Loop Number of seconds you want to sleep
    For ($i = 0; $i -le $SleepTime; $i++) {
        $timeleft = ($SleepTime - $i);

        # Progress bar showing progress of the sleep
        Write-Progress -Activity $Message -CurrentOperation "$Timeleft More Seconds" -PercentComplete (($i / $sleeptime) * 100) -Status " "

        # Sleep 1 second
        Start-Sleep 1
    }

    Write-Progress -Completed -Activity $Message -Status " "
}
