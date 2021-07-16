# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: Write-SimpleLogFile.ps1
	Requires: NA
    Major Release History:
        06/22/2021 - Initial Release

.SYNOPSIS
Supports writing a basic log file to LocalAppData

.DESCRIPTION
Supports basic log file generation for other scripts.
Places the log file into the $env:LocalAppData Folder.

Supports outputing to the host as well as the log files.

.PARAMETER String
String to be written into the log file.

.PARAMETER Name
Name of the log file.

.PARAMETER OutHost
Switch that will write the output to the host as well as the log file.

.PARAMETER OpenLog
Opens the log file in notepad.

.OUTPUTS
Log file specified in the -Name parameter.
Writes the file intothe $Env:LocalAppData

.EXAMPLE
Write-SimpleLogFile -String "Start ProcessA" -Name mylogfile.log

Writes "[Date] - Start ProcessA" to $env:LocalAppData\mylogfile.log

.EXAMPLE
Write-SimpleLogFile -String "Start ProcessB" -Name mylogfile.log -OutHost

Writes "[Date] - Start ProcessB" to $env:LocalAppData\mylogfile and to the Host

#>
Function Write-SimpleLogfile {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$String,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$OutHost,

        [switch]$OpenLog

    )

    Begin {
        # Get our log file path
        $LogFile = Join-Path $env:LOCALAPPDATA $Name

        if ($OpenLog) {
            Notepad.exe $LogFile
            Exit
        }
    }
    Process {

        # Get the current date
        [string]$date = Get-Date -Format G

        # Build output string
        [string]$logstring = ( "[" + $date + "] - " + $string)

        # Write everything to our log file and the screen
        $logstring | Out-File -FilePath $LogFile -Append -Confirm:$false
        if ($OutHost) { Write-Host $logstring }
        else { Write-Verbose  $logstring }
    }
}


