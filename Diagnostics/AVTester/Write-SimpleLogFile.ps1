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
Places the log file into the requested Folder.

Supports out putting to the host as well as the log files.

.PARAMETER String
String to be written into the log file.

.PARAMETER Path
String with the Path where the log file will be written.

.PARAMETER FileName
Name of the log file.

.PARAMETER OutHost
Switch that will write the output to the host as well as the log file.

.PARAMETER OpenLog
Opens the log file in notepad.

.OUTPUTS
Log file specified in the FileName parameter.
Writes the file in to the Path specified in the Path parameter.

.EXAMPLE
Write-SimpleLogFile -String "Start ProcessA" -FileName MyLogFile.log -Path "C:\temp"

Writes "[Date] - Start ProcessA" to C:\temp\MyLogFile.log

.EXAMPLE
Write-SimpleLogFile -String "Start ProcessB" -FileName MyLogFile.log -OutHost -Path "C:\temp"

Writes "[Date] - Start ProcessB" to C:\temp\MyLogFile and to the Host

#>
function Write-SimpleLogFile {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$String,

        [parameter(Mandatory)]
        [ValidateScript({
                if (Test-Path -Path $_ -PathType Container) { $true }
                else { throw "Path $_ is not valid" }
            })]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [switch]$OutHost,

        [switch]$OpenLog

    )

    begin {
        # Get our log file path
        $LogFile = Join-Path $Path $FileName

        if ($OpenLog) {
            Notepad.exe $LogFile
            exit
        }
    }
    process {

        # Get the current date
        [string]$date = Get-Date -Format G

        # Build output string
        [string]$logString = ( "[" + $date + "] - " + $string)

        # Write everything to our log file and the screen
        $logString | Out-File -FilePath $LogFile -Append -Confirm:$false
        if ($OutHost) { Write-Host $logString }
        else { Write-Verbose  $logString }
    }
}
