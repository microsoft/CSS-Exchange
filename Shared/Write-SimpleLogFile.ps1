# Writes output to a log file with a time date stamp
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

