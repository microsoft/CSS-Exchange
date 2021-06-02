# Writes output to a log file with a time date stamp
Function Write-SimpleLogfile {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$String,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [switch]$OutHost

    )

    # Get our log file path
    $LogFile = Join-Path $env:LOCALAPPDATA $Name

    # Get the current date
    [string]$date = Get-Date -Format G

    # Build output string
    [string]$logstring = ( "[" + $date + "] - " + $string)

    # Write everything to our log file and the screen
    $logstring | Out-File -FilePath $LogFile -Append -Confirm:$false
    if ($OutHost) { Write-Host $logstring }
    else { Write-Verbose  $logstring }
}
