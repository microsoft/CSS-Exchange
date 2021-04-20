function Invoke-DiskShadow {
    Write-Host " " $nl
    Get-Date
    Write-Host "Starting DiskShadow copy of Exchange database: $selDB" -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    Write-Host "Running the following command:" $nl
    Write-Host "`"C:\Windows\System32\diskshadow.exe /s $path\diskshadow.dsh /l $path\diskshadow.log`"" $nl
    Write-Host " "

    #in case the $path and the script location is different we need to change location into the $path directory to get the results to work as expected.
    try {
        $here = (Get-Location).Path
        Set-Location $path
        diskshadow.exe /s $path\diskshadow.dsh /l $path\diskshadow.log
    } finally {
        Set-Location $here
    }
}