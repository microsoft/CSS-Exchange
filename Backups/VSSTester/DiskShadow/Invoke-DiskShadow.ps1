function Invoke-DiskShadow {
    Write-Host " " $nl
    Get-Date
    Write-Host "Starting DiskShadow copy of Exchange database: $selDB" -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    Write-Host "Running the following command:" $nl
    Write-Host "`"C:\Windows\System32\diskshadow.exe /s $path\diskshadow.dsh /l $path\diskshadow.log`"" $nl
    Write-Host " "

    diskshadow.exe /s $path\diskshadow.dsh /l $path\diskshadow.log
}