function Invoke-RemoveExposedDrives {

    function Out-removeDHSFile {
        param ([string]$fileline)
        $fileline | Out-File -FilePath "$path\removeSnapshot.dsh" -Encoding ASCII -Append
    }

    " "
    Get-Date
    Write-Host "Diskshadow Snapshots" -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    Write-Host " "
    if ($null -eq $logsnapvol) {
        $exposedDrives = $dbsnapvol
    } else {
        $exposedDrives = $dbsnapvol.ToString() + " and " + $logsnapvol.ToString()
    }
    "If the snapshot was successful, the snapshot should be exposed as drive(s) $exposedDrives."
    "You should be able to see and navigate the snapshot with File Explorer. How would you like to proceed?"
    Write-Host " "
    Write-Host "NOTE: It is recommended to wait a few minutes to allow truncation to possibly occur before moving past this point." -ForegroundColor Cyan
    Write-Host "      This allows time for the logs that are automatically collected to include the window for the truncation to occur." -ForegroundColor Cyan
    Write-Host
    Write-Host "When ready, choose from the options below:" -ForegroundColor Yellow
    " "
    Write-Host "  1. Remove exposed snapshot now"
    Write-Host "  2. Keep snapshot exposed"
    Write-Host " "
    Write-Warning "Selecting option 1 will permanently delete the snapshot created, i.e. your backup will be deleted."
    " "
    $matchCondition = "^[1-2]$"
    Write-Debug "matchCondition: $matchCondition"
    do {
        Write-Host "Selection" -ForegroundColor Yellow -NoNewline
        $removeExpose = Read-Host " "
        if ($removeExpose -notmatch $matchCondition) {
            Write-Host "Error! Please choose a valid option." -ForegroundColor red
        }
    } while ($removeExpose -notmatch $matchCondition)

    $unexposeCommand = "delete shadows exposed $dbsnapvol"
    if ($null -ne $logsnapvol) {
        $unexposeCommand += $nl + "delete shadows exposed $logsnapvol"
    }

    if ($removeExpose -eq "1") {
        New-Item -Path $path\removeSnapshot.dsh -type file -Force
        Out-removeDHSFile $unexposeCommand
        Out-removeDHSFile "exit"
        & 'C:\Windows\System32\diskshadow.exe' /s $path\removeSnapshot.dsh
    } elseif ($removeExpose -eq "2") {
        Write-Host "You can remove the snapshots at a later time using the diskshadow tool from a command prompt."
        Write-Host "Run diskshadow followed by these commands:"
        Write-Host $unexposeCommand
    }
}