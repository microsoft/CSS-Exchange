function Get-VSSWritersBefore {
    " "
    Get-Date
    Write-Host "Checking VSS Writer Status: (All Writers must be in a Stable state before running this script)" -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    $writers = (vssadmin list writers)
    $writers > $path\vssWritersBefore.txt

    foreach ($line in $writers) {
        if ($line -like "Writer name:*") {
            "$line"
        } elseif ($line -like "   State:*") {
            if ($line -ne "   State: [1] Stable") {
                $nl
                Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!   WARNING   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor red
                $nl
                Write-Host "One or more writers are NOT in a 'Stable' state, STOPPING SCRIPT." -ForegroundColor red
                $nl
                Write-Host "Review the vssWritersBefore.txt file in '$path' for more information." -ForegroundColor Red
                Write-Host "You can also use an Exchange Management Shell or a Command Prompt to run: 'vssadmin list writers'" -ForegroundColor red
                $nl
                Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor red
                $nl
                stopTransLog
                do {
                    Write-Host
                    $continue = Read-Host "Please use the <Enter> key to exit..."
                }
                While ($null -notmatch $continue)
                exit
            } else {
                "$line" + $nl
            }
        }
    }
    " " + $nl
}