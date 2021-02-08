function Get-VSSWritersBefore {
    " "
    Get-Date
    Write-Host "Checking VSS Writer Status: (All Writers must be in a Stable state before running this script)" -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    $writers = (vssadmin list writers)
    $writers > $path\vssWritersBefore.txt
    $exchangeWriter = $false

    foreach ($line in $writers) {

        if ($line -like "Writer name:*") {
            "$line"

            if ($line.Contains("Microsoft Exchange Writer")) {
                $exchangeWriter = $true
            }
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
                exit
            } else {
                "$line" + $nl
            }
        }
    }
    " " + $nl

    if (!$exchangeWriter) {
        Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!   WARNING   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor red
        Write-Host "Microsoft Exchange Writer not present on server. Unable to preform proper backups on the server."  -ForegroundColor Red
        Write-Host
        Write-Host " - Recommend to restart MSExchangeRepl service to see if the writer comes back. If it doesn't, review the application logs for any events to determine why." -ForegroundColor Cyan
        Write-Host " --- Look for Event ID 2003 to verify that all internal components come online. If you see this event, try to use PSExec.exe to start a cmd.exe as the SYSTEM account and run 'vssadmin list writers'" -ForegroundColor Cyan
        Write-Host " --- If you find the Microsoft Exchange Writer, then we have a permissions issue on the computer that is preventing normal user accounts from finding all the writers." -ForegroundColor Cyan
        Write-Host " - If still not able to determine why, need to have a Microsoft Engineer review ExTrace with Cluster.Replay tags of the MSExchangeRepl service starting up." -ForegroundColor Cyan
        Write-Host
        Write-Host "Stopping Script"
        exit
    }
}