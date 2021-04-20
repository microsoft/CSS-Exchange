function Get-VSSWritersAfter {
    " "
    Get-Date
    Write-Host "Checking VSS Writer Status: (after backup)" -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    " "
    $writers = (vssadmin list writers)
    $writers > $path\vssWritersAfter.txt

    foreach ($line in $writers) {
        if ($line -like "Writer name:*") {
            "$line"
        } elseif ($line -like "   State:*") {
            "$line" + $nl
        }
    }
}