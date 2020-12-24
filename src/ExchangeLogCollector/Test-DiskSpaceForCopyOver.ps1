Function Test-DiskSpaceForCopyOver {
    param(
        [parameter(Mandatory = $true)][array]$LogPathObject,
        [parameter(Mandatory = $true)][string]$RootPath 
    )
    Write-ScriptDebug("Function Enter: Test-DiskSpaceForCopyOver")
    foreach ($svrObj in $LogPathObject) {
        $totalSize += $svrObj.Size 
    }
    #switch it to GB in size 
    $totalSizeGB = $totalSize / 1GB
    #Get the local free space again 
    $freeSpace = Get-FreeSpace -FilePath $RootPath
    if ($freeSpace -gt ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize)) {
        Write-ScriptHost -ShowServer $true -WriteString ("Looks like we have enough free space at the path to copy over the data")
        Write-ScriptHost -ShowServer $true -WriteString ("FreeSpace: {0} TestSize: {1} Path: {2}" -f $freeSpace, ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize), $RootPath)
        return $true
    } else {
        Write-ScriptHost -ShowServer $true -WriteString("Looks like we don't have enough free space to copy over the data") -ForegroundColor "Yellow"
        Write-ScriptHost -ShowServer $true -WriteString("FreeSpace: {0} TestSize: {1} Path: {2}" -f $FreeSpace, ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize), $RootPath)
        return $false
    }
    
}