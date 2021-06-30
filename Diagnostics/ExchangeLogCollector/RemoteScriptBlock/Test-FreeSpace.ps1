# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-FreeSpace {
    param(
        [Parameter(Mandatory = $false)][array]$FilePaths
    )
    Write-ScriptDebug("Calling: Test-FreeSpace")

    if ($null -eq $FilePaths -or
        $FilePaths.Count -eq 0) {
        Write-ScriptDebug("Null FilePaths provided returning true.")
        return $true
    }

    $passed = $true
    $currentSizeCopy = Get-ItemsSize -FilePaths $FilePaths
    #It is better to be safe than sorry, checking against probably a value way higher than needed.
    if (($Script:FreeSpaceMinusCopiedAndCompressedGB - ($currentSizeCopy / 1GB)) -lt $Script:AdditionalFreeSpaceCushionGB) {
        Write-ScriptDebug("Estimated free space is getting low, going to recalculate.")
        Write-ScriptDebug("Current values: [double]FreeSpaceMinusCopiedAndCompressedGB: {0} | [double]currentSizeCopy: {1} | [double]AdditionalFreeSpaceCushionGB: {2} | [double]CurrentFreeSpaceGB: {3}" -f $Script:FreeSpaceMinusCopiedAndCompressedGB,
            ($currentSizeCopy / 1GB),
            $Script:AdditionalFreeSpaceCushionGB,
            $Script:CurrentFreeSpaceGB)
        $freeSpace = Get-FreeSpace -FilePath ("{0}\" -f $Script:RootCopyToDirectory)
        Write-ScriptDebug("True current free space: {0}" -f $freeSpace)

        if ($freeSpace -lt ($Script:CurrentFreeSpaceGB - .5)) {
            #If we off by .5GB, we need to know about this and look at the data to determine if we might have some logical errors. It is possible that the disk is that active, but that wouldn't be good either for this script.
            Write-ScriptDebug("CRIT: Disk Space logic is off. CurrentFreeSpaceGB: {0} | ActualFreeSpace: {1}" -f $Script:CurrentFreeSpaceGB, $freeSpace)
        }

        $Script:CurrentFreeSpaceGB = $freeSpace
        $Script:FreeSpaceMinusCopiedAndCompressedGB = $freeSpace
        $passed = $freeSpace -gt ($addSize = $Script:AdditionalFreeSpaceCushionGB + ($currentSizeCopy / 1GB))

        if (!($passed)) {
            Write-ScriptHost("Free space on the drive has appear to be used up past recommended thresholds. Going to stop this execution of the script. If you feel this is an Error, please notify ExToolsFeedback@microsoft.com") -ShowServer $true -ForegroundColor "Red"
            Write-ScriptHost("FilePath: {0} | FreeSpace: {1} | Looking for: {2}" -f $Script:RootCopyToDirectory, $freeSpace, ($freeSpace + $addSize)) -ShowServer $true -ForegroundColor "Red"
            return $passed
        }
    }

    $Script:TotalBytesSizeCopied += $currentSizeCopy
    $Script:FreeSpaceMinusCopiedAndCompressedGB = $Script:FreeSpaceMinusCopiedAndCompressedGB - ($currentSizeCopy / 1GB)

    Write-ScriptDebug("Current values [double]FreeSpaceMinusCopiedAndCompressedGB: {0} | [double]TotalBytesSizeCopied: {1}" -f $Script:FreeSpaceMinusCopiedAndCompressedGB, $Script:TotalBytesSizeCopied)
    Write-ScriptDebug("Returning: {0}" -f $passed)
    return $passed
}
