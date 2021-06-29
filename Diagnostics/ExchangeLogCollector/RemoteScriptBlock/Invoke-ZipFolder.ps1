# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Invoke-ZipFolder {
    param(
        [string]$Folder,
        [bool]$ZipItAll,
        [bool]$AddCompressedSize = $true
    )

    if ($ZipItAll) {
        Write-ScriptDebug("Disabling Logger before zipping up the directory")
        $Script:Logger.DisableLogger()
        Compress-Folder -Folder $Folder -IncludeMonthDay $true
    } else {
        $compressedLocation = Compress-Folder -Folder $Folder -ReturnCompressedLocation $AddCompressedSize
        if ($AddCompressedSize -and ($compressedLocation -ne [string]::Empty)) {
            $Script:TotalBytesSizeCompressed += ($size = Get-ItemsSize -FilePaths $compressedLocation)
            $Script:FreeSpaceMinusCopiedAndCompressedGB -= ($size / 1GB)
            Write-ScriptDebug("Current Sizes after compression: [double]TotalBytesSizeCompressed: {0} | [double]FreeSpaceMinusCopiedAndCompressedGB: {1}" -f $Script:TotalBytesSizeCompressed,
                $Script:FreeSpaceMinusCopiedAndCompressedGB)
        }
    }
}
