# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ItemsSize.ps1
. $PSScriptRoot\IO\Compress-Folder.ps1
function Invoke-ZipFolder {
    param(
        [string]$Folder,
        [bool]$ZipItAll,
        [bool]$AddCompressedSize = $true
    )

    if ($ZipItAll) {
        Write-Verbose("Disabling Logger before zipping up the directory")
        $Script:Logger.LoggerDisabled = $true
        Compress-Folder -Folder $Folder -IncludeMonthDay $true
    } else {
        $compressedLocation = Compress-Folder -Folder $Folder -ReturnCompressedLocation $AddCompressedSize
        if ($AddCompressedSize -and ($compressedLocation -ne [string]::Empty)) {
            $Script:TotalBytesSizeCompressed += ($size = Get-ItemsSize -FilePaths $compressedLocation)
            $Script:FreeSpaceMinusCopiedAndCompressedGB -= ($size / 1GB)
            Write-Verbose("Current Sizes after compression: [double]TotalBytesSizeCompressed: {0} | [double]FreeSpaceMinusCopiedAndCompressedGB: {1}" -f $Script:TotalBytesSizeCompressed,
                $Script:FreeSpaceMinusCopiedAndCompressedGB)
        }
    }
}
