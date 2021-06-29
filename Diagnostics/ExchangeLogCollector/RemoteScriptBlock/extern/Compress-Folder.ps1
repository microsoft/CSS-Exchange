# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/Compress-Folder/Compress-Folder.ps1
#v21.01.22.2234
Function Compress-Folder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Because it returns different types that needs to be addressed')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$Folder,
        [Parameter(Mandatory = $false)][bool]$IncludeMonthDay = $false,
        [Parameter(Mandatory = $false)][bool]$IncludeDisplayZipping = $true,
        [Parameter(Mandatory = $false)][bool]$ReturnCompressedLocation = $false,
        [Parameter(Mandatory = $false, Position = 1)][object]$PassedObjectParameter
    )
    #Function Version #v21.01.22.2234

    Function Get-DirectorySize {
        param(
            [Parameter(Mandatory = $true)][string]$Directory,
            [Parameter(Mandatory = $false)][bool]$IsCompressed = $false
        )
        Write-InvokeCommandReturnVerboseWriter("Calling: Get-DirectorySize")
        Write-InvokeCommandReturnVerboseWriter("Passed: [string]Directory: {0} | [bool]IsCompressed: {1}" -f $Directory, $IsCompressed)
        $itemSize = 0
        if ($IsCompressed) {
            $itemSize = (Get-Item $Directory).Length
        } else {
            $childItems = Get-ChildItem $Directory -Recurse | Where-Object { -not($_.Mode.StartsWith("d-")) }
            foreach ($item in $childItems) {
                $itemSize += $item.Length
            }
        }
        return $itemSize
    }
    Function Enable-IOCompression {
        $successful = $true
        Write-InvokeCommandReturnVerboseWriter("Calling: Enable-IOCompression")
        try {
            Add-Type -AssemblyName System.IO.Compression.Filesystem -ErrorAction Stop
        } catch {
            Write-InvokeCommandReturnHostWriter("Failed to load .NET Compression assembly. Unable to compress up the data.")
            $successful = $false
        }
        Write-InvokeCommandReturnVerboseWriter("Returned: [bool]{0}" -f $successful)
        return $successful
    }
    Function Confirm-IOCompression {
        Write-InvokeCommandReturnVerboseWriter("Calling: Confirm-IOCompression")
        $assemblies = [Appdomain]::CurrentDomain.GetAssemblies()
        $successful = $false
        foreach ($assembly in $assemblies) {
            if ($assembly.Location -like "*System.IO.Compression.Filesystem*") {
                $successful = $true
                break
            }
        }
        Write-InvokeCommandReturnVerboseWriter("Returned: [bool]{0}" -f $successful)
        return $successful
    }

    Function Compress-Now {
        Write-InvokeCommandReturnVerboseWriter("Calling: Compress-Now ")
        $zipFolder = Get-ZipFolderName -Folder $Folder -IncludeMonthDay $IncludeMonthDay
        if ($IncludeDisplayZipping) {
            Write-InvokeCommandReturnHostWriter("Compressing Folder {0}" -f $Folder)
        }
        $sizeBytesBefore = Get-DirectorySize -Directory $Folder
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Folder, $zipFolder)
        $timer.Stop()
        $sizeBytesAfter = Get-DirectorySize -Directory $zipFolder -IsCompressed $true
        Write-InvokeCommandReturnVerboseWriter("Compressing directory size of {0} MB down to the size of {1} MB took {2} seconds." -f ($sizeBytesBefore / 1MB), ($sizeBytesAfter / 1MB), $timer.Elapsed.TotalSeconds)
        if ((Test-Path -Path $zipFolder)) {
            Write-InvokeCommandReturnVerboseWriter("Compress successful, removing folder.")
            Remove-Item $Folder -Force -Recurse
        }
        if ($ReturnCompressedLocation) {
            Set-Variable -Name compressedLocation -Value $zipFolder -Scope 1
        }
    }

    Function Get-ZipFolderName {
        param(
            [Parameter(Mandatory = $true)][string]$Folder,
            [Parameter(Mandatory = $false)][bool]$IncludeMonthDay = $false
        )
        Write-InvokeCommandReturnVerboseWriter("Calling: Get-ZipFolderName")
        Write-InvokeCommandReturnVerboseWriter("Passed - [string]Folder:{0} | [bool]IncludeMonthDay:{1}" -f $Folder, $IncludeMonthDay)
        if ($IncludeMonthDay) {
            $zipFolderNoEXT = "{0}-{1}" -f $Folder, (Get-Date -Format Md)
        } else {
            $zipFolderNoEXT = $Folder
        }
        Write-InvokeCommandReturnVerboseWriter("[string]zipFolderNoEXT: {0}" -f $zipFolderNoEXT)
        $zipFolder = "{0}.zip" -f $zipFolderNoEXT
        if (Test-Path $zipFolder) {
            [int]$i = 1
            do {
                $zipFolder = "{0}-{1}.zip" -f $zipFolderNoEXT, $i
                $i++
            }while (Test-Path $zipFolder)
        }
        Write-InvokeCommandReturnVerboseWriter("Returned: [string]zipFolder {0}" -f $zipFolder)
        return $zipFolder
    }

    $Script:stringArray = @()
    if ($null -ne $PassedObjectParameter) {
        if ($null -ne $PassedObjectParameter.Folder) {
            $Folder = $PassedObjectParameter.Folder
            if ($null -ne $PassedObjectParameter.IncludeDisplayZipping) {
                $IncludeDisplayZipping = $PassedObjectParameter.IncludeDisplayZipping
            }
            if ($null -ne $PassedObjectParameter.ReturnCompressedLocation) {
                $ReturnCompressedLocation = $PassedObjectParameter.ReturnCompressedLocation
            }
            if ($null -ne $PassedObjectParameter.IncludeMonthDay) {
                $IncludeMonthDay = $PassedObjectParameter.IncludeMonthDay
            }
        } else {
            $Folder = $PassedObjectParameter
        }
        $InvokeCommandReturnWriteArray = $true
    }
    if ($Folder.EndsWith("\")) {
        $Folder = $Folder.TrimEnd("\")
    }
    Write-InvokeCommandReturnVerboseWriter("Calling: Compress-Folder")
    Write-InvokeCommandReturnVerboseWriter("Passed - [string]Folder: {0} | [bool]IncludeDisplayZipping: {1} | [bool]ReturnCompressedLocation: {2}" -f $Folder,
        $IncludeDisplayZipping,
        $ReturnCompressedLocation)

    $compressedLocation = [string]::Empty
    if (Test-Path $Folder) {
        if (Confirm-IOCompression) {
            Compress-Now
        } else {
            if (Enable-IOCompression) {
                Compress-Now
            } else {
                Write-InvokeCommandReturnHostWriter("Unable to compress folder {0}" -f $Folder)
                Write-InvokeCommandReturnVerboseWriter("Unable to enable IO compression on this system")
            }
        }
    } else {
        Write-InvokeCommandReturnHostWriter("Failed to find the folder {0}" -f $Folder)
    }
    if ($InvokeCommandReturnWriteArray) {
        if ($ReturnCompressedLocation) {
            Write-InvokeCommandReturnVerboseWriter("Returning: {0}" -f $compressedLocation)
            $hashTable = @{"ReturnObject" = $compressedLocation }
            $Script:stringArray += $hashTable
            return $Script:stringArray
        } else {
            return $Script:stringArray
        }
    }
    if ($ReturnCompressedLocation) {
        Write-InvokeCommandReturnVerboseWriter("Returning: {0}" -f $compressedLocation)
        return $compressedLocation
    }
}
