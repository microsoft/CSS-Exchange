# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Start-JobManager.ps1
. $PSScriptRoot\..\RemoteScriptBlock\Get-FreeSpace.ps1
. $PSScriptRoot\..\RemoteScriptBlock\IO\Compress-Folder.ps1
#This function is to handle all root zipping capabilities and copying of the data over.
function Invoke-ServerRootZipAndCopy {
    param(
        [bool]$RemoteExecute = $true
    )

    $serverNames = $Script:ArgumentList.ServerObjects |
        ForEach-Object {
            return $_.ServerName
        }

    function Write-CollectFilesFromLocation {
        Write-Host ""
        Write-Host "Please collect the following files from these servers and upload them: "
        $LogPaths |
            ForEach-Object {
                Write-Host "Server: $($_.ServerName) Path: $($_.ZipFolder)"
            }
    }

    if ($RemoteExecute) {
        $Script:ErrorsFromStartOfCopy = $Error.Count
        $Script:Logger = Get-NewLoggerInstance -LogName "ExchangeLogCollector-ZipAndCopy-Debug" -LogDirectory $Script:RootFilePath

        Write-Verbose("Getting Compress-Folder string to create Script Block")
        $compressFolderString = (${Function:Compress-Folder}).ToString()
        Write-Verbose("Creating script block")
        $compressFolderScriptBlock = [ScriptBlock]::Create($compressFolderString)

        $serverArgListZipFolder = @()

        foreach ($serverName in $serverNames) {

            $folder = "{0}{1}" -f $Script:RootFilePath, $serverName
            $serverArgListZipFolder += [PSCustomObject]@{
                ServerName   = $serverName
                ArgumentList = @($folder, $true, $true)
            }
        }

        Write-Verbose("Calling Compress-Folder")
        Start-JobManager -ServersWithArguments $serverArgListZipFolder -ScriptBlock $compressFolderScriptBlock `
            -JobBatchName "Zipping up the data for Invoke-ServerRootZipAndCopy"

        $LogPaths = Invoke-Command -ComputerName $serverNames -ScriptBlock {

            $item = $Using:RootFilePath + (Get-ChildItem $Using:RootFilePath |
                    Where-Object { $_.Name -like ("*-{0}*.zip" -f (Get-Date -Format Md)) } |
                    Sort-Object CreationTime -Descending |
                    Select-Object -First 1)

            return [PSCustomObject]@{
                ServerName = $env:COMPUTERNAME
                ZipFolder  = $item
                Size       = ((Get-Item $item).Length)
            }
        }

        if (!($SkipEndCopyOver)) {
            #Check to see if we have enough free space.
            $LogPaths |
                ForEach-Object {
                    $totalSizeToCopyOver += $_.Size
                }

            $freeSpace = Get-FreeSpace -FilePath $Script:RootFilePath
            $totalSizeGB = $totalSizeToCopyOver / 1GB

            if ($freeSpace -gt ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize)) {
                Write-Host "Looks like we have enough free space at the path to copy over the data"
                Write-Host "FreeSpace: $freeSpace TestSize: $(($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize)) Path: $RootPath"
                Write-Host ""
                Write-Host "Copying over the data may take some time depending on the network"

                $LogPaths |
                    ForEach-Object {
                        if ($_.ServerName -ne $env:COMPUTERNAME) {
                            $remoteCopyLocation = "\\{0}\{1}" -f $_.ServerName, ($_.ZipFolder.Replace(":", "$"))
                            Write-Host "[$($_.ServerName)] : Copying File $remoteCopyLocation...."
                            Copy-Item -Path $remoteCopyLocation -Destination $Script:RootFilePath
                            Write-Host "[$($_.ServerName)] : Done copying file"
                        }
                    }
            } else {
                Write-Host "Looks like we don't have enough free space to copy over the data" -ForegroundColor "Yellow"
                Write-Host "FreeSpace: $FreeSpace TestSize: $(($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize)) Path: $RootPath"
                Write-CollectFilesFromLocation
            }
        } else {
            Write-CollectFilesFromLocation
        }
    } else {
        Invoke-ZipFolder -Folder $Script:RootCopyToDirectory -ZipItAll $true -AddCompressedSize $false
    }
}
