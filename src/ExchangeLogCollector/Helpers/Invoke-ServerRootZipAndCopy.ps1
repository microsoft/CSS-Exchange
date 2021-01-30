#This function is to handle all root zipping capabilities and copying of the data over.
Function Invoke-ServerRootZipAndCopy {
    param(
        [bool]$RemoteExecute = $true
    )

    Function Write-CollectFilesFromLocation {
        Write-ScriptHost -ShowServer $false -WriteString (" ")
        Write-ScriptHost -ShowServer $false -WriteString ("Please collect the following files from these servers and upload them: ")
        $LogPaths |
            ForEach-Object {
                Write-ScriptHost -ShowServer $false -WriteString ("Server: {0} Path: {1}" -f $_.ServerName, $_.ZipFolder)
            }
    }

    if ($RemoteExecute) {
        $Script:ErrorsFromStartOfCopy = $Error.Count
        $Script:Logger = New-LoggerObject -LogDirectory $Script:RootFilePath -LogName "ExchangeLogCollector-ZipAndCopy-Debug" `
            -HostFunctionCaller $Script:HostFunctionCaller `
            -VerboseFunctionCaller $Script:VerboseFunctionCaller

        Write-ScriptDebug("Getting Compress-Folder string to create Script Block")
        $compressFolderString = (${Function:Compress-Folder}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
        Write-ScriptDebug("Creating script block")
        $compressFolderScriptBlock = [scriptblock]::Create($compressFolderString)

        $serverArgListZipFolder = @()

        foreach ($serverName in $Script:ValidServers) {

            $folder = "{0}{1}" -f $Script:RootFilePath, $serverName
            $serverArgListZipFolder += [PSCustomObject]@{
                ServerName   = $serverName
                ArgumentList = [PSCustomObject]@{
                    Folder                = $folder
                    IncludeMonthDay       = $true
                    IncludeDisplayZipping = $true
                }
            }
        }

        Write-ScriptDebug("Calling Compress-Folder")
        Start-JobManager -ServersWithArguments $serverArgListZipFolder -ScriptBlock $compressFolderScriptBlock `
            -DisplayReceiveJobInCorrectFunction $true `
            -JobBatchName "Zipping up the data for Invoke-ServerRootZipAndCopy"

        $LogPaths = Get-RemoteLogLocation -Servers $Script:ValidServers -RootPath $Script:RootFilePath

        if (!($SkipEndCopyOver)) {
            #Check to see if we have enough free space.
            $LogPaths |
                ForEach-Object {
                    $totalSizeToCopyOver += $_.Size
                }

            $freeSpace = Get-FreeSpace -FilePath $Script:RootFilePath
            $totalSizeGB = $totalSizeToCopyOver / 1GB

            if ($freeSpace -gt ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize)) {
                Write-ScriptHost -ShowServer $true -WriteString ("Looks like we have enough free space at the path to copy over the data")
                Write-ScriptHost -ShowServer $true -WriteString ("FreeSpace: {0} TestSize: {1} Path: {2}" -f $freeSpace, ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize), $RootPath)
                Write-ScriptHost -ShowServer $false -WriteString (" ")
                Write-ScriptHost -ShowServer $false -WriteString ("Copying over the data may take some time depending on the network")

                $LogPaths |
                    ForEach-Object {
                        if ($_.ServerName -ne $env:COMPUTERNAME) {
                            $remoteCopyLocation = "\\{0}\{1}" -f $_.ServerName, ($_.ZipFolder.Replace(":", "$"))
                            Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Copying File {1}...." -f $_.ServerName, $remoteCopyLocation)
                            Copy-Item -Path $remoteCopyLocation -Destination $Script:RootFilePath
                            Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Done copying file" -f $_.ServerName)
                        }
                    }
            } else {
                Write-ScriptHost -ShowServer $true -WriteString("Looks like we don't have enough free space to copy over the data") -ForegroundColor "Yellow"
                Write-ScriptHost -ShowServer $true -WriteString("FreeSpace: {0} TestSize: {1} Path: {2}" -f $FreeSpace, ($totalSizeGB + $Script:StandardFreeSpaceInGBCheckSize), $RootPath)
                Write-CollectFilesFromLocation
            }
        } else {
            Write-CollectFilesFromLocation
        }
    } else {
        Invoke-ZipFolder -Folder $Script:RootCopyToDirectory -ZipItAll $true -AddCompressedSize $false
    }
}