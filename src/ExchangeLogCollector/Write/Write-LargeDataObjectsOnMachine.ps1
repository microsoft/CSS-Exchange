#This function job is to write out the Data that is too large to pass into the main script block
#This is for mostly Exchange Related objects.
#To handle this, we export the data locally and copy the data over the correct server.
Function Write-LargeDataObjectsOnMachine {

    Function Write-ExchangeData {
        param(
            [Parameter(Mandatory = $true)][object]$PassedInfo
        )

        $location = $PassedInfo.Location
        $exchBin = "{0}\Bin" -f $PassedInfo.InstallDirectory
        $configFiles = Get-ChildItem $exchBin | Where-Object { $_.Name -like "*.config" }
        $copyTo = "{0}\Config" -f $location
        $configFiles | ForEach-Object { Copy-Item $_.VersionInfo.FileName $copyTo }

        $copyServerComponentStatesRegistryTo = "{0}\regServerComponentStates.TXT" -f $location
        reg query HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\ServerComponentStates /s > $copyServerComponentStatesRegistryTo

        Get-Command exsetup | ForEach-Object { $_.FileVersionInfo } > ("{0}\{1}_GCM.txt" -f $location, $env:COMPUTERNAME)

        #Exchange Web App Pools
        $windir = $env:windir
        $appCmd = "{0}\system32\inetsrv\appcmd.exe" -f $windir
        if (Test-Path $appCmd) {
            $appPools = &$appCmd list apppool
            $exchangeAppPools = @()
            foreach ($appPool in $appPools) {
                $startIndex = $appPool.IndexOf('"') + 1
                $appPoolName = $appPool.SubString($startIndex,
                    ($appPool.SubString($startIndex).IndexOf('"')))
                if ($appPoolName.StartsWith("MSExchange")) {
                    $exchangeAppPools += $appPoolName
                }
            }

            $configFileListLocation = @()
            foreach ($exchAppPool in $exchangeAppPools) {
                $config = &$appCmd list apppool $exchAppPool /text:CLRConfigFile
                $allResult = &$appCmd list apppool $exchAppPool /text:*
                if (($null -ne $config -and
                        $config -ne [string]::Empty) -and
                    (Test-Path $config) -and
                    (!($configFileListLocation.Contains($config.ToLower())))) {
                    $configFileListLocation += $config.ToLower()
                }
                $saveLocation = "{0}\WebAppPools\{1}_{2}.txt" -f $location, $env:COMPUTERNAME, $exchAppPool
                $allResult | Format-List * > $saveLocation
            }

            foreach ($configFile in $configFileListLocation) {
                $content = Get-Content $configFile
                $saveLocation = "{0}\WebAppPools\{1}_{2}" -f $location, $env:COMPUTERNAME,
                $configFile.Substring($configFile.LastIndexOf("\") + 1)
                $content > $saveLocation
            }
        }
    }

    Function Write-ExchangeDataLocally {
        param(
            [object]$ServerData,
            [string]$Location
        )
        $tempLocation = "{0}\{1}" -f $Location, $ServerData.ServerName
        Save-DataToFile -DataIn $ServerData.ExchangeServer -SaveToLocation ("{0}_ExchangeServer" -f $tempLocation)

        if ($ServerData.Hub) {
            Save-DataToFile -DataIn $ServerData.TransportServerInfo -SaveToLocation ("{0}_TransportServer" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.ReceiveConnectors -SaveToLocation ("{0}_ReceiveConnectors" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.QueueData -SaveToLocation ("{0}_InstantQueueInfo" -f $tempLocation)
        }
        if ($ServerData.CAS) {
            Save-DataToFile -DataIn $ServerData.CAServerInfo -SaveToLocation ("{0}_ClientAccessServer" -f $tempLocation)
        }
        if ($ServerData.Mailbox) {
            Save-DataToFile -DataIn $ServerData.MailboxServerInfo -SaveToLocation ("{0}_MailboxServer" -f $tempLocation)
        }
        if ($ServerData.Version -ge 15) {
            Save-DataToFile -DataIn $ServerData.HealthReport -SaveToLocation ("{0}_HealthReport" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.ServerComponentState -SaveToLocation ("{0}_ServerComponentState" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.ServerMonitoringOverride -SaveToLocation ("{0}_serverMonitoringOverride" -f $tempLocation)
            Save-DataToFile -DataIn $ServerData.ServerHealth -SaveToLocation ("{0}_ServerHealth" -f $tempLocation)
        }
    }

    $exchangeServerData = Get-ExchangeObjectServerData -Servers $Script:ValidServers
    #if single server or Exchange 2010 where invoke-command doesn't work
    if (!($Script:ValidServers.count -eq 1 -and
            $Script:ValidServers[0].ToUpper().Contains($env:COMPUTERNAME.ToUpper()))) {
        #Need to have install directory run through the loop first as it could be different on each server
        $serversObjectListInstall = @()
        $serverListCreateDirectories = @()
        foreach ($server in $exchangeServerData) {
            $serverObject = New-Object PSCustomObject
            $serverObject | Add-Member -MemberType NoteProperty -Name ServerName -Value $server.ServerName
            $serverObject | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $true
            $serversObjectListInstall += $serverObject

            #Create Directory
            $serverCreateDirectory = New-Object PSCustomObject
            $serverCreateDirectory | Add-Member -MemberType NoteProperty -Name ServerName -Value $server.ServerName
            $argumentObject = New-Object PSCustomObject
            [array]$value = "{0}{1}\Exchange_Server_Data\Config" -f $Script:RootFilePath, $server.ServerName
            $value += "{0}{1}\Exchange_Server_Data\WebAppPools" -f $Script:RootFilePath, $server.ServerName
            $argumentObject | Add-Member -MemberType NoteProperty -Name NewFolders -Value $value
            $serverCreateDirectory | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $argumentObject
            $serverListCreateDirectories += $serverCreateDirectory
        }
        Write-ScriptDebug("Getting Get-ExchangeInstallDirectory string to create Script Block")
        $getExchangeInstallDirectoryString = (${Function:Get-ExchangeInstallDirectory}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
        Write-ScriptDebug("Creating Script Block")
        $getExchangeInstallDirectoryScriptBlock = [scriptblock]::Create($getExchangeInstallDirectoryString)
        $serverInstallDirectories = Start-JobManager -ServersWithArguments $serversObjectListInstall -ScriptBlock $getExchangeInstallDirectoryScriptBlock `
            -NeedReturnData $true `
            -DisplayReceiveJobInCorrectFunction $true `
            -JobBatchName "Exchange Install Directories for Write-LargeDataObjectsOnMachine"

        Write-ScriptDebug("Getting New-Folder string to create Script Block")
        $newFolderString = (${Function:New-Folder}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
        Write-ScriptDebug("Creating script block")
        $newFolderScriptBlock = [scriptblock]::Create($newFolderString)
        Write-ScriptDebug("Calling job for folder creation")
        Start-JobManager -ServersWithArguments $serverListCreateDirectories -ScriptBlock $newFolderScriptBlock `
            -DisplayReceiveJobInCorrectFunction $true `
            -JobBatchName "Creating folders for Write-LargeDataObjectsOnMachine"

        $serverListLocalDataGet = @()
        $serverListZipData = @()

        foreach ($server in $exchangeServerData) {

            $location = "{0}{1}\Exchange_Server_Data" -f $Script:RootFilePath, $server.ServerName
            #Write Data
            $argumentList = New-Object PSCustomObject
            $argumentList | Add-Member -MemberType NoteProperty -Name Location -Value $location
            $argumentList | Add-Member -MemberType NoteProperty -Name InstallDirectory -Value $serverInstallDirectories[$server.ServerName]
            $serverDumpData = New-Object PSCustomObject
            $serverDumpData | Add-Member -MemberType NoteProperty -Name ServerName -Value $server.ServerName
            $serverDumpData | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $argumentList
            $serverListLocalDataGet += $serverDumpData

            #Zip data if not Master Server cause we might have more stuff to run
            if ($server.ServerName -ne $Script:MasterServer) {
                $folder = "{0}{1}" -f $Script:RootFilePath, $server.ServerName
                $parameters = New-Object PSCustomObject
                $parameters | Add-Member -MemberType NoteProperty -Name "Folder" -Value $folder
                $parameters | Add-Member -MemberType NoteProperty -Name "IncludeMonthDay" -Value $true
                $parameters | Add-Member -MemberType NoteProperty -Name "IncludeDisplayZipping" -Value $true

                $serverZipData = New-Object PSCustomObject
                $serverZipData | Add-Member -MemberType NoteProperty -Name ServerName -Value $server.ServerName
                $serverZipData | Add-Member -MemberType NoteProperty -Name ArgumentList -Value $parameters
                $serverListZipData += $serverZipData
            }
        }

        $localServerTempLocation = "{0}{1}\Exchange_Server_Data_Temp\" -f $Script:RootFilePath, $env:COMPUTERNAME
        #Write the data locally to the temp file, then copy the data to the correct location.
        foreach ($server in $exchangeServerData) {
            $location = "{0}{1}\Exchange_Server_Data" -f $Script:RootFilePath, $server.ServerName
            Write-ScriptDebug("Location of data should be at: {0}" -f $location)
            $remoteLocation = "\\{0}\{1}" -f $server.ServerName, $location.Replace(":", "$")
            Write-ScriptDebug("Remote Copy Location: {0}" -f $remoteLocation)
            $rootTempLocation = "{0}{1}" -f $localServerTempLocation, $server.ServerName
            Write-ScriptDebug("Local Root Temp Location: {0}" -f $rootTempLocation)
            New-Folder -NewFolders $rootTempLocation

            Write-ExchangeDataLocally -ServerData $server -Location $rootTempLocation

            $items = Get-ChildItem $rootTempLocation
            $items | ForEach-Object { Copy-Item $_.VersionInfo.FileName $remoteLocation }
        }
        Remove-Item $localServerTempLocation -Force -Recurse
        Write-ScriptDebug("Calling Write-ExchangeData")
        Start-JobManager -ServersWithArguments $serverListLocalDataGet -ScriptBlock ${Function:Write-ExchangeData} `
            -DisplayReceiveJob $false `
            -JobBatchName "Write the data for Write-LargeDataObjectsOnMachine"
        Write-ScriptDebug("Calling job for Zipping the data")
        Write-ScriptDebug("Getting Compress-Folder string to create Script Block")
        $compressFolderString = (${Function:Compress-Folder}).ToString().Replace("#Function Version", (Get-WritersToAddToScriptBlock))
        Write-ScriptDebug("Creating script block")
        $compressFolderScriptBlock = [scriptblock]::Create($compressFolderString)
        Start-JobManager -ServersWithArguments $serverListZipData -ScriptBlock $compressFolderScriptBlock `
            -DisplayReceiveJobInCorrectFunction $true `
            -JobBatchName "Zipping up the data for Write-LargeDataObjectsOnMachine"
    } else {

        if ($null -eq $ExInstall) {
            $ExInstall = Get-ExchangeInstallDirectory
        }
        $location = "{0}{1}\Exchange_Server_Data" -f $Script:RootFilePath, $exchangeServerData.ServerName
        [array]$createFolders = @(("{0}\Config" -f $location), ("{0}\WebAppPools" -f $location))
        New-Folder -NewFolders $createFolders -IncludeDisplayCreate $true
        $passInfo = New-Object PSCustomObject
        $passInfo | Add-Member -MemberType NoteProperty -Name ServerObject -Value $exchangeServerData
        $passInfo | Add-Member -MemberType NoteProperty -Name Location -Value $location
        $passInfo | Add-Member -MemberType NoteProperty -Name InstallDirectory -Value $ExInstall

        Write-ExchangeDataLocally -Location $location -ServerData $exchangeServerData
        Write-ScriptDebug("Writing out the Exchange data")
        Write-ExchangeData -PassedInfo $passInfo
        $folder = "{0}{1}" -f $Script:RootFilePath, $exchangeServerData.ServerName
    }
}