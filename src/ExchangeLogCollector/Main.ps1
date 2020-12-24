Function Main {

    <#
    Added the ability to call functions from within a bundled function so i don't have to duplicate work. 
    Loading the functions into memory by using the '.' allows me to do this, 
    providing that the calling of that function doesn't do anything of value when doing this. 
    #>
    $obj = New-Object PSCustomObject 
    $obj | Add-Member -MemberType NoteProperty -Name ByPass -Value $true 
    . Remote-Functions -PassedInfo $obj 
    Start-Sleep 1
    Write-Disclaimer
    Test-PossibleCommonScenarios
    Test-NoSwitchesProvided
    if(-not (Confirm-Administrator))
    {
        Write-ScriptHost -WriteString ("Hey! The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator.") -ForegroundColor "Yellow"
        exit 
    }
    if(-not(Confirm-ExchangeShell -LoadExchangeVariables $false))
    {
        Write-ScriptHost -WriteString ("It appears that you are not on an Exchange 2010 or newer server. Sorry I am going to quit.") -ShowServer $false 
        exit
    }

    $Script:RootFilePath = "{0}\{1}\" -f $FilePath, (Get-Date -Format yyyyMd)
    if((Confirm-LocalEdgeServer) -and $Servers -ne $null)
    {
        #If we are on an Exchange Edge Server, we are going to treat it like a single server on purpose as we recommend that the Edge Server is a non domain joined computer. 
        #Because it isn't a domain joined computer, we can't use remote execution
        Write-ScriptHost -WriteString ("Determined that we are on an Edge Server, we can only use locally collection for this role.") -ForegroundColor "Yellow"
        $Script:EdgeRoleDetected = $true 
        $Servers = $null
    }

    if($Servers -ne $null)
    {
        
        #possible to return null or only a single server back (localhost)
        $Script:ValidServers = Test-RemoteExecutionOfServers -ServerList $Servers
        if($Script:ValidServers -ne $null)
        {
            $Script:ValidServers = Test-DiskSpace -Servers $Script:ValidServers -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize
            Verify-LocalServerIsUsed $Script:ValidServers

            $argumentList = Get-ArgumentList -Servers $Script:ValidServers
            #I can do a try catch here, but i also need to do a try catch in the remote so i don't end up failing here and assume the wrong failure location
            try 
            {
                Invoke-Command -ComputerName $Script:ValidServers -ScriptBlock ${Function:Remote-Functions} -ArgumentList $argumentList -ErrorAction Stop
            }
            catch 
            {
                Write-Error "An error has occurred attempting to call Invoke-Command to do a remote collect all at once. Please notify ExToolsFeedback@microsoft.com of this issue. Stopping the script."
                exit
            }
            
            Start-WriteExchangeDataOnMachines
            Write-DataOnlyOnceOnLocalMachine
            $LogPaths = Get-RemoteLogLocation -Servers $Script:ValidServers -RootPath $Script:RootFilePath
            if((-not($SkipEndCopyOver)) -and (Test-DiskSpaceForCopyOver -LogPathObject $LogPaths -RootPath $Script:RootFilePath))
            {
                Write-ScriptHost -ShowServer $false -WriteString (" ") 
                Write-ScriptHost -ShowServer $false -WriteString ("Copying over the data may take some time depending on the network")
                foreach($svr in $LogPaths)
                {
                    #Don't want to do the local host
                    if($svr.ServerName -ne $env:COMPUTERNAME)
                    {
                        $remoteCopyLocation = "\\{0}\{1}" -f $svr.ServerName, ($svr.ZipFolder.Replace(":","$"))
                        Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Copying File {1}...." -f $svr.ServerName, $remoteCopyLocation) 
                        Copy-Item -Path $remoteCopyLocation -Destination $Script:RootFilePath
                        Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Done copying file" -f $svr.ServerName)
                    }
                    
                }

            }
            else 
            {
                Write-ScriptHost -ShowServer $false -WriteString (" ")
                Write-ScriptHost -ShowServer $false -WriteString ("Please collect the following files from these servers and upload them: ")
                foreach($svr in $LogPaths)
                {
                    Write-ScriptHost -ShowServer $false -WriteString ("Server: {0} Path: {1}" -f $svr.ServerName, $svr.ZipFolder) 
                }
            }
        }
        else 
        {
            #We have failed to do invoke-command on all the servers.... so we are going to do the same logic locally
            Write-ScriptHost -ShowServer $false -WriteString ("Failed to do remote collection for all the servers in the list...") -ForegroundColor "Yellow"
            #want to test local server's free space first before moving to just collecting the data 
            if((Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize) -eq $null)
            {
                Write-ScriptHost -ShowServer $false -WriteString ("Failed to have enough space available locally as well. We can't continue with the data collection") -ForegroundColor "Yellow" 
                exit 
            }
            if((Enter-YesNoLoopAction -Question "Do you want to collect from the local server only?" -YesAction {return $true} -NoAction {return $false}))
            {
                Remote-Functions -PassedInfo (Get-ArgumentList -Servers $env:COMPUTERNAME)
                $Script:ValidServers = @($env:COMPUTERNAME)
                Start-WriteExchangeDataOnMachines
                Write-DataOnlyOnceOnLocalMachine
            }
            
        }
    }

    else 
    {
        if((Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize) -eq $null)
        {
            exit
        }
        if(-not($Script:EdgeRoleDetected))
        {
            Write-ScriptHost -ShowServer $false -WriteString ("Note: Remote Collection is now possible for Windows Server 2012 and greater on the remote machine. Just use the -Servers paramater with a list of Exchange Server names") -ForegroundColor "Yellow"
            Write-ScriptHost -ShowServer $false -WriteString ("Going to collect the data locally")
        }
        Remote-Functions -PassedInfo (Get-ArgumentList -Servers $env:COMPUTERNAME)
        $Script:ValidServers = @($env:COMPUTERNAME)
        Start-WriteExchangeDataOnMachines
        Write-DataOnlyOnceOnLocalMachine 
    }

    Write-FeedBack
        
}

Main 