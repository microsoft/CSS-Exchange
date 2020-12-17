#################################################################################
# 
# The sample scripts are not supported under any Microsoft standard support 
# program or service. The sample scripts are provided AS IS without warranty 
# of any kind. Microsoft further disclaims all implied warranties including, without 
# limitation, any implied warranties of merchantability or of fitness for a particular 
# purpose. The entire risk arising out of the use or performance of the sample scripts 
# and documentation remains with you. In no event shall Microsoft, its authors, or 
# anyone else involved in the creation, production, or delivery of the scripts be liable 
# for any damages whatsoever (including, without limitation, damages for loss of business 
# profits, business interruption, loss of business information, or other pecuniary loss) 
# arising out of the use of or inability to use the sample scripts or documentation, 
# even if Microsoft has been advised of the possibility of such damages
#
#################################################################################
#
# Version: v1.2 [https://github.com/Microsoft/VSSTESTER]
#
# Authors: Michael Barta <mbarta@microsoft.com>,
#          Muralidharan Natarajan <munatara@microsoft.com>,
#          Matthew Huynh <mahuynh@microsoft.com>
#
#################################################################################
#
# Purpose:
# This script will allow you to test VSS functionality on Exchange server using DiskShadow.
# The script will automatically detect active and passive database copies running on the server.
# The general logic is:
# - start a PowerShell transcript
# - enable ExTRA tracing
# - enable VSS tracing
# - optionally: create the diskshadow config file with shadow expose enabled,
#               execute VSS backup using diskshadow,
#               delete the VSS snapshot post-backup
# - stop PowerShell transcript
#
#################################################################################

Clear-host

# if a transcript is running, we need to stop it as this script will start its own
try {
Stop-Transcript | Out-Null
} catch [System.InvalidOperationException] { }

Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

write-host "****************************************************************************************"
write-host "****************************************************************************************" 
write-host "**                                                                                    **" -BackgroundColor DarkMagenta
write-host "**        VSSTESTER SCRIPT VERSION 1.2 (for Exchange 2010, 2013, 2016, 2019)          **" -foregroundcolor Cyan -BackgroundColor DarkMagenta
write-host "**                                                                                    **" -BackgroundColor DarkMagenta
write-host "****************************************************************************************" 
write-host "****************************************************************************************" 

#newLine shortcut
$script:nl = "`r`n"
$nl

#start time
$startInfo = Get-Date
get-date

if ($DebugPreference -ne 'SilentlyContinue') {
    $nl
    Write-Host 'This script is running in DEBUG mode since $DebugPreference is not set to SilentlyContinue.' -ForegroundColor Red
}

$nl
Write-Host "Please select the operation you would like to perform from the following options:" -foregroundcolor Green
$nl
Write-Host "  1. " -foregroundcolor Yellow -nonewline; Write-host "Test backup using built-in Diskshadow"
Write-Host "  2. " -foregroundcolor Yellow -nonewline; Write-Host "Enable logging to troubleshoot backup issues"
$nl

$matchCondition = "^[1|2]$"
Write-Debug "matchCondition: $matchCondition"
Do
{
    Write-host "Selection: " -foregroundcolor Yellow -nonewline;
    $Selection = Read-Host
    if($Selection -notmatch $matchCondition) 
    {
        Write-host "Error! Please select a valid option!" -ForegroundColor Red
    }
}
while ($Selection -notmatch $matchCondition) 


#=======================================
#Function to check VSSAdmin List Writers status
function listVSSWritersBefore
{
	" "
    get-date
	Write-host "Checking VSS Writer Status: (All Writers must be in a Stable state before running this script)" -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
	$writers = (vssadmin list writers)
	$writers > $path\vssWritersBefore.txt

	foreach ($line in $writers)
	{
		if ($line -like "Writer name:*")
		{
		"$line"
		}
		elseif ($line -like "   State:*")
		{
			if ($line -ne "   State: [1] Stable")
			{
			$nl
			write-host "!!!!!!!!!!!!!!!!!!!!!!!!!!   WARNING   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -foregroundcolor red
			$nl
			Write-Host "One or more writers are NOT in a 'Stable' state, STOPPING SCRIPT." -foregroundcolor red
			$nl
			Write-Host "Review the vssWritersBefore.txt file in '$path' for more information." -ForegroundColor Red
			write-host "You can also use an Exchange Management Shell or a Command Prompt to run: 'vssadmin list writers'" -foregroundcolor red
			$nl
			write-host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -foregroundcolor red
			$nl
			stopTransLog
			do
			{
				Write-Host
				$continue = Read-Host "Please use the <Enter> key to exit..."
			}
			While ($continue -notmatch $null)
			exit
			}
			else
			{
			"$line" + $nl
			}
		}
	}
	" " + $nl
}

function listVSSWritersAfter
{
	" "
    get-date
	Write-host "Checking VSS Writer Status: (after backup)" -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
	" "
	$writers = (vssadmin list writers)
	$writers1 = (vssadmin list writers)
	$writers > $path\vssWritersAfter.txt

	foreach ($line in $writers)
	{
		if ($line -like "Writer name:*")
		{
		"$line"
		}
		elseif ($line -like "   State:*")
		{
		"$line" + $nl		
		}
	}
	}
	
#==============================
#function to start a transcript log
function startTransLog
{
	$nl
    Get-Date
	Write-host "Starting transcript..." -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"

    start-transcript -path "$($script:path)\vssTranscript.log"
    $nl	
} 


#==============================
#4. function to stop a transcript log
function stopTransLog
{
    " " + $nl 
    Get-Date
	write-host "Stopping transcript log..." -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
    stop-transcript
    " " + $nl
	 do
			{
				Write-Host
				$continue = Read-Host "Please use the <Enter> key to exit..."
			}
			While ($continue -notmatch $null)
		exit
} 


#==============================
#5. function to enable diagnostics logging
function enableDiagLogging
{
	" "
    Get-date
   	write-host "Enabling Diagnostics Logging..." -foregroundcolor green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
   set-eventloglevel 'MSExchange Repl\Service' -level expert 
    $getReplSvc = get-eventloglevel 'MSExchange Repl\Service'
    write-host $getReplSvc.Identity " - " $getReplSvc.eventlevel  $nl

    set-eventloglevel 'MSExchange Repl\Exchange VSS Writer' -level expert
    $getReplVSSWriter = get-eventloglevel 'MSExchange Repl\Exchange VSS Writer'
    write-host $getReplVSSWriter.identity " - " $getReplVSSWriter.eventlevel  $nl

    if ($exchVer -eq "2010") {
        set-eventloglevel 'MSExchangeIS\9002 System\Backup Restore' -level expert
        $getBackRest = get-eventloglevel 'MSExchangeIS\9002 System\Backup Restore'
        write-host $getBackRest.identity " - " $getBackRest.eventlevel  $nl
    }
}



#===============================
#6. function to disable diagnostics logging
function disableDiagLogging
{
	
    write-host " "  $nl
    Get-Date
    write-host "Disabling Diagnostics Logging..." -foregroundcolor green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
    set-eventloglevel 'MSExchange Repl\Service' -level lowest
    $disgetReplSvc = get-eventloglevel 'MSExchange Repl\Service'
    write-host $disgetReplSvc.Identity " - " $disgetReplSvc.eventlevel $nl  

    set-eventloglevel 'MSExchange Repl\Exchange VSS Writer' -level lowest
    $disgetReplVSSWriter = get-eventloglevel 'MSExchange Repl\Exchange VSS Writer'
    write-host $disgetReplVSSWriter.identity " - " $disgetReplVSSWriter.eventlevel $nl
    
    if ($exchVer -eq "2010") {
        set-eventloglevel 'MSExchangeIS\9002 System\Backup Restore' -level lowest
        $disgetBackRest = get-eventloglevel 'MSExchangeIS\9002 System\Backup Restore'
        write-host $disgetBackRest.identity " - " $disgetBackRest.eventlevel $nl
    }
}



#==============================
#7. function to get the server name
function getLocalServerName
{   
    Get-Date
	Write-host "Getting Server name..." -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
    $script:serverName = Hostname
	Write-Host $serverName
	Write-Host " " $nl
}


#==============================
#8. function to get Exchange version
function exchVersion
{
    Get-Date
	Write-host "Verifying Exchange version..." -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------" 
	" "
    $script:exchVer = (get-exchangeserver $serverName).admindisplayversion
    $exchVerMajor = $exchVer.major
    $exchVerMinor = $exchVer.minor
    
    switch ($exchVerMajor) {
        "14" {
	        $script:exchVer = "2010"
        }
        "15" {
            switch ($exchVerMinor) {
                "0" {
	                $script:exchVer = "2013"
                }
                "1" {
	                $script:exchVer = "2016"
				}
				"2" {
					$script:exchVer = "2019"
				}
            }
        }
            
        default {
            write-host "This script is only for Exchange 2010, 2013, 2016, and 2019 servers." -foregroundcolor red $nl
		    do
			{
				Write-Host
				$continue = Read-Host "Please use the <Enter> key to exit..."
			}
			While ($continue -notmatch $null)
		    exit }
    }

    write-host "$serverName is an Exchange $exchVer server." $nl
}


#==============================
#9. function to get list of databases
function getDatabases
{		
    Get-Date
    write-host "Getting databases on server:" $serverName -foregroundcolor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
    
    [array]$script:databases = get-mailboxdatabase -server $serverName -status
	if ((Get-PublicFolderDatabase -Server $serverName) -ne $null)
	{
        $script:databases += get-publicfolderdatabase -server $serverName -status
	}
    
    #write-host "Database Name:`t`t Mounted: `t`t Mounted On Server:" -foregroundcolor Yellow $nl
    $script:dbID = 0
    
    foreach ($script:db in $databases)
    {
        $script:db | Add-Member NoteProperty Number $dbID
        
        $dbID++
    }
    
    $script:databases | ft Number,Name,Mounted,Server -AutoSize | Out-String
    
    write-host " " $nl
}


#============================================

#function to check database copy status
#Function runs agains the selected database to see if the copies of mailbox database are in healthy state.
function copystatus
{
	if ((($databases[$dbtoBackup]).ismailboxdatabase) -eq "True")
	{
        Get-Date
		Write-host "Status of '$selDB' and its replicas (if any)" -foregroundcolor Green $nl
		Write-Host "--------------------------------------------------------------------------------------------------------------" 
		" "
		[array]$copystatus =(get-mailboxdatabasecopystatus -identity ($databases[$dbtoBackup]).name)
		($copystatus|fl) | Out-File -filepath "$path\copystatus.txt"
			for($i = 0; $i -lt ($copystatus).length; $i++ )
			{
				if (($copystatus[$i].status -eq "Healthy") -or ($copystatus[$i].status -eq "Mounted"))
				{
				write-host $copystatus[$i].name is $copystatus[$i].status
				}
				else
				{
				write-host $copystatus[$i].name is $copystatus[$i].status
				write-host "One of the copies of the seelected database is not healthy. Please run backup after ensuring that the database copy is healthy" -Foregroundcolor Yellow
				stopTransLog
				do
			{
				Write-Host
				$continue = Read-Host "Please use the <Enter> key to exit..."
			}
			While ($continue -notmatch $null)
				exit
				}
			}
	}
	Else
		{
		Write-host "Not checking database copy status since the selected database is a Public Folder Database..."
		}
" "
}
   
   
#==============================
#10. function to select the database to backup
function getDBtoBackup
{
    $maxDbIndexRange = $script:databases.length-1
    $matchCondition = "^([0-9]|[1-9][0-9])$"
    Write-Debug "matchCondition: $matchCondition"
	do {
        Write-host "Select the number of the database to backup" -foregroundcolor Yellow -nonewline;
        $script:dbtoBackup=Read-Host " "
        
        if ($script:dbtoBackup -notmatch $matchCondition -or [int]$script:dbtoBackup -gt $maxDbIndexRange) {
            Write-host "Error! Please select a valid option!" -ForegroundColor Red
        }
    	
    } while ($script:dbtoBackup -notmatch $matchCondition -or [int]$script:dbtoBackup -gt $maxDbIndexRange) # notmatch is case-insensitive
	
		if ((($databases[$dbtoBackup]).ismailboxdatabase) -eq "True")
		{

		$script:dbGuid = (get-mailboxdatabase ($databases[$dbtoBackup])).guid
	    $script:selDB = (get-mailboxdatabase ($databases[$dbtoBackup])).name
		" "
	    "The database guid for '$selDB' is: $dbGuid"
		" "
	    $script:dbMountedOn = (get-mailboxdatabase ($databases[$dbtoBackup])).server.name
		}
		else
		{
	    $script:dbGuid = (get-publicfolderdatabase ($databases[$dbtoBackup])).guid
	    $script:selDB = (get-publicfolderdatabase ($databases[$dbtoBackup])).name
	    "The database guid for '$selDB' is: $dbGuid"
		" "
	    $script:dbMountedOn = (get-publicfolderdatabase ($databases[$dbtoBackup])).server.name
		}
	    write-host "The database is mounted on server: $dbMountedOn" $nl
	    
		if ($dbMountedOn -eq "$serverName")
		{
			$script:dbStatus = "active"
	    }
	    else
	    {
	       $script:dbStatus = "passive"
	    } 
}

function Out-DHSFile 
{ 
param ([string]$fileline) 
$fileline | Out-File -filepath "$path\diskshadow.dsh" -Encoding ASCII -Append 
}


function Out-removeDHSFile 
{ 
param ([string]$fileline) 
$fileline | Out-File -filepath "$path\removeSnapshot.dsh" -Encoding ASCII -Append 
}


#============================
#12. function to create diskshadow file
function createDiskShadowFile
{
	
#	creates the diskshadow.dsh file that will be written to below
#	-------------------------------------------------------------
	$nl
    Get-Date
	Write-host "Creating diskshadow config file..." -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
	$nl
	new-item -path $path\diskshadow.dsh -type file -force | Out-Null

#	beginning lines of file
#	-----------------------
	Out-DHSFile "set verbose on"
	Out-DHSFile "set context persistent"
	Out-DHSFile " "

#	writers to exclude
#	------------------
	Out-DHSFile "writer exclude {e8132975-6f93-4464-a53e-1050253ae220}"
	Out-DHSFile "writer exclude {2a40fd15-dfca-4aa8-a654-1f8c654603f6}"
	Out-DHSFile "writer exclude {35E81631-13E1-48DB-97FC-D5BC721BB18A}"
	Out-DHSFile "writer exclude {be000cbe-11fe-4426-9c58-531aa6355fc4}"
	Out-DHSFile "writer exclude {4969d978-be47-48b0-b100-f328f07ac1e0}"
	Out-DHSFile "writer exclude {a6ad56c2-b509-4e6c-bb19-49d8f43532f0}"
	Out-DHSFile "writer exclude {afbab4a2-367d-4d15-a586-71dbb18f8485}"
	Out-DHSFile "writer exclude {59b1f0cf-90ef-465f-9609-6ca8b2938366}"
	Out-DHSFile "writer exclude {542da469-d3e1-473c-9f4f-7847f01fc64f}"
	Out-DHSFile "writer exclude {4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f}"
	Out-DHSFile "writer exclude {41e12264-35d8-479b-8e5c-9b23d1dad37e}"
	Out-DHSFile "writer exclude {12ce4370-5bb7-4C58-a76a-e5d5097e3674}"
	Out-DHSFile "writer exclude {cd3f2362-8bef-46c7-9181-d62844cdc062}"
	Out-DHSFile "writer exclude {dd846aaa-A1B6-42A8-AAF8-03DCB6114BFD}"
	Out-DHSFile "writer exclude {B2014C9E-8711-4C5C-A5A9-3CF384484757}"
	Out-DHSFile "writer exclude {BE9AC81E-3619-421F-920F-4C6FEA9E93AD}"	
	Out-DHSFile "writer exclude {F08C1483-8407-4A26-8C26-6C267A629741}"
	Out-DHSFile "writer exclude {6F5B15B5-DA24-4D88-B737-63063E3A1F86}"
	Out-DHSFile "writer exclude {368753EC-572E-4FC7-B4B9-CCD9BDC624CB}"
	Out-DHSFile "writer exclude {5382579C-98DF-47A7-AC6C-98A6D7106E09}"
	Out-DHSFile "writer exclude {d61d61c8-d73a-4eee-8cdd-f6f9786b7124}"
	Out-DHSFile "writer exclude {75dfb225-e2e4-4d39-9ac9-ffaff65ddf06}"
	Out-DHSFile "writer exclude {0bada1de-01a9-4625-8278-69e735f39dd2}"
    Out-DHSFile "writer exclude {a65faa63-5ea8-4ebc-9dbd-a0c4db26912a}"
	Out-DHSFile " "

#	add databases to exclude
#	------------------------
	foreach ($db in $databases)
		{
		$dbg = ($db.guid)
		
		if (($db).guid -ne $dbGuid)
			{
			if (($db.ismailboxdatabase) -eq "True")
			{				
			$mountedOnServer = (get-mailboxdatabase $db).server.name
			}
			else
			{
			$mountedOnServer = (get-publicfolderdatabase $db).server.name
			}
			if ($mountedOnServer -eq $serverName)
			{
			$script:activeNode = $true
			
			Out-DHSFile "writer exclude `"Microsoft Exchange Writer:\Microsoft Exchange Server\Microsoft Information Store\$serverName\$dbg`""
			}
		#if passive copy, add it with replica in the string
		else
		{
		$script:activeNode = $false
		Out-DHSFile "writer exclude `"Microsoft Exchange Replica Writer:\Microsoft Exchange Server\Microsoft Information Store\Replica\$serverName\$dbg`""
		}			
			}
#	add database to include
#	-----------------------		
		else 
			{			
			if (($db.ismailboxdatabase) -eq "True")
			{
			$mountedOnServer = (get-mailboxdatabase $db).server.name
			}
			else
			{
			$mountedOnServer = (get-publicfolderdatabase $db).server.name
			}
			
						
				
			}
		}
		Out-DHSFile " "
	
#	-------------
	Out-DHSFile "Begin backup"

#	add the volumes for the included database
#	-----------------------------------------
	#gets a list of mount points on local server
	$mpvolumes = get-wmiobject -query "select name, deviceid from win32_volume where drivetype=3 AND driveletter=NULL" 
	$deviceIDs = @()
	
	#if selected database is a mailbox database, get mailbox paths
	if ((($databases[$dbtoBackup]).ismailboxdatabase) -eq "True")
	{
		$getDB = (get-mailboxdatabase $selDB)
	    
   		$dbMP = $false
		$logMP = $false
		
		#if no mountpoints ($mpvolumes) causes null-valued error, need to handle
		if ($mpvolumes -ne $null)
		{ 
		foreach ($mp in $mpvolumes)
		{
		$mpname=(($mp.name).substring(0,$mp.name.length -1))
			#if following mount point path exists in database path use deviceID in diskshadow config file
			 if ($getDB.edbFilePath.pathname.ToString().ToLower().StartsWith($mpname.ToString().ToLower()))
			 {
			 Write-Host " "
			 write-host "Mount point: " $mp.name " in use for database path: "
			 #Write-host "Yes. I am a database in mountpoint"
			 "The selected database path is: " + $getDB.edbFilePath.pathname
			 Write-Host "adding deviceID to file: "
			 $dbEdbVol = $mp.deviceid
			 Write-Host $dbEdbVol
	
			 #add device ID to array
			  $deviceID1 = $mp.DeviceID
			 $dbMP = $true
			}
		
			#if following mount point path exists in log path use deviceID in diskshadow config file
			 if ($getDB.logFolderPath.pathname.ToString().ToLower().contains($mpname.ToString().ToLower()))
			 {
			 Write-Host " "
			 write-host "Mount point: " $mp.name " in use for log path: "
			 #Write-host "Yes. My logs are in a mountpoint"
			 "The log folder path of selected database is: " + $getDB.logfolderPath.pathname
			 Write-Host "adding deviceID to file: "
			 $dbLogVol = $mp.deviceid
			 write-host $dbLogVol
			 $deviceID2 =$mp.DeviceID
			 $logMP = $true	
			 }
			
		}
		$deviceIDs = $deviceID1,$deviceID2
		}
	}	
	
	#if not a mailbox database, assume its a public folder database, get public folder paths
	
	if ((($databases[$dbtoBackup]).ispublicfolderdatabase) -eq "True")
	{
	$getDB = (get-publicfolderdatabase $selDB)
	
	$dbMP = $false
	$logMP = $false
	
	if ($mpvolumes -ne $null)
	{
	foreach ($mp in $mpvolumes)
			{
$mpname=(($mp.name).substring(0,$mp.name.length -1))	
	#if following mount point path exists in database path use deviceID in diskshadow config file
			
			if ($getDB.edbFilePath.pathname.ToString().ToLower().StartsWith($mpname.ToString().ToLower()))
			{
			Write-Host " "
			write-host "Mount point: " $mp.name " in use for database path: "
			"The current database path is: " + $getDB.edbFilePath.pathname
			Write-Host "adding deviceID to file: "
			$dbEdbVol = $mp.deviceid
			Write-Host $dbvol
	
			#add device ID to array
			$deviceID1 = $mp.DeviceID
			$dbMP = $true
			}
		
			#if following mount point path exists in log path use deviceID in diskshadow config file
			
			 if ($getDB.logFolderPath.pathname.ToString().ToLower().contains($mpname.ToString().ToLower()))
			 {
			 Write-Host " "
			 write-host "Mount point: " $vol.name " in use for log path: "
			"The log folder path of selected database is: " + $getDB.logfolderPath.pathname
			 Write-Host "adding deviceID to file "
			 $dbLogVol = $mp.deviceid
			 write-host $dblogvol
	
			 $deviceID2 =$mp.DeviceID
			 $logMP = $true	
			 }
		}
	$deviceIDs = $deviceID1,$deviceID2
	}
	}
			
	if ($dbMP -eq $false)
	{
    
	$dbEdbVol = ($getDB.edbfilepath.pathname).substring(0,2)
	"The selected database path is '" + $getDB.edbFilePath.pathname + "' so adding volume $dbEdbVol to backup scope"
	$deviceID1 = $dbEdbVol	
	}
	
	if ($logMP -eq $false)
	{
	$dbLogVol = ($getDB.logFolderpath.pathname).substring(0,2)
	$nl
	"The selected database log folder path is '" + $getDB.logFolderpath.pathname + "' so adding volume $dbLogVol to backup scope"
	$deviceID2 = $dbLogVol
	}
	
# Here is where we start adding the appropriate volumes or mountpoints to the diskshadow config file
# We make sure that we add only one Logical volume when we detect the EDB and log files
# are on the same volume
	
    $nl
	$deviceIDs = $deviceID1,$deviceID2 
	$comp = [string]::Compare($deviceID1, $deviceID2, $True)
	If($comp -eq 0)
	{
	$dID = $deviceIDs[0]
	Write-Debug -Message ('$dID = ' + $dID.ToString())
	Write-Debug "When the database and log files are on the same volume, we add the volume only once"
	if ($dID.length -gt "2")
	 {
	 $addVol = "add volume $dID alias vss_test_" + ($dID).tostring().substring(11,8)
     write-host $addVol
	 Out-DHSFile $addVol
	 }
	 else
	{
	$addVol = "add volume $dID alias vss_test_" + ($dID).tostring().substring(0,1)
    write-host $addVol
	Out-DHSFile $addVol
	}
	
	}

	
	else
	 {
	Write-Host " "
	foreach ($device in $deviceIDs)
	{
	if ($device.length -gt "2")
	 {
	 Write-Host "Adding the Mount Point for DSH file"
	 $addVol = "add volume $device alias vss_test_" + ($device).tostring().substring(11,8)
     Write-Host $addVol
	 Out-DHSFile $addVol
	 }
	 else
	{
	Write-Host "Adding the volume for DSH file"
	$addVol = "add volume $device alias vss_test_" + ($device).tostring().substring(0,1)
    Write-Host $addVol
	Out-DHSFile $addVol
	}
	}
	 }
	Out-DHSFile "create"	
	Out-DHSFile " "

    $nl
    Get-Date
    Write-host "Getting drive letters for exposing backup snapshot" -foregroundcolor Green
    Write-Host "--------------------------------------------------------------------------------------------------------------"

    # check to see if the drives are the same for both database and logs
    # if the same volume is used, only one drive letter is needed for exposure
    # if two volumes are used, two drive letters are needed
    
    $matchCondition = "^[a-z]:$"
    write-debug $matchCondition
	
	if ($dbEdbVol -eq $dbLogVol)
		{
		$nl
		"Since the same volume is used for this database's EDB and logs, we only need a single drive"
        "letter to expose the backup snapshot."	
		$nl
        
        do {
            Write-host "Enter an unused drive letter with colon (e.g. X:) to expose the snapshot" -foregroundcolor Yellow -nonewline;
            $script:dbsnapvol = read-host " "
            if ($dbsnapvol -notmatch $matchCondition) {
                Write-Host "Your input was not acceptable. Please use a single letter and colon, e.g. X:" -ForegroundColor red
            }
        } while ($dbsnapvol -notmatch $matchCondition)
        
		}
	else
		{
        $nl
		"Since different volumes are used for this database's EDB and logs, we need two drive"
        "letters to expose the backup snapshot."	
		$nl
        
        do {
            Write-host "Enter an unused drive letter with colon (e.g. X:) to expose the DATABASE volume" -foregroundcolor Yellow -nonewline;
            $script:dbsnapvol = read-host " "
            if ($dbsnapvol -notmatch $matchCondition) {
                Write-Host "Your input was not acceptable. Please use a single letter and colon, e.g. X:" -ForegroundColor red
            }
        } while ($dbsnapvol -notmatch $matchCondition)
        
        do {
            Write-host "Enter an unused drive letter with colon (e.g. Y:) to expose the LOG volume" -foregroundcolor Yellow -nonewline;
            $script:logsnapvol = read-host " "
            if ($logsnapvol -notmatch $matchCondition) {
                Write-Host "Your input was not acceptable. Please use a single letter and colon, e.g. Y:" -ForegroundColor red
            }
            if ($logsnapvol -eq $dbsnapvol) {
                Write-Host "You must choose a different drive letter than the one chosen to expose the DATABASE volume." -ForegroundColor red
            }
        } while (($logsnapvol -notmatch $matchCondition) -or ($logsnapvol -eq $dbsnapvol))
        
		$nl
		}

    Write-Debug "dbsnapvol: $dbsnapvol | logsnapvol: $logsnapvol"

    # expose the drives
    # if volumes are the same only one entry is needed
	if ($dbEdbVol -eq $dbLogVol)
	{
		if ($dbEdbVol.length -gt "2")
		{
		$dbvolstr = "expose %vss_test_" + ($dbEdbVol).substring(11,8) + "% $dbsnapvol"
		Out-DHSFile $dbvolstr
		}
		else
		{
		$dbvolstr = "expose %vss_test_" + ($dbEdbVol).substring(0,1) + "% $dbsnapvol"
		Out-DHSFile $dbvolstr
		}
	}
    # volumes are different, getting both
	else
	{
		# if mountpoint use first part of string, if not use first letter
		if ($dbEdbVol.length -gt "2")
		{
		$dbvolstr = "expose %vss_test_" + ($dbEdbVol).substring(11,8) + "% $dbsnapvol"
		Out-DHSFile $dbvolstr
		}
		Else
		{
		$dbvolstr = "expose %vss_test_" + ($dbEdbVol).substring(0,1) + "% $dbsnapvol"
		Out-DHSFile $dbvolstr
		}
		
		# if mountpoint use first part of string, if not use first letter
		if ($dbLogVol.length -gt "2")
		{
		$logvolstr = "expose %vss_test_" + ($dbLogVol).substring(11,8) + "% $logsnapvol"	
		Out-DHSFile $logvolstr
		}
		else
		{
		$logvolstr = "expose %vss_test_" + ($dbLogVol).substring(0,1) + "% $logsnapvol"	
		Out-DHSFile $logvolstr
		}
	}

    # ending data of file
	Out-DHSFile "end backup"

}

#Function to remove exposed snapshots
#====================================

function removeExposedDrives
{
	" "
    Get-Date
	Write-host "Diskshadow Snapshots" -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
	Write-Host " "
    if ($logsnapvol -eq $null) {
        $exposedDrives = $dbsnapvol
    } else {
        $exposedDrives = $dbsnapvol.ToString() + " and " + $logsnapvol.ToString()
    }
	"If the snapshot was successful, the snapshot should be exposed as drive(s) $exposedDrives."
    "You should be able to see and navigate the snapshot with File Explorer. How would you like to proceed?"
	Write-host " "
	Write-host "When ready, choose from the options below:" -foregroundcolor Yellow
	" "
	write-host "  1. Remove exposed snapshot now" 
	write-host "  2. Keep snapshot exposed"
	Write-host " "
	Write-Warning "Selecting option 1 will permanently delete the snapshot created, i.e. your backup will be deleted."
	" "
    
    $matchCondition = "^[1-2]$"
    Write-Debug "matchCondition: $matchCondition"
    do {
	   Write-host "Selection" -foregroundcolor Yellow -nonewline
        $removeExpose = read-host " "
        if ($removeExpose -notmatch $matchCondition) {
        write-host "Error! Please choose a valid option." -ForegroundColor red
        }
    } while ($removeExpose -notmatch $matchCondition)
    
    $unexposeCommand = "delete shadows exposed $dbsnapvol"
	if ($logsnapvol -ne $null)
	{
       $unexposeCommand += $nl + "delete shadows exposed $logsnapvol"
	}
	
	if ($removeExpose -eq "1")
	{	
	new-item -path $path\removeSnapshot.dsh -type file -force

    Out-removeDHSFile $unexposeCommand
    Out-removeDHSFile "exit"

	invoke-expression "&'C:\Windows\System32\diskshadow.exe' /s $path\removeSnapshot.dsh"
	
	} elseif ($removeExpose -eq "2")
	{
	   write-host "You can remove the snapshots at a later time using the diskshadow tool from a command prompt."
       write-host "Run diskshadow followed by these commands:"
       write-host $unexposeCommand
    }	
}

function runDiskShadow
{
	write-host " " $nl
    Get-Date
	write-host "Starting DiskShadow copy of Exchange database: $selDB" -foregroundcolor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
	write-host "Running the following command:" $nl
	write-host "`"C:\Windows\System32\diskshadow.exe /s $path\diskshadow.dsh /l $path\diskshadow.log`"" $nl
	write-host " "
	
	diskshadow.exe /s $path\diskshadow.dsh /l $path\diskshadow.log
}

function Out-ExTRAConfigFile 
{ 
param ([string]$fileline) 
$fileline | Out-File -filepath "C:\EnabledTraces.Config" -Encoding ASCII -Append 
}

function create-ExTRATracingConfig
{
	" "
    Get-Date
	Write-host "Enabling ExTRA Tracing..." -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
    new-item -path "C:\EnabledTraces.Config" -type file -force
    
	Out-ExTRAConfigFile "TraceLevels:Debug,Warning,Error,Fatal,Info,Performance,Function,Pfd"
    if ($exchVer -eq "2010") {
	   Out-ExTRAConfigFile "Store:tagEseBack,tagVSS,tagJetBackup,tagJetRestore"
    } elseif ($exchVer -eq "2013" -or $exchVer -eq "2016" -or $exchVer -eq "2019") {
        Out-ExTRAConfigFile "ManagedStore.PhysicalAccess:JetBackup,JetRestore"
    }
	Out-ExTRAConfigFile "Cluster.Replay:ReplicaVssWriterInterop,ReplicaInstance,LogTruncater"
	Out-ExTRAConfigFile "FilteredTracing:No"
	Out-ExTRAConfigFile "InMemoryTracing:No"
	" "
    write-debug "ExTRA trace config file created successfully"
}

# if the user runs the script on passive node to monitor or perform a
# passive copy backup, ExTRA will be turned on in active node and at end of the backup,
# output ETL will be copied over to the active node

function enable-ExTRATracing
{
	
	#active server, only get tracing from active node
	if ($dbMountedOn -eq $serverName)
	{
    	" "
    	"Creating Exchange Trace data collector set..."
    	logman create trace VSSTester -p "Microsoft Exchange Server 2010" -o $path\vsstester.etl -ow
    	"Starting Exchange Trace data collector..."
    	logman start VSSTester
    	" "
	}
	#passive server, get tracing from both active and passive nodes
	else
	{
    	" "
    	"Copying the ExTRA config file 'EnabledTraces.config' file to $dbMountedOn..."
    	#copy enabledtraces.config from current passive copy to active copy server
    	copy-item "c:\EnabledTraces.Config" "\\$dbMountedOn\c$\enabledtraces.config" -Force
    	
    	#create trace on passive copy
    	"Creating Exchange Trace data collector set on $serverName..."
    	logman create trace VSSTester-Passive -p "Microsoft Exchange Server 2010" -o $path\vsstester-passive.etl -s $serverName -ow
    	#create trace on active copy
    	"Creating Exchange Trace data collector set on $dbMountedOn..."
    	logman create trace VSSTester-Active -p "Microsoft Exchange Server 2010" -o $path\vsstester-active.etl -s $dbMountedOn -ow
    	#start trace on passive copy	
    	"Starting Exchange Trace data collector on $serverName..."
    	logman start VSSTester-Passive -s $serverName
    	#start trace on active copy
    	"Starting Exchange Trace data collector on $dbMountedOn..."
    	logman start VSSTester-Active -s $dbMountedOn
    	" "
	}
	
	write-debug "ExTRA trace started successfully"
}

function disable-ExTRATracing
{
	" "
    Get-Date
	Write-host "Disabling ExTRA Tracing..." -foregroundcolor Green $nl
	Write-Host "--------------------------------------------------------------------------------------------------------------"
	" "
	if ($dbMountedOn -eq "$serverName")
	{
	#stop active copy
	Write-Host " "
	"Stopping Exchange Trace data collector on $serverName..." 
	logman stop vssTester -s $serverName
	"Deleting Exchange Trace data collector on $serverName..." 
	logman delete vssTester -s $serverName
	" "
	}
	
	else
	{
	#stop passive copy
	"Stopping Exchange Trace data collector on $serverName..." 
	logman stop vssTester-Passive -s $serverName
	"Deleting Exchange Trace data collector on $serverName..." 
	logman delete vssTester-Passive -s $serverName
	#stop active copy
	"Stopping Exchange Trace data collector on $dbMountedOn..." 
	logman stop vssTester-Active -s $dbMountedOn
	"Deleting Exchange Trace data collector on $dbMountedOn..." 
	logman delete vssTester-Active -s $dbMountedOn
	" "
	"Moving ETL file from $dbMountedOn to $serverName..."
	" "
	$etlPath = $path -replace ":\\", "$\"
	move-item "\\$dbMountedOn\$etlPath\vsstester-active_000001.etl" "\\$servername\$etlPath\vsstester-active_000001.etl" -Force
	}

}

#Function to get the path - save config files for diskshadow and output logs.
function get-Path
{
    
	$nl
	Write-host "Please specify a directory other than root of a volume to save the configuration and output files." -foregroundcolor Green
    
    $pathExists = $false
    
    # get path, ensuring it exists
    do {
        Write-host "Directory path (e.g. C:\temp): " -foregroundcolor Yellow -nonewline;
        $script:path = Read-Host
        Write-Debug "path: $path"
        try {
            $pathExists = Test-Path -Path "$path"
        } catch {
        }
        write-debug "pathExists: $pathExists"
        if ($pathExists -ne $true) {
            Write-host "Error! The path does not exist. Please enter a valid path." -ForegroundColor red
        }
    } while ($pathExists -ne $true)
}

#starts OS level VSS tracing
function enableVSSTracing
{
" "
Get-Date
Write-host "Enabling VSS Tracing..." -foregroundcolor Green $nl
Write-Host "--------------------------------------------------------------------------------------------------------------"
" "
logman start vss -o $path\vss.etl -ets -p "{9138500e-3648-4edb-aa4c-859e9f7b7c38}" 0xfff 255
}
#stop VSS tracings collection
function disableVSSTracing
{
" "
Get-Date
Write-host "Disabling VSS Tracing..." -foregroundcolor Green $nl
Write-Host "--------------------------------------------------------------------------------------------------------------"
" "
logman stop vss -ets
" "
}

#Here is where we wait for the end user to perform the backup using the backup software and then come back to the script to press "Enter", thereby stopping data collection
function start-3rdpartybackup
{
Get-Date
Write-host "Data Collection" -foregroundcolor green $nl
Write-Host "--------------------------------------------------------------------------------------------------------------"
" "
Write-Host "Data collection is now enabled." -foregroundcolor Yellow
Write-Host "Please start your backup using the third party software so the script can record the diagnostic data." -foregroundcolor Yellow
Write-Host "When the backup is COMPLETE, use the <Enter> key to terminate data collection..." -foregroundcolor Yellow -NoNewline
Read-host
}

function get-applogs
{
" "	
Get-Date
write-host "Getting events from the application and system logs since the script's start time of ($startInfo)" -foregroundcolor Green $nl
Write-Host "--------------------------------------------------------------------------------------------------------------"
" "
"Getting application log events..."
Get-EventLog -LogName Application -After $startInfo | export-clixml $path\events-App.xml
"Getting system log events..."
Get-EventLog -LogName System -After $startInfo | export-clixml $path\events-System.xml
"Getting events complete!"
}

# Based on the menu selection, we will execute different functions.
# We will perform get-path irrespective of the selection because we have to write the logs.

try {
	
	get-Path
			
	if ($Selection -eq 1)
		{
		startTranslog
		getLocalServerName
		exchVersion
		listVSSWritersBefore
		getDatabases
		getDBtoBackup
		copystatus
		createDiskShadowFile #---
		enableDiagLogging
		enableVSSTracing
		create-ExTRATracingConfig
		enable-ExTRATracing
		runDiskShadow #---
		disable-ExTRATracing
		disableDiagLogging
		disableVSSTracing
		listVSSWritersAfter
		removeExposedDrives #---
		get-applogs
		}
		
	elseif($Selection -eq 2)
		{
		startTranslog
		getLocalServerName
		exchVersion
		listVSSWritersBefore
		getDatabases
		getDBtoBackup
		copystatus
		enableDiagLogging
		enableVSSTracing
		create-ExTRATracingConfig
		enable-ExTRATracing
		start-3rdpartybackup #---
		disable-ExTRATracing
		disableDiagLogging
		disableVSSTracing
		listVSSWritersAfter
		get-applogs
		}
		
}
finally {
    # always stop our transcript at end of script's execution
    # we catch a failure here if we try to stop a transcript that's not running
    try { stopTransLog } catch {}
}
#End of script	