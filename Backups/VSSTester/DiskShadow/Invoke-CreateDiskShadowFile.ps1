function Invoke-CreateDiskShadowFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'Required to get drives on old systems')]
    param()

    function Out-DHSFile {
        param ([string]$fileline)
        $fileline | Out-File -FilePath "$path\diskshadow.dsh" -Encoding ASCII -Append
    }

    #	creates the diskshadow.dsh file that will be written to below
    #	-------------------------------------------------------------
    $nl
    Get-Date
    Write-Host "Creating diskshadow config file..." -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    $nl
    New-Item -Path $path\diskshadow.dsh -type file -Force | Out-Null

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
    foreach ($db in $databases) {
        $dbg = ($db.guid)

        if (($db).guid -ne $dbGuid) {
            if (($db.IsMailboxDatabase) -eq "True") {
                $mountedOnServer = (Get-MailboxDatabase $db).server.name
            } else {
                $mountedOnServer = (Get-PublicFolderDatabase $db).server.name
            }
            if ($mountedOnServer -eq $serverName) {
                $script:activeNode = $true

                Out-DHSFile "writer exclude `"Microsoft Exchange Writer:\Microsoft Exchange Server\Microsoft Information Store\$serverName\$dbg`""
            }
            #if passive copy, add it with replica in the string
            else {
                $script:activeNode = $false
                Out-DHSFile "writer exclude `"Microsoft Exchange Replica Writer:\Microsoft Exchange Server\Microsoft Information Store\Replica\$serverName\$dbg`""
            }
        }
        #	add database to include
        #	-----------------------
        else {
            if (($db.IsMailboxDatabase) -eq "True") {
                $mountedOnServer = (Get-MailboxDatabase $db).server.name
            } else {
                $mountedOnServer = (Get-PublicFolderDatabase $db).server.name
            }
        }
    }
    Out-DHSFile " "
    Out-DHSFile "Begin backup"

    #	add the volumes for the included database
    #	-----------------------------------------
    #gets a list of mount points on local server
    $mpvolumes = get-wmiobject -query "select name, deviceid from win32_volume where drivetype=3 AND driveletter=NULL"
    $deviceIDs = @()

    #if selected database is a mailbox database, get mailbox paths
    if ((($databases[$dbtoBackup]).IsMailboxDatabase) -eq "True") {
        $getDB = (Get-MailboxDatabase $selDB)

        $dbMP = $false
        $logMP = $false

        #if no mountpoints ($mpvolumes) causes null-valued error, need to handle
        if ($null -ne $mpvolumes) {
            foreach ($mp in $mpvolumes) {
                $mpname = (($mp.name).substring(0, $mp.name.length - 1))
                #if following mount point path exists in database path use deviceID in diskshadow config file
                if ($getDB.EdbFilePath.pathname.ToString().ToLower().StartsWith($mpname.ToString().ToLower())) {
                    Write-Host " "
                    Write-Host "Mount point:  $($mp.name) in use for database path: "
                    #Write-host "Yes. I am a database in mountpoint"
                    "The selected database path is: " + $getDB.EdbFilePath.pathname
                    Write-Host "adding deviceID to file: "
                    $dbEdbVol = $mp.deviceid
                    Write-Host $dbEdbVol

                    #add device ID to array
                    $deviceID1 = $mp.DeviceID
                    $dbMP = $true
                }

                #if following mount point path exists in log path use deviceID in diskshadow config file
                if ($getDB.LogFolderPath.pathname.ToString().ToLower().contains($mpname.ToString().ToLower())) {
                    Write-Host " "
                    Write-Host "Mount point: $($mp.name) in use for log path: "
                    #Write-host "Yes. My logs are in a mountpoint"
                    "The log folder path of selected database is: " + $getDB.LogFolderPath.pathname
                    Write-Host "adding deviceID to file: "
                    $dbLogVol = $mp.deviceid
                    Write-Host $dbLogVol
                    $deviceID2 = $mp.DeviceID
                    $logMP = $true
                }
            }
            $deviceIDs = $deviceID1, $deviceID2
        }
    }

    #if not a mailbox database, assume its a public folder database, get public folder paths
    if ((($databases[$dbtoBackup]).IsPublicFolderDatabase) -eq "True") {
        $getDB = (Get-PublicFolderDatabase $selDB)

        $dbMP = $false
        $logMP = $false

        if ($null -ne $mpvolumes) {
            foreach ($mp in $mpvolumes) {
                $mpname = (($mp.name).substring(0, $mp.name.length - 1))
                #if following mount point path exists in database path use deviceID in diskshadow config file

                if ($getDB.EdbFilePath.pathname.ToString().ToLower().StartsWith($mpname.ToString().ToLower())) {
                    Write-Host " "
                    Write-Host "Mount point: $($mp.name) in use for database path: "
                    "The current database path is: " + $getDB.EdbFilePath.pathname
                    Write-Host "adding deviceID to file: "
                    $dbEdbVol = $mp.deviceId
                    Write-Host $dbvol

                    #add device ID to array
                    $deviceID1 = $mp.DeviceID
                    $dbMP = $true
                }

                #if following mount point path exists in log path use deviceID in diskshadow config file
                if ($getDB.LogFolderPath.pathname.ToString().ToLower().contains($mpname.ToString().ToLower())) {
                    Write-Host " "
                    Write-Host "Mount point: $($vol.name) in use for log path: "
                    "The log folder path of selected database is: " + $getDB.LogFolderPath.pathname
                    Write-Host "adding deviceID to file "
                    $dbLogVol = $mp.deviceId
                    Write-Host $dblogvol

                    $deviceID2 = $mp.DeviceID
                    $logMP = $true
                }
            }
            $deviceIDs = $deviceID1, $deviceID2
        }
    }

    if ($dbMP -eq $false) {

        $dbEdbVol = ($getDB.EdbFilePath.pathname).substring(0, 2)
        "The selected database path is '" + $getDB.EdbFilePath.pathname + "' so adding volume $dbEdbVol to backup scope"
        $deviceID1 = $dbEdbVol
    }

    if ($logMP -eq $false) {
        $dbLogVol = ($getDB.LogFolderPath.pathname).substring(0, 2)
        $nl
        "The selected database log folder path is '" + $getDB.LogFolderPath.pathname + "' so adding volume $dbLogVol to backup scope"
        $deviceID2 = $dbLogVol
    }

    # Here is where we start adding the appropriate volumes or mountpoints to the diskshadow config file
    # We make sure that we add only one Logical volume when we detect the EDB and log files
    # are on the same volume

    $nl
    $deviceIDs = $deviceID1, $deviceID2
    $comp = [string]::Compare($deviceID1, $deviceID2, $True)
    if ($comp -eq 0) {
        $dID = $deviceIDs[0]
        Write-Debug -Message ('$dID = ' + $dID.ToString())
        Write-Debug "When the database and log files are on the same volume, we add the volume only once"
        if ($dID.length -gt "2") {
            $addVol = "add volume $dID alias vss_test_" + ($dID).tostring().substring(11, 8)
            Write-Host $addVol
            Out-DHSFile $addVol
        } else {
            $addVol = "add volume $dID alias vss_test_" + ($dID).tostring().substring(0, 1)
            Write-Host $addVol
            Out-DHSFile $addVol
        }
    } else {
        Write-Host " "
        foreach ($device in $deviceIDs) {
            if ($device.length -gt "2") {
                Write-Host "Adding the Mount Point for DSH file"
                $addVol = "add volume $device alias vss_test_" + ($device).tostring().substring(11, 8)
                Write-Host $addVol
                Out-DHSFile $addVol
            } else {
                Write-Host "Adding the volume for DSH file"
                $addVol = "add volume $device alias vss_test_" + ($device).tostring().substring(0, 1)
                Write-Host $addVol
                Out-DHSFile $addVol
            }
        }
    }
    Out-DHSFile "create"
    Out-DHSFile " "
    $nl
    Get-Date
    Write-Host "Getting drive letters for exposing backup snapshot" -ForegroundColor Green
    Write-Host "--------------------------------------------------------------------------------------------------------------"

    # check to see if the drives are the same for both database and logs
    # if the same volume is used, only one drive letter is needed for exposure
    # if two volumes are used, two drive letters are needed

    $matchCondition = "^[a-z]:$"
    Write-Debug $matchCondition

    if ($dbEdbVol -eq $dbLogVol) {
        $nl
        "Since the same volume is used for this database's EDB and logs, we only need a single drive"
        "letter to expose the backup snapshot."
        $nl

        do {
            Write-Host "Enter an unused drive letter with colon (e.g. X:) to expose the snapshot" -ForegroundColor Yellow -NoNewline
            $script:dbsnapvol = Read-Host " "
            if ($dbsnapvol -notmatch $matchCondition) {
                Write-Host "Your input was not acceptable. Please use a single letter and colon, e.g. X:" -ForegroundColor red
            }
        } while ($dbsnapvol -notmatch $matchCondition)
    } else {
        $nl
        "Since different volumes are used for this database's EDB and logs, we need two drive"
        "letters to expose the backup snapshot."
        $nl

        do {
            Write-Host "Enter an unused drive letter with colon (e.g. X:) to expose the DATABASE volume" -ForegroundColor Yellow -NoNewline
            $script:dbsnapvol = Read-Host " "
            if ($dbsnapvol -notmatch $matchCondition) {
                Write-Host "Your input was not acceptable. Please use a single letter and colon, e.g. X:" -ForegroundColor red
            }
        } while ($dbsnapvol -notmatch $matchCondition)

        do {
            Write-Host "Enter an unused drive letter with colon (e.g. Y:) to expose the LOG volume" -ForegroundColor Yellow -NoNewline
            $script:logsnapvol = Read-Host " "
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
    if ($dbEdbVol -eq $dbLogVol) {
        if ($dbEdbVol.length -gt "2") {
            $dbvolstr = "expose %vss_test_" + ($dbEdbVol).substring(11, 8) + "% $dbsnapvol"
            Out-DHSFile $dbvolstr
        } else {
            $dbvolstr = "expose %vss_test_" + ($dbEdbVol).substring(0, 1) + "% $dbsnapvol"
            Out-DHSFile $dbvolstr
        }
    } else {
        # volumes are different, getting both
        # if mountpoint use first part of string, if not use first letter
        if ($dbEdbVol.length -gt "2") {
            $dbvolstr = "expose %vss_test_" + ($dbEdbVol).substring(11, 8) + "% $dbsnapvol"
            Out-DHSFile $dbvolstr
        } else {
            $dbvolstr = "expose %vss_test_" + ($dbEdbVol).substring(0, 1) + "% $dbsnapvol"
            Out-DHSFile $dbvolstr
        }

        # if mountpoint use first part of string, if not use first letter
        if ($dbLogVol.length -gt "2") {
            $logvolstr = "expose %vss_test_" + ($dbLogVol).substring(11, 8) + "% $logsnapvol"
            Out-DHSFile $logvolstr
        } else {
            $logvolstr = "expose %vss_test_" + ($dbLogVol).substring(0, 1) + "% $logsnapvol"
            Out-DHSFile $logvolstr
        }
    }

    # ending data of file
    Out-DHSFile "end backup"
}