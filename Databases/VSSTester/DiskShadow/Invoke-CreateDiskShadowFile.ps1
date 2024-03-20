# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-CreateDiskShadowFile {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath,

        [string]
        $ServerName,

        [Parameter(Mandatory = $true, ParameterSetName = "BackupByDatabase")]
        [object[]]
        $Databases,

        [Parameter(Mandatory = $true, ParameterSetName = "BackupByDatabase")]
        [object]
        $DatabaseToBackup,

        [Parameter(Mandatory = $true, ParameterSetName = "BackupByVolume")]
        [object[]]
        $VolumesToBackup,

        [Parameter(Mandatory = $true)]
        [string[]]
        $DriveLetters
    )

    function Out-DHSFile {
        param ([string]$FileLine)
        $FileLine | Out-File -FilePath "$OutputPath\DiskShadow.dsh" -Encoding ASCII -Append
    }

    #	creates the DiskShadow.dsh file that will be written to below
    #	-------------------------------------------------------------
    Write-Host "$(Get-Date) Creating DiskShadow config file..."
    New-Item -Path $OutputPath\DiskShadow.dsh -type file -Force | Out-Null

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

    if ($DatabaseToBackup) {
        #	add databases to exclude
        #	------------------------
        foreach ($db in $Databases) {
            if ($db.Identity -ne $DatabaseToBackup.Identity) {
                if ($db.Server.Name -eq $ServerName) {
                    Out-DHSFile "writer exclude `"Microsoft Exchange Writer:\Microsoft Exchange Server\Microsoft Information Store\$serverName\$($db.Guid)`""
                } else {
                    #if passive copy, add it with replica in the string
                    Out-DHSFile "writer exclude `"Microsoft Exchange Replica Writer:\Microsoft Exchange Server\Microsoft Information Store\Replica\$serverName\$($db.Guid)`""
                }
            }
        }
    }

    Out-DHSFile " "
    Out-DHSFile "Begin backup"

    if ($DatabaseToBackup) {
        #	add the volumes for the included database
        #	-----------------------------------------
        #gets a list of mount points on local server
        $mpVolumes = Get-CimInstance -Query "select name, DeviceId from win32_volume where DriveType=3 AND DriveLetter=NULL"
        $deviceIDs = @()

        $dbMP = $false
        $logMP = $false

        #if no MountPoints ($mpVolumes) causes null-valued error, need to handle
        if ($null -ne $mpVolumes) {
            foreach ($mp in $mpVolumes) {
                $mpName = (($mp.name).substring(0, $mp.name.length - 1))
                #if following mount point path exists in database path use deviceID in DiskShadow config file
                if ($DatabaseToBackup.EdbFilePath.PathName.StartsWith($mpName, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Write-Host "  Mount point:  $($mp.name) in use for database path: "
                    Write-Host "  The selected database path is: $($DatabaseToBackup.EdbFilePath.PathName)"
                    $dbEdbVol = $mp.DeviceId
                    Write-Host "  adding deviceID to file: $dbEdbVol"

                    #add device ID to array
                    $deviceID1 = $mp.DeviceID
                    $dbMP = $true
                }

                #if following mount point path exists in log path use deviceID in DiskShadow config file
                if ($DatabaseToBackup.LogFolderPath.PathName.ToLower().Contains($mpName.ToLower())) {
                    Write-Host
                    Write-Host "  Mount point: $($mp.name) in use for log path: "
                    Write-Host "  The log folder path of selected database is: $($DatabaseToBackup.LogFolderPath.PathName)"
                    $dbLogVol = $mp.DeviceId
                    Write-Host "  adding deviceID to file: $dbLogVol"
                    $deviceID2 = $mp.DeviceID
                    $logMP = $true
                }
            }
        }

        if ($dbMP -eq $false) {
            $dbEdbVol = ($DatabaseToBackup.EdbFilePath.PathName).substring(0, 2)
            Write-Host "  The selected database path is '$($DatabaseToBackup.EdbFilePath.PathName)' so adding volume $dbEdbVol to backup scope"
            $deviceID1 = $dbEdbVol
        }

        if ($logMP -eq $false) {
            $dbLogVol = ($DatabaseToBackup.LogFolderPath.PathName).substring(0, 2)
            Write-Host "  The selected database log folder path is '$($DatabaseToBackup.LogFolderPath.PathName)' so adding volume $dbLogVol to backup scope"
            $deviceID2 = $dbLogVol
        }

        $deviceIDs = @($deviceID1)
        if ($deviceID2 -ne $deviceID1) {
            $deviceIDs += $deviceID2
        }
    } else {
        $validVolumes = Get-CimInstance -Query "select name, DeviceId from win32_volume where DriveType=3" |
            Where-Object { $_.Name -match "^\w:" } | Select-Object Name, DeviceID
        $deviceIDs = @()
        foreach ($v in $VolumesToBackup) {
            $volToBackup = $validVolumes | Where-Object { $_.Name -eq $v }
            if ($null -eq $volToBackup) {
                Write-Warning "Failed to find volume by name: $v. Available volumes:`n$([string]::Join("`n", $validVolumes))"
                exit
            }

            $deviceIDs += $volToBackup.DeviceID
        }
    }

    # Here is where we start adding the appropriate volumes or MountPoints to the DiskShadow config file
    # We make sure that we add only one Logical volume when we detect the EDB and log files
    # are on the same volume

    for ($i = 0; $i -lt $deviceIDs.Count; $i++) {
        $id = $deviceIDs[$i]
        Write-Debug -Message ('$id = ' + $id.ToString())
        $addVol = "add volume $id alias vss_test_$i"
        Write-Host $addVol
        Out-DHSFile $addVol
    }

    Out-DHSFile "create"
    Out-DHSFile " "
    Write-Host "$(Get-Date) Getting drive letters for exposing backup snapshot"

    # expose the drives
    if ($deviceIDs.Count -lt $DriveLetters.Count) {
        Write-Warning "Determined that we need $($deviceIDs.Count) drive letters to expose the snapshots, but only $($DriveLetters.Count) were provided. Exiting."
        exit
    }

    for ($i = 0; $i -lt $deviceIDs.Count; $i++) {
        $dbVolStr = "expose %vss_test_$($i)% $($DriveLetters[$i]):"
        Out-DHSFile $dbVolStr
    }

    # ending data of file
    Out-DHSFile "end backup"

    # return the drive letters we used
    return $DriveLetters | Select-Object -First ($deviceIDs.Count)
}
