# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Enter-YesNoLoopAction.ps1
. $PSScriptRoot\Start-JobManager.ps1
. $PSScriptRoot\..\RemoteScriptBlock\Get-FreeSpace.ps1
. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptBlock\Get-DefaultSBInjectionContext.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptBlock\RemoteSBLoggingFunctions.ps1
function Test-DiskSpace {
    param(
        [Parameter(Mandatory = $true)][array]$Servers,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$CheckSize
    )
    Write-Verbose("Function Enter: Test-DiskSpace")
    Write-Verbose("Passed: [string]Path: {0} | [int]CheckSize: {1}" -f $Path, $CheckSize)
    Write-Host "Checking the free space on the servers before collecting the data..."
    if (-not ($Path.EndsWith("\"))) {
        $Path = "{0}\" -f $Path
    }

    function Test-ServerDiskSpace {
        param(
            [Parameter(Mandatory = $true)][string]$Server,
            [Parameter(Mandatory = $true)][int]$FreeSpace,
            [Parameter(Mandatory = $true)][int]$CheckSize
        )
        Write-Verbose("Calling Test-ServerDiskSpace")
        Write-Verbose("Passed: [string]Server: {0} | [int]FreeSpace: {1} | [int]CheckSize: {2}" -f $Server, $FreeSpace, $CheckSize)

        if ($FreeSpace -gt $CheckSize) {
            Write-Host "[Server: $Server] : We have more than $CheckSize GB of free space."
            return $true
        } else {
            Write-Host "[Server: $Server] : We have less than $CheckSize GB of free space."
            return $false
        }
    }

    if ($Servers.Count -eq 1 -and $Servers[0] -eq $env:COMPUTERNAME) {
        Write-Verbose("Local server only check. Not going to invoke Start-JobManager")
        $freeSpace = Get-FreeSpace -FilePath $Path
        if (Test-ServerDiskSpace -Server $Servers[0] -FreeSpace $freeSpace -CheckSize $CheckSize) {
            return $Servers[0]
        } else {
            return $null
        }
    }

    $serverArgs = @()
    foreach ($server in $Servers) {
        $serverArgs += [PSCustomObject]@{
            ServerName   = $server
            ArgumentList = $Path
        }
    }

    Write-Verbose("Getting Get-FreeSpace string to create Script Block")
    $getFreeSpaceScriptBlock = Get-DefaultSBInjectionContext -PrimaryScriptBlock ${Function:Get-FreeSpace}
    Write-Verbose("Successfully Created Script Block")
    $params = @{
        ServersWithArguments  = $serverArgs
        ScriptBlock           = $getFreeSpaceScriptBlock
        NeedReturnData        = $true
        JobBatchName          = "Getting the free space for test disk space"
        RemotePipelineHandler = ${Function:Invoke-RemotePipelineLoggingLocal}
    }
    $serversData = Start-JobManager @params
    $passedServers = @()
    foreach ($server in $Servers) {

        $freeSpace = $serversData[$server]
        if (Test-ServerDiskSpace -Server $server -FreeSpace $freeSpace -CheckSize $CheckSize) {
            $passedServers += $server
        }
    }

    if ($passedServers.Count -eq 0) {
        Write-Host "Looks like all the servers didn't pass the disk space check."
        Write-Host "Because there are no servers left, we will stop the script."
        exit
    } elseif ($passedServers.Count -ne $Servers.Count) {
        Write-Host "Looks like all the servers didn't pass the disk space check."
        Write-Host "We will only collect data from these servers: "
        foreach ($svr in $passedServers) {
            Write-Host $svr
        }
        Enter-YesNoLoopAction -Question "Collect data only from servers that passed the disk space check?" -YesAction {} -NoAction { exit }
    }
    Write-Verbose("Function Exit: Test-DiskSpace")
    return $passedServers
}
