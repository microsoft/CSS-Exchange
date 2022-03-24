# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Enter-YesNoLoopAction.ps1
. $PSScriptRoot\PipelineFunctions.ps1
. $PSScriptRoot\Start-JobManager.ps1
. $PSScriptRoot\..\RemoteScriptBlock\Get-FreeSpace.ps1
. $PSScriptRoot\..\..\..\Shared\Add-ScriptBlockInjection.ps1
Function Test-DiskSpace {
    param(
        [Parameter(Mandatory = $true)][array]$Servers,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$CheckSize
    )
    Write-ScriptDebug("Function Enter: Test-DiskSpace")
    Write-ScriptDebug("Passed: [string]Path: {0} | [int]CheckSize: {1}" -f $Path, $CheckSize)
    Write-ScriptHost -WriteString ("Checking the free space on the servers before collecting the data...") -ShowServer $false
    if (-not ($Path.EndsWith("\"))) {
        $Path = "{0}\" -f $Path
    }

    Function Test-ServerDiskSpace {
        param(
            [Parameter(Mandatory = $true)][string]$Server,
            [Parameter(Mandatory = $true)][int]$FreeSpace,
            [Parameter(Mandatory = $true)][int]$CheckSize
        )
        Write-ScriptDebug("Calling Test-ServerDiskSpace")
        Write-ScriptDebug("Passed: [string]Server: {0} | [int]FreeSpace: {1} | [int]CheckSize: {2}" -f $Server, $FreeSpace, $CheckSize)

        if ($FreeSpace -gt $CheckSize) {
            Write-ScriptHost -WriteString ("[Server: {0}] : We have more than {1} GB of free space." -f $Server, $CheckSize) -ShowServer $false
            return $true
        } else {
            Write-ScriptHost -WriteString ("[Server: {0}] : We have less than {1} GB of free space." -f $Server, $CheckSize) -ShowServer $false
            return $false
        }
    }

    if ($Servers.Count -eq 1 -and $Servers[0] -eq $env:COMPUTERNAME) {
        Write-ScriptDebug("Local server only check. Not going to invoke Start-JobManager")
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

    Write-ScriptDebug("Getting Get-FreeSpace string to create Script Block")
    SetWriteRemoteVerboseAction "New-VerbosePipelineObject"
    $getFreeSpaceString = Add-ScriptBlockInjection -PrimaryScriptBlock ${Function:Get-FreeSpace} `
        -IncludeScriptBlock @(${Function:Write-Verbose}, ${Function:New-PipelineObject}, ${Function:New-VerbosePipelineObject}) `
        -IncludeUsingParameter "WriteRemoteVerboseDebugAction"
    Write-ScriptDebug("Creating Script Block")
    $getFreeSpaceScriptBlock = [scriptblock]::Create($getFreeSpaceString)
    $serversData = Start-JobManager -ServersWithArguments $serverArgs -ScriptBlock $getFreeSpaceScriptBlock `
        -NeedReturnData $true `
        -JobBatchName "Getting the free space for test disk space" `
        -RemotePipelineHandler ${Function:Invoke-PipelineHandler}
    $passedServers = @()
    foreach ($server in $Servers) {

        $freeSpace = $serversData[$server]
        if (Test-ServerDiskSpace -Server $server -FreeSpace $freeSpace -CheckSize $CheckSize) {
            $passedServers += $server
        }
    }

    if ($passedServers.Count -eq 0) {
        Write-ScriptHost -WriteString("Looks like all the servers didn't pass the disk space check.") -ShowServer $false
        Write-ScriptHost -WriteString("Because there are no servers left, we will stop the script.") -ShowServer $false
        exit
    } elseif ($passedServers.Count -ne $Servers.Count) {
        Write-ScriptHost -WriteString ("Looks like all the servers didn't pass the disk space check.") -ShowServer $false
        Write-ScriptHost -WriteString ("We will only collect data from these servers: ") -ShowServer $false
        foreach ($svr in $passedServers) {
            Write-ScriptHost -ShowServer $false -WriteString ("{0}" -f $svr)
        }
        Enter-YesNoLoopAction -Question "Are yu sure you want to continue?" -YesAction {} -NoAction { exit }
    }
    Write-ScriptDebug("Function Exit: Test-DiskSpace")
    return $passedServers
}
