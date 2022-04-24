# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function NewTaskAction {
    [CmdletBinding()]
    param(
        [string]$FunctionName,
        [object]$Parameters
    )
    return [PSCustomObject]@{
        FunctionName = $FunctionName
        Parameters   = $Parameters
    }
}

Function NewLogCopyParameters {
    param(
        [string]$LogPath,
        [string]$CopyToThisLocation
    )
    return @{
        LogPath            = $LogPath
        CopyToThisLocation = [System.IO.Path]::Combine($Script:RootCopyToDirectory, $CopyToThisLocation)
    }
}

Function GetTaskActionToString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [object]$TaskAction
    )
    $params = $TaskAction.Parameters
    $line = "$($TaskAction.FunctionName)"

    if ($null -ne $params) {
        $line += " LogPath: '$($params.LogPath)' CopyToThisLocation: '$($params.CopyToThisLocation)'"
    }
    return $line
}

Function Add-TaskAction {
    param(
        [string]$FunctionName
    )
    $Script:taskActionList.Add((NewTaskAction $FunctionName))
}

Function Add-LogCopyBasedOffTimeTaskAction {
    param(
        [string]$LogPath,
        [string]$CopyToThisLocation
    )
    $params = @{
        FunctionName = "Copy-LogsBasedOnTime"
        Parameters   = (NewLogCopyParameters $LogPath $CopyToThisLocation)
    }
    $Script:taskActionList.Add((NewTaskAction @params))
}

Function Add-LogCopyFullTaskAction {
    param (
        [string]$LogPath,
        [string]$CopyToThisLocation
    )
    $params = @{
        FunctionName = "Copy-FullLogFullPathRecurse"
        Parameters   = (NewLogCopyParameters $LogPath $CopyToThisLocation)
    }
    $Script:taskActionList.Add((NewTaskAction @params))
}

Function Add-DefaultLogCopyTaskAction {
    param(
        [string]$LogPath,
        [string]$CopyToThisLocation
    )
    if ($PassedInfo.CollectAllLogsBasedOnLogAge) {
        Add-LogCopyBasedOffTimeTaskAction $LogPath $CopyToThisLocation
    } else {
        Add-LogCopyFullTaskAction $LogPath $CopyToThisLocation
    }
}
