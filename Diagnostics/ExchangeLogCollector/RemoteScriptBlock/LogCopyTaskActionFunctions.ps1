# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function NewTaskAction {
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

function NewLogCopyParameters {
    param(
        [string]$LogPath,
        [string]$CopyToThisLocation
    )
    return @{
        LogPath            = $LogPath
        CopyToThisLocation = [System.IO.Path]::Combine($Script:RootCopyToDirectory, $CopyToThisLocation)
    }
}

function NewLogCopyBasedOffTimeParameters {
    param(
        [string]$LogPath,
        [string]$CopyToThisLocation,
        [bool]$IncludeSubDirectory
    )
    return (NewLogCopyParameters $LogPath $CopyToThisLocation) + @{
        IncludeSubDirectory = $IncludeSubDirectory
    }
}

function GetTaskActionToString {
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

function Add-TaskAction {
    param(
        [string]$FunctionName
    )
    $Script:taskActionList.Add((NewTaskAction $FunctionName))
}

function Add-LogCopyBasedOffTimeTaskAction {
    param(
        [string]$LogPath,
        [string]$CopyToThisLocation,
        [bool]$IncludeSubDirectory = $true
    )
    $timeCopyParams = @{
        LogPath             = $LogPath
        CopyToThisLocation  = $CopyToThisLocation
        IncludeSubDirectory = $IncludeSubDirectory
    }
    $params = @{
        FunctionName = "Copy-LogsBasedOnTime"
        Parameters   = (NewLogCopyBasedOffTimeParameters @timeCopyParams)
    }
    $Script:taskActionList.Add((NewTaskAction @params))
}

function Add-LogCopyFullTaskAction {
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

function Add-DefaultLogCopyTaskAction {
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

function Get-LogSourceIdentifier {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $normalizedPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\').ToUpperInvariant()
    $label = [regex]::Replace($normalizedPath, '[^A-Z0-9_-]+', '_').Trim('_')
    if ($label.Length -gt 48) {
        $label = $label.Substring($label.Length - 48)
    }

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($normalizedPath))
    } finally {
        $algorithm.Dispose()
    }

    $shortHash = [System.BitConverter]::ToString($hash).Replace('-', '').Substring(0, 12).ToLowerInvariant()
    return "${label}_$shortHash"
}
