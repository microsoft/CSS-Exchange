﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-WmiObjectHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-PageFileInformation {
    param()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $pageFiles = $null
    Get-WmiObjectHandler -Class "Win32_PageFileSetting" -CatchActionFunction ${Function:Invoke-CatchActions} |
        Invoke-RemotePipelineHandlerList -Result ([ref]$pageFiles)
    $pageFileList = New-Object 'System.Collections.Generic.List[object]'

    if ($null -eq $pageFiles -or
        $pageFiles.Count -eq 0) {
        Write-Verbose "Found No Page File Settings"
        $pageFileList.Add([PSCustomObject]@{
                Name        = [string]::Empty
                InitialSize = 0
                MaximumSize = 0
            })
    } else {
        Write-Verbose "Found $($pageFiles.Count) different page files"
    }

    foreach ($pageFile in $pageFiles) {
        $pageFileList.Add([PSCustomObject]@{
                Name        = $pageFile.Name
                InitialSize = $pageFile.InitialSize
                MaximumSize = $pageFile.MaximumSize
            })
    }

    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $pageFileList
}
