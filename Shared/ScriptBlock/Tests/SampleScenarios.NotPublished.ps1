# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Sample functions that are going to be used for testing out the dev of Script Block injection for remote execution and logging
#>


SetWriteRemoteVerboseAction "New-RemoteVerbosePipelineObject"

$params = @{
    PrimaryScriptBlock       = ${Function:Get-FreeSpace}
    IncludeScriptBlock       = @(${Function:Write-Verbose}, ${Function:Write-Host}, ${Function:New-RemoteLoggingPipelineObject}, ${Function:New-RemoteVerbosePipelineObject})
    IncludeUsingVariableName = "WriteRemoteVerboseDebugAction"
}

function Get-FreeSpace {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '', Justification = 'Different types returned')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][ValidateScript( { $_.ToString().EndsWith("\") })][string]$FilePath
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "Passed: [string]FilePath: $FilePath"

    function UpdateTestPath {
        param(
            [Parameter(Mandatory = $true)]
            [string]$FilePath
        )
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        Write-Verbose "Passed value $filePath"
        $FilePath = $FilePath.Substring(0, $FilePath.LastIndexOf("\", $FilePath.Length - 2) + 1)
        Write-Verbose "Updated Value: $FilePath"
        $FilePath
    }

    $drivesList = Get-CimInstance Win32_Volume -Filter "DriveType = 3"
    $testPath = $FilePath
    $freeSpaceSize = -1
    while ($true) {
        if ($testPath -eq [string]::Empty) {
            Write-Host "Unable to fine a drive that matches the file path: $FilePath"
            return $freeSpaceSize
        }
        Write-Verbose "Trying to find path that matches path: $testPath"
        foreach ($drive in $drivesList) {
            if ($drive.Name -eq $testPath) {
                Write-Verbose "Found a match"
                $freeSpaceSize = $drive.FreeSpace / 1GB
                Write-Verbose "Have $freeSpaceSize`GB of Free Space"
                return $freeSpaceSize
            }
            Write-Verbose "Drive name: '$($drive.Name)' didn't match"
        }

        $itemTarget = [string]::Empty
        if ((Test-Path $testPath)) {
            $item = Get-Item $testPath
            if ($item.Target -like "Volume{*}\") {
                Write-Verbose "File Path appears to be a mount point target: $($item.Target)"
                $itemTarget = $item.Target
            } else {
                Write-Verbose "Path didn't appear to be a mount point target"
            }
        } else {
            Write-Verbose "Path isn't a true path yet."
        }

        if ($itemTarget -ne [string]::Empty) {
            foreach ($drive in $drivesList) {
                if ($drive.DeviceID.Contains($itemTarget)) {
                    $freeSpaceSize = $drive.FreeSpace / 1GB
                    Write-Verbose "Have $freeSpaceSize`GB of Free Space"
                    return $freeSpaceSize
                }
                Write-Verbose "DeviceID didn't appear to match: $($drive.DeviceID)"
            }
            if ($freeSpaceSize -eq -1) {
                Write-Host "Unable to fine a drive that matches the file path: $FilePath"
                Write-Host "This shouldn't have happened."
                return $freeSpaceSize
            }
        }

        # Because we are calling a function that also contains things that are going to get added to the pipeline in remote context, we need to handle this
        UpdateTestPath -FilePath $testPath | Invoke-RemotePipelineHandler -Result ([ref]$testPath)
    }
}

