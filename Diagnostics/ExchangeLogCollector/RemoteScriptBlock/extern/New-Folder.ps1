# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#https://github.com/dpaulson45/PublicPowerShellFunctions/blob/master/src/Common/New-Folder/New-Folder.ps1
#v21.01.22.2234
Function New-Folder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'I prefer New here')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Multiple output types')]
    [CmdletBinding()]
    param(
        [Alias("NewFolder")]
        [Parameter(Mandatory = $false)][array]$NewFolders,
        [Parameter(Mandatory = $false)][bool]$IncludeDisplayCreate,
        [Parameter(Mandatory = $false, Position = 1)][object]$PassedParametersObject
    )
    #Function Version #v21.01.22.2234

    Function New-Directory {
        param(
            [Parameter(Mandatory = $false)][string]$NewFolder
        )
        if (-not (Test-Path -Path $NewFolder)) {
            if ($IncludeDisplayCreate -or $InvokeCommandReturnWriteArray) {
                Write-InvokeCommandReturnHostWriter("Creating Directory: {0}" -f $NewFolder)
            }
            [System.IO.Directory]::CreateDirectory($NewFolder) | Out-Null
        } else {
            if ($IncludeDisplayCreate -or $InvokeCommandReturnWriteArray) {
                Write-InvokeCommandReturnHostWriter("Directory {0} is already created!" -f $NewFolder)
            }
        }
    }

    $Script:stringArray = @()
    if ($null -ne $PassedParametersObject) {
        if ($null -ne $PassedParametersObject.NewFolders) {
            $NewFolders = $PassedParametersObject.NewFolders
        } else {
            $NewFolders = $PassedParametersObject
        }
        $InvokeCommandReturnWriteArray = $true
    }
    if ($NewFolders.Count -gt 1) {
        $verboseDisplayNewFolders = "Multiple ('{0}') Folders Passed" -f $NewFolders.Count
    } else {
        $verboseDisplayNewFolders = $NewFolders[0]
    }
    Write-InvokeCommandReturnVerboseWriter("Calling: New-Folder")
    Write-InvokeCommandReturnVerboseWriter("Passed: [string]NewFolders: {0} | [bool]IncludeDisplayCreate: {1}" -f $verboseDisplayNewFolders,
        $IncludeDisplayCreate)

    foreach ($newFolder in $NewFolders) {
        New-Directory -NewFolder $newFolder
    }

    if ($InvokeCommandReturnWriteArray) {
        return $Script:stringArray
    }
}
