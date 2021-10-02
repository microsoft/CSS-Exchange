# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-WmiObjectHandler.ps1
Function Get-PageFileInformation {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $pageFiles = @(Get-WmiObjectHandler -ComputerName $Script:Server -Class "Win32_PageFileSetting" -CatchActionFunction ${Function:Invoke-CatchActions})
    $pageFileList = $null

    if ($null -eq $pageFiles) {
        Write-Verbose "Found No Page File Settings"
    } else {
        Write-Verbose "Found $($pageFiles.Count) different page files"
        $pageFileList = New-Object 'System.Collections.Generic.List[object]'
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
