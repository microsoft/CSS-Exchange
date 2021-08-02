# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-WmiObjectHandler.ps1
Function Get-PageFileInformation {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    [HealthChecker.PageFileInformation]$page_obj = New-Object HealthChecker.PageFileInformation
    $pageFile = Get-WmiObjectHandler -ComputerName $Script:Server -Class "Win32_PageFileSetting" -CatchActionFunction ${Function:Invoke-CatchActions}

    if ($null -ne $pageFile) {
        if ($pageFile.GetType().Name -eq "ManagementObject") {
            $page_obj.MaxPageSize = $pageFile.MaximumSize
        }
        $page_obj.PageFile = $pageFile
    } else {
        Write-Verbose "Return Null value"
    }

    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $page_obj
}
