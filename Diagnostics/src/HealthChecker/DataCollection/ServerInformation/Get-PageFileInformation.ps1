Function Get-PageFileInformation {

    Write-VerboseOutput("Calling: Get-PageFileInformation")
    [HealthChecker.PageFileInformation]$page_obj = New-Object HealthChecker.PageFileInformation
    $pageFile = Get-WmiObjectHandler -ComputerName $Script:Server -Class "Win32_PageFileSetting" -CatchActionFunction ${Function:Invoke-CatchActions}

    if ($null -ne $pageFile) {
        if ($pageFile.GetType().Name -eq "ManagementObject") {
            $page_obj.MaxPageSize = $pageFile.MaximumSize
        }
        $page_obj.PageFile = $pageFile
    } else {
        Write-VerboseOutput("Return Null value")
    }

    Write-VerboseOutput("Exiting: Get-PageFileInformation")
    return $page_obj
}