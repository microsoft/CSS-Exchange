Function Get-PageFileInformation {

    Write-VerboseOutput("Calling: Get-PageFileInformation")

    [HealthChecker.PageFileInformation]$page_obj = New-Object HealthChecker.PageFileInformation
    $pagefile = Get-WmiObjectHandler -ComputerName $Script:Server -Class "Win32_PageFileSetting" -CatchActionFunction ${Function:Invoke-CatchActions}
    if($pagefile -ne $null) 
    { 
        if($pagefile.GetType().Name -eq "ManagementObject")
        {
            $page_obj.MaxPageSize = $pagefile.MaximumSize
        }
        $page_obj.PageFile = $pagefile
    }
    else
    {
        Write-VerboseOutput("Return Null value")
    }

    Write-VerboseOutput("Exiting: Get-PageFileInformation")
    return $page_obj
}