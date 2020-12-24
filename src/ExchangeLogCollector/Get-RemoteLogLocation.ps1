Function Get-RemoteLogLocation {
    param(
        [parameter(Mandatory = $true)][array]$Servers,
        [parameter(Mandatory = $true)][string]$RootPath 
    )
    Write-ScriptDebug("Calling: Get-RemoteLogLocation")
    Write-ScriptDebug("Passed: Number of servers {0} | [string]RootPath:{1}" -f $Servers.Count, $RootPath)
    Function Get-ZipLocation {
        param(
            [parameter(Mandatory = $true)][string]$RootPath
        )
        $like = "*-{0}*.zip" -f (Get-Date -Format Md)
        $item = $RootPath + (Get-ChildItem $RootPath | ? { $_.Name -like $like } | sort CreationTime -Descending)[0]
            
        $obj = New-Object -TypeName PSCustomObject 
        $obj | Add-Member -MemberType NoteProperty -Name ServerName -Value $env:COMPUTERNAME
        $obj | Add-Member -MemberType NoteProperty -Name ZipFolder -Value $item
        $obj | Add-Member -MemberType NoteProperty -Name Size -Value ((Get-Item $item).Length)
        return $obj
    }
        
    $logInfo = Invoke-Command -ComputerName $Servers -ScriptBlock ${function:Get-ZipLocation} -ArgumentList $RootPath 
        
    return $logInfo
}