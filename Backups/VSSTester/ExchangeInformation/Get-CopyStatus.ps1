function Get-CopyStatus {
    if ((($databases[$dbToBackup]).IsMailboxDatabase) -eq "True") {
        Get-Date
        Write-Host "Status of '$selDB' and its replicas (if any)" -ForegroundColor Green $nl
        Write-Host "--------------------------------------------------------------------------------------------------------------"
        " "
        [array]$copyStatus = (Get-MailboxDatabaseCopyStatus -identity ($databases[$dbToBackup]).name)
        ($copyStatus | Format-List) | Out-File -FilePath "$path\copyStatus.txt"
        for ($i = 0; $i -lt ($copyStatus).length; $i++ ) {
            if (($copyStatus[$i].status -eq "Healthy") -or ($copyStatus[$i].status -eq "Mounted")) {
                Write-Host "$($copyStatus[$i].name) is $($copyStatus[$i].status)"
            } else {
                Write-Host "$($copyStatus[$i].name) is $($copyStatus[$i].status)"
                Write-Host "One of the copies of the selected database is not healthy. Please run backup after ensuring that the database copy is healthy" -ForegroundColor Yellow
                exit
            }
        }
    } Else {
        Write-Host "Not checking database copy status since the selected database is a Public Folder Database..."
    }
    " "
}
