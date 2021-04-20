function Get-DBtoBackup {
    $maxDbIndexRange = $script:databases.length - 1
    $matchCondition = "^([0-9]|[1-9][0-9])$"
    Write-Debug "matchCondition: $matchCondition"
    do {
        Write-Host "Select the number of the database to backup" -ForegroundColor Yellow -NoNewline;
        $script:dbToBackup = Read-Host " "

        if ($script:dbToBackup -notmatch $matchCondition -or [int]$script:dbToBackup -gt $maxDbIndexRange) {
            Write-Host "Error! Please select a valid option!" -ForegroundColor Red
        }
    } while ($script:dbToBackup -notmatch $matchCondition -or [int]$script:dbToBackup -gt $maxDbIndexRange) # notmatch is case-insensitive

    if ((($databases[$dbToBackup]).IsMailboxDatabase) -eq "True") {

        $script:dbGuid = (Get-MailboxDatabase ($databases[$dbToBackup])).guid
        $script:selDB = (Get-MailboxDatabase ($databases[$dbToBackup])).name
        " "
        "The database guid for '$selDB' is: $dbGuid"
        " "
        $script:dbMountedOn = (Get-MailboxDatabase ($databases[$dbToBackup])).server.name
    } else {
        $script:dbGuid = (Get-PublicFolderDatabase ($databases[$dbToBackup])).guid
        $script:selDB = (Get-PublicFolderDatabase ($databases[$dbToBackup])).name
        "The database guid for '$selDB' is: $dbGuid"
        " "
        $script:dbMountedOn = (Get-PublicFolderDatabase ($databases[$dbToBackup])).server.name
    }
    Write-Host "The database is mounted on server: $dbMountedOn $nl"

    if ($dbMountedOn -eq "$serverName") {
        $script:dbStatus = "active"
    } else {
        $script:dbStatus = "passive"
    }
}