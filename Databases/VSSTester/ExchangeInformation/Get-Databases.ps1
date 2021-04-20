function Get-Databases {
    Get-Date
    Write-Host "Getting databases on server: $serverName" -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "

    [array]$script:databases = Get-MailboxDatabase -server $serverName -status
    if ($null -ne (Get-PublicFolderDatabase -Server $serverName)) {
        $script:databases += Get-PublicFolderDatabase -server $serverName -status
    }

    #write-host "Database Name:`t`t Mounted: `t`t Mounted On Server:" -foregroundcolor Yellow $nl
    $script:dbID = 0

    foreach ($script:db in $databases) {
        $script:db | Add-Member NoteProperty Number $dbID
        $dbID++
    }

    $script:databases | Format-Table Number, Name, Mounted, Server -AutoSize | Out-String

    Write-Host " " $nl
}