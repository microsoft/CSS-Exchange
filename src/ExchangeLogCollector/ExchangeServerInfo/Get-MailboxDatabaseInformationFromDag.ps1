Function Get-MailboxDatabaseInformationFromDAG {
    param(
        [parameter(Mandatory = $true)]$DAGInfo
    )
    Write-ScriptDebug("Function Enter: Get-MailboxDatabaseInformationFromDAG")
    Write-ScriptHost -WriteString ("Getting Database information from {0} DAG member servers" -f $DAGInfo.Name) -ShowServer $false 
    $allDupMDB = @()
    foreach ($serverObj in $DAGInfo.Servers) {
        foreach ($server in $serverObj.Name) {
            $allDupMDB += Get-MailboxDatabase -Server $server -Status 
        }
    }
    #remove all dups 
    $MailboxDBS = @()
    foreach ($t_mdb in $allDupMDB) {
        $add = $true
        foreach ($mdb in $MailboxDBS) {
            if ($mdb.Name -eq $t_mdb.Name) {
                $add = $false
                break
            }
        }
        if ($add) {
            $MailboxDBS += $t_mdb
        }
    }
    
    Write-ScriptHost -WriteString ("Found the following databases:") -ShowServer $false 
    foreach ($mdb in $MailboxDBS) {
        Write-ScriptHost -WriteString ($mdb) -ShowServer $false 
    }
    
    $MailboxDBInfo = @() 
    
    foreach ($mdb in $MailboxDBS) {
        $mdb_Name = $mdb.Name 
        $dbObj = New-Object PSCustomObject
        $dbObj | Add-Member -MemberType NoteProperty -Name MDBName -Value $mdb_Name
        $dbObj | Add-Member -MemberType NoteProperty -Name MDBInfo -Value $mdb
        $value = Get-MailboxDatabaseCopyStatus $mdb_Name\*
        $dbObj | Add-Member -MemberType NoteProperty -Name MDBCopyStatus -Value $value
        $MailboxDBInfo += $dbObj
    }
    Write-ScriptDebug("Function Exit: Get-MailboxDatabaseInformationFromDAG")
    return $MailboxDBInfo
}