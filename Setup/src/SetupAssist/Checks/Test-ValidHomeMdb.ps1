Function Test-ValidHomeMDB {
    ldifde -t 3268 -r "(&(objectClass=user)(mailnickname=*)(!(msExchRemoteRecipientType=*))(!(targetAddress=*))(msExchHideFromAddressLists=TRUE)(!(cn=HealthMailbox*)))" -l "distinguishedName,homeMDB" -f "$PSScriptRoot\validHomeMdb.txt" | Out-Null
    $ldifeObject = @(Get-Content "$PSScriptRoot\validHomeMdb.txt" | ConvertFrom-Ldif)

    if ($ldifeObject.Count -gt 0) {

        $emptyHomeMDB = @()
        $runActions = $false
        foreach ($result in $ldifeObject) {
            $dbName = $result.homeMDB

            if (![string]::IsNullOrEmpty($dbName)) {

                if (!([ADSI]::Exists("LDAP://$dbName"))) {
                    Write-Warning "Mailbox DN: $($result.dn) has an invalid homeMDB value."
                    $runActions = $true
                }
            } else {
                $emptyHomeMDB += $result.dn
            }
        }

        if ($emptyHomeMDB.Count -ge 1) {
            $runActions = $true
            Write-Warning "The following mailbox(es) have empty homeMDB values that will cause issues with setup"
            foreach ($dn in $emptyHomeMDB) {
                Write-Host "`t$dn"
            }
        }

        if ($runActions) {
            Write-Host ""
            Write-Warning "Follow the below steps to address empty/invalid homeMDB"
            Write-Host "`tRun the below command in EMS against each of the above mailboxes. If EMS is down, launch PowerShell and run `"Add-PSSnapin *Exchange*`""
            Write-Host "`t`tSet-Mailbox 'DN' -Database 'DB_Name'"
            Write-Host ""
        } else {
            Write-Host "All Critical Mailboxes have valid HomeMDB values"
        }
    } else {
        throw "Unexpected LDIF data."
    }
}
