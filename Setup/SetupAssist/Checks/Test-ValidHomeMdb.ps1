# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Test-ValidHomeMDB {
    $filePath = "$PSScriptRoot\validHomeMdb.txt"
    $rootDSE = [ADSI]("LDAP://RootDSE")
    $arbitration = 0x800000
    $discovery = 0x20000000
    $publicFolder = 0x1000000000
    $recipientTypes = $arbitration -bor $discovery -bor $publicFolder
    ldifde -t 3268 -r "(&(objectClass=user)(mailnickname=*)(msExchRecipientTypeDetails:1.2.840.113556.1.4.804:=$recipientTypes))" `
        -l "distinguishedName,homeMDB" -f $filePath -d $rootDSE.rootDomainNamingContext | Out-Null

    $ldifeObject = @(Get-Content $filePath | ConvertFrom-Ldif)

    if ($ldifeObject.Count -gt 0) {

        $emptyHomeMDB = @()
        $runActions = $false
        foreach ($result in $ldifeObject) {
            $dbName = $result.homeMDB

            if (![string]::IsNullOrEmpty($dbName)) {

                if (!([ADSI]::Exists("LDAP://$dbName"))) {
                    "Mailbox DN: $($result.dn) has an invalid homeMDB value." | Receive-Output -IsWarning
                    $runActions = $true
                }
            } else {
                $emptyHomeMDB += $result.dn
            }
        }

        if ($emptyHomeMDB.Count -ge 1) {
            $runActions = $true
            "The following mailbox(es) have empty homeMDB values that will cause issues with setup" | Receive-Output -IsWarning
            foreach ($dn in $emptyHomeMDB) {
                "`t$dn" | Receive-Output
            }
        }

        if ($runActions) {
            "" | Receive-Output
            "Follow the below steps to address empty/invalid homeMDB" | Receive-Output -IsWarning
            "`tRun the below command in EMS against each of the above mailboxes. If EMS is down, launch PowerShell and run `"Add-PSSnapin *Exchange*`"" | Receive-Output
            "`t`tSet-Mailbox 'DN' -Database 'DB_Name'" | Receive-Output
            "" | Receive-Output
        } else {
            Remove-Item $filePath -Force
            "All Critical Mailboxes have valid HomeMDB values" | Receive-Output
        }
    } else {
        Write-Error "Unexpected LDIF data in Test-ValidHomeMdb."
    }
}
