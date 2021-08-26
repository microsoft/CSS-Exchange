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
    $testName = "Valid Home MDB"

    if ($ldifeObject.Count -gt 0) {

        foreach ($result in $ldifeObject) {
            $dbName = $result.homeMDB
            $params = @{
                TestName      = $testName
                Details       = @("Mailbox DN: $($result.dn)",
                    "Database DN: $dbName")
                ReferenceInfo = @("Run the following command in EMS.",
                    "If EMS is down, launch PowerShell and run `"Add-PSSnapin *Exchange*`"",
                    "    Set-Mailbox 'DN' -Database 'DB_Name'")
            }

            if (![string]::IsNullOrEmpty($dbName)) {

                if (!([ADSI]::Exists("LDAP://$dbName"))) {
                    New-TestResult @params -Result "Failed"
                } else {
                    New-TestResult @params -Result "Passed"
                }
            } else {
                New-TestResult @params -Result "Failed"
            }
        }

        Remove-Item $filePath -Force
    } else {
        New-TestResult -TestName $testName -Result "Failed" -Details "Unexpected LDIF Data"
    }
}
