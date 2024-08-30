# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Search-AllActiveDirectoryDomains.ps1

function Test-ValidMailboxProperties {
    $validHomeMdbTestName = "Valid Home MDB" # Need to make sure the property value homeMDB is not null and points to a valid database object.
    $validHomeServerTestName = "Valid Home Server Name" # Need to make sure the property value msExchHomeServerName is not null.
    $arbitration = 0x800000
    $discovery = 0x20000000
    $publicFolder = 0x1000000000
    $recipientTypes = $arbitration -bor $discovery -bor $publicFolder
    $filter = "(&(objectClass=user)(mailNickname=*)(msExchRecipientTypeDetails:1.2.840.113556.1.4.804:=$recipientTypes))"
    $propsToLoad = @("distinguishedName", "homeMDB", "msExchHomeServerName")

    $results = Search-AllActiveDirectoryDomains -Filter $filter -PropertiesToLoad $propsToLoad

    if ($null -ne $results -and
        $results.Count -gt 0) {

        foreach ($result in $results) {
            $dbName = $result.Properties["homeMDB"]
            $mailboxDN = $result.Properties["distinguishedName"]
            $params = @{
                TestName      = $validHomeMdbTestName
                Details       = ("Mailbox DN: $mailboxDN`n" +
                    "Database DN: $dbName")
                ReferenceInfo = ("Run the following command in EMS.`n" +
                    "If EMS is down, launch PowerShell and run `"Add-PSSnapin *Exchange*`"`n" +
                    "    Set-Mailbox 'DN' -Database 'DB_Name'")
            }

            if ((-not([string]::IsNullOrEmpty($dbName))) -and
                ([ADSI]::Exists("LDAP://$dbName"))) {
                New-TestResult @params -Result "Passed"
            } else {
                New-TestResult @params -Result "Failed"
            }

            $homeServer = $result.Properties["msExchHomeServerName"]
            $params = @{
                TestName      = $validHomeServerTestName
                Details       = ("Mailbox DN: $mailboxDN`nHome Server Name: $homeServer")
                ReferenceInfo = ("Run the following command in PowerShell or EMS.`n" +
                    "Set-ADObject 'DN' -Add @{msExchHomeServerName='AnExchangeServer-ExchangeLegacyDN-Value'}")
            }

            if ((-not([string]::IsNullOrEmpty($homeServer)))) {
                New-TestResult @params -Result "Passed"
            } else {
                New-TestResult @params -Result "Failed"
            }
        }
    } else {
        $params = @{
            Result  = "Failed"
            Details = "Failed to find any critical mailboxes"
        }
        New-TestResult @params -TestName $validHomeMdbTestName
        New-TestResult @params -TestName $validHomeServerTestName
    }
}
