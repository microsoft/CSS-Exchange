function Write-TestMailEnabledFolderResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $mailEnabledSystemFolder = 0
        $mailEnabledWithNoADObject = 0
        $mailDisabledWithProxyGuid = 0
        $orphanedMPF = 0
        $orphanedMPFDuplicate = 0
        $orphanedMPFDisconnected = 0
    }

    process {
        if ($TestResult.TestName -eq "MailEnabledFolder") {
            switch ($TestResult.ResultType) {
                "MailEnabledSystemFolder" { $mailEnabledSystemFolder++ }
                "MailEnabledWithNoADObject" { $mailEnabledWithNoADObject++ }
                "MailDisabledWithProxyGuid" { $mailDisabledWithProxyGuid++ }
                "OrphanedMPF" { $orphanedMPF++ }
                "OrphanedMPFDuplicate" { $orphanedMPFDuplicate++ }
                "OrphanedMPFDisconnected" { $orphanedMPFDisconnected++ }
            }
        }
    }

    end {
        if ($mailEnabledSystemFolder -gt 0) {
            Write-Host
            Write-Host $mailEnabledSystemFolder "system folders are mail-enabled. These folders should be mail-disabled."
            Write-Host "These folders are shown in the results CSV with a result type of MailEnabledSystemFolder."
            Write-Host "After confirming the accuracy of the results, you can mail-disable them with the following command:"
            Write-Host "Import-Csv .\ValidationResults.csv | ? ResultType -eq MailEnabledSystemFolder | % { Disable-MailPublicFolder $_.FolderIdentity }" -ForegroundColor Green
        }

        if ($mailEnabledWithNoADObject -gt 0) {
            Write-Host
            Write-Host $mailEnabledWithNoADObject "folders are mail-enabled, but have no AD object. These folders should be mail-disabled."
            Write-Host "These folders are shown in the results CSV with a result type of MailEnabledWithNoADObject."
            Write-Host "After confirming the accuracy of the results, you can mail-disable them with the following command:"
            Write-Host "Import-Csv .\ValidationResults.csv | ? ResultType -eq MailEnabledWithNoADObject | % { Disable-MailPublicFolder $_.FolderIdentity }" -ForegroundColor Green
        }

        if ($mailDisabledWithProxyGuid -gt 0) {
            Write-Host
            Write-Host $mailDisabledWithProxyGuid "folders are mail-disabled, but have proxy GUID values. These folders should be mail-enabled."
            Write-Host "These folders are shown in the results CSV with a result type of MailDisabledWithProxyGuid."
            Write-Host "After confirming the accuracy of the results, you can mail-enable them with the following command:"
            Write-Host "Import-Csv .\ValidationResults.csv | ? ResultType -eq MailDisabledWithProxyGuid | % { Enable-MailPublicFolder $_.FolderIdentity }" -ForegroundColor Green
        }

        if ($orphanedMPF -gt 0) {
            Write-Host
            Write-Host $orphanedMPF "mail public folders are orphaned. They exist in Active Directory"
            Write-Host "but are not linked to any public folder. Therefore, they should be deleted."
            Write-Host "These folders are shown in the results CSV with a result type of OrphanedMPF."
            Write-Host "After confirming the accuracy of the results, you can delete them manually,"
            Write-Host "or use a command like this:"
            Write-Host "Import-Csv .\ValidationResults.csv | ? ResultType -eq OrphanedMPF | % { `$folder = ([ADSI](`"LDAP://`$_`")); `$parent = ([ADSI]`"`$(`$folder.Parent)`"); `$parent.Children.Remove(`$folder) }" -ForegroundColor Green
        }

        if ($orphanedMPFDuplicate -gt 0) {
            Write-Host
            Write-Host $orphanedMPFDuplicate "mail public folders point to public folders that point to a different directory object."
            Write-Host "These folders are shown in the results CSV with a result type of OrphanedMPFDuplicate."
            Write-Host "These should be deleted. Their email addresses may be merged onto the linked object."
            Write-Host "After confirming the accuracy of the results, you can delete them manually,"
            Write-Host "or use a command like this:"
            Write-Host "Import-Csv .\ValidationResults.csv | ? ResultType -eq OrphanedMPFDuplicate | % { `$folder = ([ADSI](`"LDAP://`$(`$_.FolderIdentity)`")); `$parent = ([ADSI]`"`$(`$folder.Parent)`"); `$parent.Children.Remove(`$folder) }" -ForegroundColor Green
            Write-Host "After these objects are deleted, the email addresses can be merged onto the linked objects:"
            Write-Host "Import-Csv .\ValidationResults.csv | ? ResultType -eq OrphanedMPFDuplicate | % { Invoke-Expression `$_.ResultData }" -ForegroundColor Green
        }

        if ($orphanedMPFDisconnected -gt 0) {
            Write-Host
            Write-Host $orphanedMPFDisconnected "mail public folders point to public folders that are mail-disabled."
            Write-Host "These require manual intervention. Either the directory object should be deleted, or the folder should be mail-enabled, or both."
            Write-Host "Open the ValidationResults.csv and filter for ResultType of OrphanedMPFDisconnected to identify these folders."
            Write-Host "The FolderIdentity provides the DN of the mail object. The FolderEntryId provides the EntryId of the folder."
        }
    }
}
