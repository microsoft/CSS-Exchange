# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-ResultSummary.ps1

function Write-TestMailEnabledFolderResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    begin {
        $mailEnabledSystemFolderResults = New-Object System.Collections.ArrayList
        $mailEnabledWithNoADObjectResults = New-Object System.Collections.ArrayList
        $mailDisabledWithProxyGuidResults = New-Object System.Collections.ArrayList
        $orphanedMPFResults = New-Object System.Collections.ArrayList
        $orphanedMPFDuplicateResults = New-Object System.Collections.ArrayList
        $orphanedMPFDisconnectedResults = New-Object System.Collections.ArrayList
    }

    process {
        if ($TestResult.TestName -eq "MailEnabledFolder") {
            switch ($TestResult.ResultType) {
                "MailEnabledSystemFolder" { [void]$mailEnabledSystemFolderResults.Add($TestResult) }
                "MailEnabledWithNoADObject" { [void]$mailEnabledWithNoADObjectResults.Add($TestResult) }
                "MailDisabledWithProxyGuid" { [void]$mailDisabledWithProxyGuidResults.Add($TestResult) }
                "OrphanedMPF" { [void]$orphanedMPFResults.Add($TestResult) }
                "OrphanedMPFDuplicate" { [void]$orphanedMPFDuplicateResults.Add($TestResult) }
                "OrphanedMPFDisconnected" { [void]$orphanedMPFDisconnectedResults.Add($TestResult) }
            }
        }
    }

    end {
        if ($mailEnabledSystemFolderResults.Count -gt 0) {
            Get-ResultSummary -ResultType $mailEnabledSystemFolderResults[0].ResultType -Severity $mailEnabledSystemFolderResults[0].Severity -Count $mailEnabledSystemFolderResults.Count -Action (
                "System folders are mail-enabled. These folders should be mail-disabled. " +
                "After confirming the accuracy of the results, you can mail-disable them with the following command:`n`n" +
                "Import-Csv .\ValidationResults.csv |`n" +
                " ? ResultType -eq MailEnabledSystemFolder |`n" +
                " % { Disable-MailPublicFolder $_.FolderIdentity }")
        }

        if ($mailEnabledWithNoADObjectResults.Count -gt 0) {
            Get-ResultSummary -ResultType $mailEnabledWithNoADObjectResults[0].ResultType -Severity $mailEnabledWithNoADObjectResults[0].Severity -Count $mailEnabledWithNoADObjectResults.Count -Action (
                "Folders are mail-enabled, but have no AD object. These folders should be mail-disabled. " +
                "After confirming the accuracy of the results, you can mail-disable them with the following command:`n`n" +
                "Import-Csv .\ValidationResults.csv | `n" +
                " ? ResultType -eq MailEnabledWithNoADObject |`n" +
                " % { Disable-MailPublicFolder $_.FolderIdentity }")
        }

        if ($mailDisabledWithProxyGuidResults.Count -gt 0) {
            Get-ResultSummary -ResultType $mailDisabledWithProxyGuidResults[0].ResultType -Severity $mailDisabledWithProxyGuidResults[0].Severity -Count $mailDisabledWithProxyGuidResults.Count -Action (
                "Folders are mail-disabled, but have proxy GUID values. These folders should be mail-enabled. " +
                "After confirming the accuracy of the results, you can mail-enable them with the following command:`n`n" +
                "Import-Csv .\ValidationResults.csv |`n" +
                " ? ResultType -eq MailDisabledWithProxyGuid |`n" +
                " % { Enable-MailPublicFolder $_.FolderIdentity }")
        }

        if ($orphanedMPFResults.Count -gt 0) {
            Get-ResultSummary -ResultType $orphanedMPFResults[0].ResultType -Severity $orphanedMPFResults[0].Severity -Count $orphanedMPFResults.Count -Action (
                "Mail public folders are orphaned. They exist in Active Directory " +
                "but are not linked to any public folder. Therefore, they should be deleted. " +
                "After confirming the accuracy of the results, you can delete them manually, " +
                "or use a command like this to delete them all:`n`n" +
                "Import-Csv .\ValidationResults.csv |`n" +
                " ? ResultType -eq OrphanedMPF |`n" +
                " % {`n" +
                "  `$folder = ([ADSI](`"LDAP://`$_`"))`n" +
                "  `$parent = ([ADSI]`"`$(`$folder.Parent)`")`n" +
                "  `$parent.Children.Remove(`$folder)`n" +
                " }")
        }

        if ($orphanedMPFDuplicateResults.Count -gt 0) {
            Get-ResultSummary -ResultType $orphanedMPFDuplicateResults[0].ResultType -Severity $orphanedMPFDuplicateResults[0].Severity -Count $orphanedMPFDuplicateResults.Count -Action (
                "Mail public folders point to public folders that point to a different directory object. " +
                "These should be deleted. Their email addresses may be merged onto the linked object. " +
                "After confirming the accuracy of the results, you can delete them manually, " +
                "or use a command like this:`n`n" +
                "Import-Csv .\ValidationResults.csv |`n" +
                " ? ResultType -eq OrphanedMPFDuplicate |`n" +
                " % {`n" +
                "  `$folder = ([ADSI](`"LDAP://`$(`$_.FolderIdentity)`"))`n" +
                "  `$parent = ([ADSI]`"`$(`$folder.Parent)`")`n" +
                "  `$parent.Children.Remove(`$folder)`n" +
                " }`n`n" +
                "After these objects are deleted, the email addresses can be merged onto the linked objects:`n`n" +
                "Import-Csv .\ValidationResults.csv |`n" +
                " ? ResultType -eq OrphanedMPFDuplicate |`n" +
                " % { Invoke-Expression `$_.ResultData }")
        }

        if ($orphanedMPFDisconnectedResults.Count -gt 0) {
            Get-ResultSummary -ResultType $orphanedMPFDisconnectedResults[0].ResultType -Severity $orphanedMPFDisconnectedResults[0].Severity -Count $orphanedMPFDisconnectedResults.Count -Action (
                "Mail public folders point to public folders that are mail-disabled. " +
                "These require manual intervention. Either the directory object should be deleted, or the folder should be mail-enabled, or both. " +
                "Open the ValidationResults.csv and filter for ResultType of OrphanedMPFDisconnected to identify these folders. " +
                "The FolderIdentity provides the DN of the mail object. The FolderEntryId provides the EntryId of the folder.")
        }
    }
}
