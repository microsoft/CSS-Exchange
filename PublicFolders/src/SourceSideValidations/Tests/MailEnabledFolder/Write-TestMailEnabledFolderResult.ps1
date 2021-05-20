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
        }

        if ($mailEnabledWithNoADObject -gt 0) {
            Write-Host
            Write-Host $mailEnabledWithNoADObject "folders are mail-enabled, but have no AD object. These folders should be mail-disabled."
        }

        if ($mailDisabledWithProxyGuid -gt 0) {
            Write-Host
            Write-Host $mailDisabledWithProxyGuid "folders are mail-disabled, but have proxy GUID values. These folders should be mail-enabled."
        }

        if ($orphanedMPF -gt 0) {
            Write-Host
            Write-Host $orphanedMPF "mail public folders are orphaned. These directory objects should be deleted."
        }

        if ($orphanedMPFDuplicate -gt 0) {
            Write-Host
            Write-Host $orphanedMPFDuplicate "mail public folders point to public folders that point to a different directory object. These should be deleted. Their email addresses may be merged onto the linked object."
        }

        if ($orphanedMPFDisconnected -gt 0) {
            Write-Host
            Write-Host $orphanedMPFDisconnected "mail public folders point to public folders that are mail-disabled. These require manual intervention. Either the directory object should be deleted, or the folder should be mail-enabled, or both."
        }
    }
}
