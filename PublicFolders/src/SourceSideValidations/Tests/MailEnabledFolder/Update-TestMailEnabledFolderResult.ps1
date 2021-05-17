function Update-TestMailEnabledFolderResult {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object]
        $TestResult
    )

    process {
        if ($TestResult.ResultType -eq "MailEnabledSystemFolder") {
            Write-Host
            Write-Host $group.Count "system folders are mail-enabled. These folders should be mail-disabled."
        } elseif ($TestResult.ResultType -eq "MailEnabledWithNoADObject") {
            Write-Host
            Write-Host $group.Count "folders are mail-enabled, but have no AD object. These folders should be mail-disabled."
        } elseif ($TestResult.ResultType -eq "MailDisabledWithProxyGuid") {
            Write-Host
            Write-Host $group.Count "folders are mail-disabled, but have proxy GUID values. These folders should be mail-enabled."
        } elseif ($TestResult.ResultType -eq "OrphanedMPF") {
            Write-Host
            Write-Host $group.Count "mail public folders are orphaned. These directory objects should be deleted."
        } elseif ($TestResult.ResultType -eq "OrphanedMPFDuplicate") {
            Write-Host
            Write-Host $group.Count "mail public folders point to public folders that point to a different directory object. These should be deleted. Their email addresses may be merged onto the linked object."
        } elseif ($TestResult.ResultType -eq "OrphanedMPFDisconnected") {
            Write-Host
            Write-Host $group.Count "mail public folders point to public folders that are mail-disabled. These require manual intervention. Either the directory object should be deleted, or the folder should be mail-enabled, or both."
        }
    }
}
