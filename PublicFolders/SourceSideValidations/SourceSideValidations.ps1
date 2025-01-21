# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [bool]
    $StartFresh = $true,

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [switch]
    $SlowTraversal,

    [Parameter(Mandatory = $true, ParameterSetName = "RemoveInvalidPermissions")]
    [switch]
    $RemoveInvalidPermissions,

    [Parameter(Mandatory = $true, ParameterSetName = "SummarizePreviousResults")]
    [Switch]
    $SummarizePreviousResults,

    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "RemoveInvalidPermissions")]
    [Parameter(ParameterSetName = "SummarizePreviousResults")]
    [string]
    $ResultsFile = (Join-Path $PSScriptRoot "ValidationResults.csv"),

    [Parameter()]
    [switch]
    $SkipVersionCheck,

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [ValidateSet("Dumpsters", "Limits", "Names", "MailEnabled", "Permissions")]
    [string[]]
    $Tests = @("Dumpsters", "Limits", "Names", "MailEnabled", "Permissions")
)

. $PSScriptRoot\Tests\DumpsterMapping\AllFunctions.ps1
. $PSScriptRoot\Tests\Limit\AllFunctions.ps1
. $PSScriptRoot\Tests\Name\AllFunctions.ps1
. $PSScriptRoot\Tests\MailEnabledFolder\AllFunctions.ps1
. $PSScriptRoot\Tests\Permission\AllFunctions.ps1
. $PSScriptRoot\Get-FolderData.ps1
. $PSScriptRoot\JobQueue.ps1
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\Out-Columns.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1

# For HashSet support
Add-Type -AssemblyName System.Core -ErrorAction Stop

try {
    if (-not $SkipVersionCheck) {
        if (Test-ScriptVersion -AutoUpdate) {
            # Update was downloaded, so stop here.
            Write-Host "Script was updated. Please rerun the command."
            return
        }
    }

    $errorColor = "Red"
    $configuredErrorColor = (Get-Host).PrivateData.ErrorForegroundColor
    if ($configuredErrorColor -is [ConsoleColor]) {
        $errorColor = $configuredErrorColor
    }

    $warningColor = "Yellow"
    $configuredWarningColor = (Get-Host).PrivateData.WarningForegroundColor
    if ($configuredWarningColor -is [ConsoleColor]) {
        $warningColor = $configuredWarningColor
    }

    $severityColorizer = {
        param($o, $propName)
        if ($propName -eq "Severity") {
            switch ($o.$propName) {
                "Error" { $errorColor }
                "Warning" { $warningColor }
            }
        }
    }

    if ($SummarizePreviousResults) {
        $results = Import-Csv $ResultsFile
        $summary = New-Object System.Collections.ArrayList
        $summary.AddRange(@($results | Write-TestDumpsterMappingResult))
        $summary.AddRange(@($results | Write-TestFolderLimitResult))
        $summary.AddRange(@($results | Write-TestFolderNameResult))
        $summary.AddRange(@($results | Write-TestMailEnabledFolderResult))
        $summary.AddRange(@($results | Write-TestPermissionResult))
        $summary | Out-Columns -LinesBetweenObjects 1 -ColorizerFunctions $severityColorizer
        return
    }

    if ($RemoveInvalidPermissions) {
        $shell = Confirm-ExchangeShell

        if (-not $shell.EMS) {
            Write-Host "The -RemoveInvalidPermissions switch must be used from Exchange Management Shell. If you are using EMS,"
            Write-Host "then there may be an issue with the Auth Certificate or some other issue preventing PowerShell serialization."
            Write-Host "Cannot continue."
            return
        }

        if (-not (Test-Path $ResultsFile)) {
            Write-Error "File not found: $ResultsFile. Please specify -ResultsFile or run without -RemoveInvalidPermissions to generate a results file."
        } else {
            Import-Csv $ResultsFile | Remove-InvalidPermission
        }

        return
    }

    $startTime = Get-Date

    if ($null -eq (Get-Command Set-ADServerSettings -ErrorAction:SilentlyContinue)) {
        Write-Warning "Exchange Server cmdlets are not present in this shell."
        return
    }

    Set-ADServerSettings -ViewEntireForest $true

    $progressParams = @{
        Activity = "Validating public folders"
        Id       = 1
    }

    Write-Progress @progressParams -Status "Step 1 of 6"

    $mailboxToServerMap = @{}

    # Validate that all PF mailboxes are available
    $anyPFMailboxUnavailable = $false
    $pfMailboxes = Get-Mailbox -PublicFolder
    foreach ($mailbox in $pfMailboxes) {
        try {
            $db = Get-MailboxDatabase $mailbox.Database -Status
            if ($db.Mounted) {
                $mailboxToServerMap[$mailbox.DisplayName] = $db.Server
            } else {
                Write-Warning "Database $db is not mounted. This database holds PF mailbox $mailbox and must be mounted."
                $anyPFMailboxUnavailable = $true
            }
        } catch {
            Write-Error $_
            $anyPFMailboxUnavailable = $true
        }
    }

    $folderData = Get-FolderData -StartFresh $StartFresh -SlowTraversal $SlowTraversal

    if ($folderData.IpmSubtree.Count -lt 1) {
        return
    }

    $folderData.MailboxToServerMap = $mailboxToServerMap

    # Validate that all content mailboxes exist
    $ipmSubtreeByMailboxGuid = $folderData.IpmSubtree | Group-Object ContentMailboxGuid
    foreach ($group in $ipmSubtreeByMailboxGuid) {
        $mailbox = Get-Mailbox -PublicFolder $group.Name -ErrorAction SilentlyContinue
        if ($null -eq $mailbox) {
            Write-Warning "Content Mailbox $($group.Name) not found. $($group.Count) folders point to this invalid mailbox."
            $anyPFMailboxUnavailable = $true
        }
    }

    if ($anyPFMailboxUnavailable) {
        Write-Host "One or more PF mailboxes cannot be reached. Unable to proceed."
        return
    }

    # Now we're ready to do the checks

    if (Test-Path $ResultsFile) {
        $directory = [System.IO.Path]::GetDirectoryName($ResultsFile)
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($ResultsFile)
        $timeString = (Get-Item $ResultsFile).LastWriteTime.ToString("yyMMdd-HHmm")
        Move-Item -Path $ResultsFile -Destination (Join-Path $directory "$($fileName)-$timeString.csv")
    }

    if ($folderData.Errors.Count -gt 0) {
        $folderData.Errors | Export-Csv $ResultsFile -NoTypeInformation -Encoding UTF8
    }

    if ("Dumpsters" -in $Tests) {
        Write-Progress @progressParams -Status "Step 2 of 6"

        $badDumpsters = Test-DumpsterMapping -FolderData $folderData
        $badDumpsters | Export-Csv $ResultsFile -NoTypeInformation -Append -Encoding UTF8
    }

    if ("Limits" -in $Tests) {
        Write-Progress @progressParams -Status "Step 3 of 6"

        # This test emits results in a weird order, so sort them.
        $limitsExceeded = Test-FolderLimit -FolderData $folderData | Sort-Object FolderIdentity
        $limitsExceeded | Export-Csv $ResultsFile -NoTypeInformation -Append -Encoding UTF8
    }

    if ("Names" -in $Tests) {
        Write-Progress @progressParams -Status "Step 4 of 6"

        $badNames = Test-FolderName -FolderData $folderData
        $badNames | Export-Csv $ResultsFile -NoTypeInformation -Append -Encoding UTF8
    }

    if ("MailEnabled" -in $Tests) {
        Write-Progress @progressParams -Status "Step 5 of 6"

        $badMailEnabled = Test-MailEnabledFolder -FolderData $folderData
        $badMailEnabled | Export-Csv $ResultsFile -NoTypeInformation -Append -Encoding UTF8
    }

    if ("Permissions" -in $Tests) {
        Write-Progress @progressParams -Status "Step 6 of 6"

        $badPermissions = Test-Permission -FolderData $folderData
        $badPermissions | Export-Csv $ResultsFile -NoTypeInformation -Append -Encoding UTF8
    }

    Write-Progress @progressParams -Completed

    # Output the results

    $results = New-Object System.Collections.ArrayList
    $results.AddRange(@($badDumpsters | Write-TestDumpsterMappingResult))
    $results.AddRange(@($limitsExceeded | Write-TestFolderLimitResult))
    $results.AddRange(@($badNames | Write-TestFolderNameResult))
    $results.AddRange(@($badMailEnabled | Write-TestMailEnabledFolderResult))
    $results.AddRange(@($badPermissions | Write-TestPermissionResult))
    $results | Out-Columns -LinesBetweenObjects 1

    Write-Host
    Write-Host "Validation results were written to file:"
    Write-Host $ResultsFile -ForegroundColor Green

    $private:endTime = Get-Date

    Write-Host
    Write-Host "SourceSideValidations complete. Total duration" ($endTime - $startTime)
} finally {
    Write-Host
    Write-Host "Liked the script or had a problem? Let us know at ExToolsFeedback@microsoft.com"
}
