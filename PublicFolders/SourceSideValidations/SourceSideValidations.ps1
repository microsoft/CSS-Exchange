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
. $PSScriptRoot\..\..\Shared\Test-ScriptVersion.ps1
. $PSScriptRoot\..\..\Shared\Out-Columns.ps1

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

    $folderData = Get-FolderData -StartFresh $StartFresh -SlowTraversal $SlowTraversal

    if ($folderData.IpmSubtree.Count -lt 1) {
        return
    }

    $script:anyDatabaseDown = $false
    Get-Mailbox -PublicFolder | ForEach-Object {
        try {
            $db = Get-MailboxDatabase $_.Database -Status
            if ($db.Mounted) {
                $folderData.MailboxToServerMap[$_.DisplayName] = $db.Server
            } else {
                Write-Error "Database $db is not mounted. This database holds PF mailbox $_ and must be mounted."
                $script:anyDatabaseDown = $true
            }
        } catch {
            Write-Error $_
            $script:anyDatabaseDown = $true
        }
    }

    if ($script:anyDatabaseDown) {
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
        $folderData.Errors | Export-Csv $ResultsFile -NoTypeInformation
    }

    if ("Dumpsters" -in $Tests) {
        Write-Progress @progressParams -Status "Step 2 of 6"

        $badDumpsters = Test-DumpsterMapping -FolderData $folderData
        $badDumpsters | Export-Csv $ResultsFile -NoTypeInformation -Append
    }

    if ("Limits" -in $Tests) {
        Write-Progress @progressParams -Status "Step 3 of 6"

        # This test emits results in a weird order, so sort them.
        $limitsExceeded = Test-FolderLimit -FolderData $folderData | Sort-Object FolderIdentity
        $limitsExceeded | Export-Csv $ResultsFile -NoTypeInformation -Append
    }

    if ("Names" -in $Tests) {
        Write-Progress @progressParams -Status "Step 4 of 6"

        $badNames = Test-FolderName -FolderData $folderData
        $badNames | Export-Csv $ResultsFile -NoTypeInformation -Append
    }

    if ("MailEnabled" -in $Tests) {
        Write-Progress @progressParams -Status "Step 5 of 6"

        $badMailEnabled = Test-MailEnabledFolder -FolderData $folderData
        $badMailEnabled | Export-Csv $ResultsFile -NoTypeInformation -Append
    }

    if ("Permissions" -in $Tests) {
        Write-Progress @progressParams -Status "Step 6 of 6"

        $badPermissions = Test-Permission -FolderData $folderData
        $badPermissions | Export-Csv $ResultsFile -NoTypeInformation -Append
    }

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
    Write-Host "Have feedback? Please visit https://aka.ms/SSVFeedback"
}
