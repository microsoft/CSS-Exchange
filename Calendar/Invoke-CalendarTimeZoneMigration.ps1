# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore Rehoming

<#
.SYNOPSIS
    Moves organizer-owned Exchange Server calendar items from one Windows time zone to another while
    keeping their local date and time, for example after a region changes its time zone rules.
.DESCRIPTION
    This script is for Exchange Server (on-premises). For Exchange Online use Invoke-CalendarEventMigration.

    Run in Windows PowerShell 5.1 on a management or user computer. Run as administrator is not required and
    the Exchange Management Shell is not used. The script talks to Exchange Web Services (EWS) with existing
    permissions: the mailbox owner, a delegate with Editor rights on the calendar and Send on Behalf or Send As
    (see -SkipSendPermissionCheck), or a separately granted, scoped ApplicationImpersonation role (-Impersonation).

    Typical workflow:
      1. -ListTimeZones to confirm the exact Windows time zone IDs known to Exchange.
      2. -ReportPath to create a CSV of the affected single items and recurring series. Review it and
         delete the rows that must not be changed.
      3. -CsvPath with -ToWindowsTimeZoneId to preview the migration, then repeat with -Apply.
      4. -Reconcile only if a migration was interrupted (for example the window was closed).

    Every run writes a summary, a result CSV and a detailed journal for each mailbox under -LogDirectory.
    The log directory contains calendar data and must be protected.
.PARAMETER EwsUrl
    HTTPS URL of Exchange Web Services, for example https://mail.contoso.com/EWS/Exchange.asmx.
    If omitted, Autodiscover finds it for the first mailbox: first the Active Directory service connection
    point (internal URL), then https://<domain>/autodiscover and https://autodiscover.<domain> (external URL).
    The URL that was found is displayed and recorded in the run log. Any Exchange server or namespace can be
    used because every request names the target mailbox.
.PARAMETER ListTimeZones
    Lists the Windows time zone IDs supported by the Exchange server.
.PARAMETER Mailbox
    One or more SMTP addresses of calendar owners. A delegate specifies the owner's address.
    With -ListTimeZones, only used for Autodiscover; the default is the current user's address.
.PARAMETER FromWindowsTimeZoneId
    The Windows time zone ID the items currently use, for example "Pacific Standard Time".
.PARAMETER ReportPath
    Path of the CSV report to create. The report is read-only and changes no items.
.PARAMETER QueryStartDate
    Start of the search window. A date without a time zone offset is UTC midnight. Default: now.
    A recurring series is included completely if any of its occurrences falls inside the window.
.PARAMETER QueryWindowInDays
    Length of the search window in days, from 1 to 1825. Default: 365.
.PARAMETER CsvPath
    A reviewed report CSV. Only the listed items are processed; no additional items are searched.
.PARAMETER ToWindowsTimeZoneId
    The Windows time zone ID the items move to, for example "British Columbia Standard Time".
.PARAMETER LogDirectory
    Directory for the run logs. A new subdirectory is created for every run.
.PARAMETER Apply
    Changes items and sends normal meeting updates. Without -Apply the script only previews.
.PARAMETER Reconcile
    Resolves items that still carry an in-progress marker from an interrupted run.
.PARAMETER SearchDirectory
    The LogDirectory (or directories) of the interrupted run. Used with -Reconcile.
.PARAMETER ResendNotification
    With -Reconcile: resend the meeting update for an item whose update may not have been delivered.
.PARAMETER Credential
    Account used for EWS. If omitted, the current Windows credentials are used.
.PARAMETER Impersonation
    Use EWS impersonation of the calendar owner. The account needs the ApplicationImpersonation role.
.PARAMETER SkipSendPermissionCheck
    Allows a delegate without Send on Behalf or Send As to migrate items and send the meeting updates.
    By default such items are not changed (status NotAttempted). Exchange itself lets a delegate with
    Editor permission on the calendar send meeting updates on behalf of the organizer; use this switch
    only when that is acceptable in your organization.
.PARAMETER MaxAttachmentHashSizeMB
    File attachments up to this size are verified by SHA256; larger ones by name, type and size. Default: 25.
    Reconcile verifies each interrupted operation with the limit that operation used.
.PARAMETER Force
    Replace an existing report CSV.
.PARAMETER SkipVersionCheck
    Do not check for a newer version of the script.
.EXAMPLE
    .\Invoke-CalendarTimeZoneMigration.ps1 -EwsUrl https://mail.contoso.com/EWS/Exchange.asmx -ListTimeZones
.EXAMPLE
    .\Invoke-CalendarTimeZoneMigration.ps1 -Mailbox user1@contoso.com -FromWindowsTimeZoneId "Pacific Standard Time" -QueryStartDate 2026-11-01 -ReportPath .\Report.csv

    The EWS URL is found by Autodiscover.
.EXAMPLE
    .\Invoke-CalendarTimeZoneMigration.ps1 -EwsUrl https://mail.contoso.com/EWS/Exchange.asmx -Mailbox user1@contoso.com -FromWindowsTimeZoneId "Pacific Standard Time" -QueryStartDate 2026-11-01 -ReportPath .\Report.csv
.EXAMPLE
    .\Invoke-CalendarTimeZoneMigration.ps1 -EwsUrl https://mail.contoso.com/EWS/Exchange.asmx -CsvPath .\Report.csv -ToWindowsTimeZoneId "British Columbia Standard Time" -LogDirectory .\Logs -Apply
.EXAMPLE
    .\Invoke-CalendarTimeZoneMigration.ps1 -EwsUrl https://mail.contoso.com/EWS/Exchange.asmx -Reconcile -CsvPath .\Logs\<RunId>\selection.csv -SearchDirectory .\Logs -LogDirectory .\Logs -Apply
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Migrate')]
param (
    [Parameter(Mandatory = $false)]
    [uri]
    $EwsUrl,

    [Parameter(Mandatory = $true, ParameterSetName = 'ListTimeZones')]
    [switch]
    $ListTimeZones,

    [Parameter(Mandatory = $true, ParameterSetName = 'Report')]
    [Parameter(Mandatory = $true, ParameterSetName = 'MigrateSearch')]
    [Parameter(Mandatory = $false, ParameterSetName = 'ListTimeZones')]
    [string[]]
    $Mailbox,

    [Parameter(Mandatory = $true, ParameterSetName = 'Report')]
    [Parameter(Mandatory = $true, ParameterSetName = 'MigrateSearch')]
    [string]
    $FromWindowsTimeZoneId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Report')]
    [string]
    $ReportPath,

    [Parameter(Mandatory = $false, ParameterSetName = 'Report')]
    [Parameter(Mandatory = $false, ParameterSetName = 'MigrateSearch')]
    [string]
    $QueryStartDate = [DateTimeOffset]::UtcNow.ToString('o'),

    [Parameter(Mandatory = $false, ParameterSetName = 'Report')]
    [Parameter(Mandatory = $false, ParameterSetName = 'MigrateSearch')]
    [ValidateRange(1, 1825)]
    [int]
    $QueryWindowInDays = 365,

    [Parameter(Mandatory = $true, ParameterSetName = 'Migrate')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Reconcile')]
    [string]
    $CsvPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Migrate')]
    [Parameter(Mandatory = $true, ParameterSetName = 'MigrateSearch')]
    [string]
    $ToWindowsTimeZoneId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Migrate')]
    [Parameter(Mandatory = $true, ParameterSetName = 'MigrateSearch')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Reconcile')]
    [string]
    $LogDirectory,

    [Parameter(Mandatory = $false, ParameterSetName = 'Migrate')]
    [Parameter(Mandatory = $false, ParameterSetName = 'MigrateSearch')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Reconcile')]
    [switch]
    $Apply,

    [Parameter(Mandatory = $true, ParameterSetName = 'Reconcile')]
    [switch]
    $Reconcile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Reconcile')]
    [string[]]
    $SearchDirectory,

    [Parameter(Mandatory = $false, ParameterSetName = 'Reconcile')]
    [switch]
    $ResendNotification,

    [Parameter(Mandatory = $false)]
    [PSCredential]
    $Credential,

    [Parameter(Mandatory = $false)]
    [switch]
    $Impersonation,

    [Parameter(Mandatory = $false, ParameterSetName = 'Migrate')]
    [Parameter(Mandatory = $false, ParameterSetName = 'MigrateSearch')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Reconcile')]
    [switch]
    $SkipSendPermissionCheck,

    [Parameter(Mandatory = $false, ParameterSetName = 'Migrate')]
    [Parameter(Mandatory = $false, ParameterSetName = 'MigrateSearch')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Reconcile')]
    [ValidateRange(0, 1024)]
    [int]
    $MaxAttachmentHashSizeMB = 25,

    [Parameter(Mandatory = $false, ParameterSetName = 'Report')]
    [switch]
    $Force,

    [Parameter(Mandatory = $false)]
    [switch]
    $SkipVersionCheck
)

begin {
    Set-StrictMode -Version 2
    $ErrorActionPreference = 'Stop'

    . $PSScriptRoot\CalendarTimeZoneMigrationHelpers\EwsTransport.ps1
    . $PSScriptRoot\CalendarTimeZoneMigrationHelpers\CalendarTimeZoneData.ps1
    . $PSScriptRoot\CalendarTimeZoneMigrationHelpers\MigrationJournal.ps1
    . $PSScriptRoot\CalendarTimeZoneMigrationHelpers\Rehoming.ps1
    . $PSScriptRoot\CalendarTimeZoneMigrationHelpers\Reconcile.ps1
    . $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
} process {
    $BuildVersion = ""

    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Run this script in Windows PowerShell 5.1. PowerShell 7 is not supported.'
    }

    if (-not $SkipVersionCheck -and (Test-ScriptVersion -AutoUpdate)) {
        Write-Host "Script was updated. Please rerun the command." -ForegroundColor Yellow
        return
    }

    $script:ExOPRuntimeVersion = if ([string]::IsNullOrEmpty($BuildVersion)) { 'development' } else { $BuildVersion }
    $runtimeFiles = @($PSCommandPath)
    $helperDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'CalendarTimeZoneMigrationHelpers'
    if (Test-Path -LiteralPath $helperDirectory -PathType Container) {
        $runtimeFiles += @(Get-ChildItem -LiteralPath $helperDirectory -Filter '*.ps1' -File | ForEach-Object { $_.FullName })
    }
    $script:ExOPRuntimeFiles = $runtimeFiles
    $script:MaxAttachmentHashBytes = [long]$MaxAttachmentHashSizeMB * 1MB
    Write-Verbose "Script version: $($script:ExOPRuntimeVersion)"

    $rows = @()
    if ($PSCmdlet.ParameterSetName -in 'Migrate', 'Reconcile') {
        $rows = @(Import-Csv -LiteralPath $CsvPath)
        if ($rows.Count -eq 0) {
            Write-Host 'The CSV contains no rows. Nothing was changed.'
            return
        }
    }

    if ($null -ne $EwsUrl) {
        $session = New-ExOPCalendarSession -EwsUrl $EwsUrl -Credential $Credential -Impersonation:$Impersonation
    } else {
        $discoveryAddress = if ($rows.Count -gt 0 -and $null -ne $rows[0].PSObject.Properties['Mailbox']) { [string]$rows[0].Mailbox }
        elseif ($Mailbox) { $Mailbox[0] }
        elseif ($null -eq $Credential) { Get-ExOPCurrentUserSmtpAddress }
        if (-not $discoveryAddress) {
            throw 'The EWS URL cannot be discovered without a mailbox address. Specify -EwsUrl or -Mailbox.'
        }
        Write-Host "Running Autodiscover for $discoveryAddress"
        $discovered = Resolve-ExOPEwsUrl -EmailAddress $discoveryAddress -Credential $Credential
        Write-Host "Using EWS URL $($discovered.EwsUrl.AbsoluteUri) found by $($discovered.Source). Use -EwsUrl to choose another URL."
        $session = New-ExOPCalendarSession -EwsUrl $discovered.EwsUrl -Credential $Credential -Impersonation:$Impersonation `
            -EwsUrlSource $discovered.Source
    }

    if ($PSCmdlet.ParameterSetName -eq 'ListTimeZones') {
        Get-ExOPCalendarTimeZone -Session $session | Sort-Object -Property Id
        return
    }

    if ($PSCmdlet.ParameterSetName -in 'Report', 'MigrateSearch') {
        $queryStart = [DateTimeOffset]::Parse($QueryStartDate, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
        $rows = @(
            foreach ($owner in $Mailbox) {
                Write-Host "Searching the calendar of $owner"
                Get-ExOPCalendarMigrationReport -Session $session -Mailbox $owner -FromWindowsTimeZoneId $FromWindowsTimeZoneId `
                    -QueryStartDate $queryStart -QueryWindowInDays $QueryWindowInDays
            }
        )
        if ($rows.Count -eq 0) {
            Write-Host 'No matching organizer-owned items were found. Nothing was changed.'
        }
        $unclassified = @($session.Diagnostics | Where-Object { $_.Code -in 'MissingTimeZone', 'NoWindowsTimeZoneDefinition', 'IanaTimeZone' })
        if ($unclassified.Count -gt 0) {
            Write-Host "$($unclassified.Count) organizer-owned item(s) have no usable time zone definition and were not included. See the warnings above." -ForegroundColor Yellow
        }
        if ($rows.Count -eq 0) {
            return
        }
        if ($PSCmdlet.ParameterSetName -eq 'Report') {
            $exported = $rows | Export-ExOPCalendarMigrationReport -Path $ReportPath -Force:$Force
            Write-Host "Report with $($exported.RowCount) rows written to $($exported.Path). Review it before migrating."
            return
        }
    }

    if ($PSCmdlet.ParameterSetName -eq 'Reconcile') {
        $approved = $Apply -and $PSCmdlet.ShouldProcess("$($rows.Count) calendar items through $($session.EwsUrl.AbsoluteUri)", 'Reconcile interrupted migrations')
        $parameters = @{
            Session = $session; SearchDirectory = $SearchDirectory; LogDirectory = $LogDirectory
            Apply = $approved; ResendNotification = $ResendNotification; SkipSendPermissionCheck = $SkipSendPermissionCheck; Confirm = $false
        }
        if ($Apply -and $WhatIfPreference) { $parameters.Apply = $true; $parameters.WhatIf = $true }
        $results = @($rows | Invoke-ExOPCalendarMigrationReconcile @parameters)
    } else {
        $approved = $Apply -and $PSCmdlet.ShouldProcess("$($rows.Count) calendar items through $($session.EwsUrl.AbsoluteUri)",
            "Move to '$ToWindowsTimeZoneId' keeping local times, and send meeting updates")
        $parameters = @{
            Session = $session; ToWindowsTimeZoneId = $ToWindowsTimeZoneId; LogDirectory = $LogDirectory
            Apply = $approved; SkipSendPermissionCheck = $SkipSendPermissionCheck; Confirm = $false
        }
        if ($Apply -and $WhatIfPreference) { $parameters.Apply = $true; $parameters.WhatIf = $true }
        $results = @($rows | Invoke-ExOPCalendarEventMigration @parameters)
    }

    $results | Select-Object -Property Mailbox, Subject, Status, Severity, CalendarState, NotificationStatus, RollbackStatus

    $critical = @($results | Where-Object { $_.Severity -eq 'Critical' })
    $unsuccessful = @($results | Where-Object { $_.Status -in 'Failed', 'RolledBack', 'NotAttempted' })
    if ($results.Count -gt 0) { Write-Host "Logs: $($results[0].ReportDirectory)" }
    if ($critical.Count -gt 0) {
        Write-Host "$($critical.Count) item(s) need manual attention. See summary.txt for each mailbox." -ForegroundColor Red
        exit 2
    }
    if ($unsuccessful.Count -gt 0) {
        Write-Host "$($unsuccessful.Count) item(s) were not migrated. See summary.txt for each mailbox." -ForegroundColor Yellow
        exit 1
    }
}
