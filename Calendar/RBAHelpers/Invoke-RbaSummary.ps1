# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-RbaPhaseVerbose {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Verbose "[$($script:RunStopwatch.ElapsedMilliseconds)ms] $Message"
}

function Invoke-RbaSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [Alias("MeetingSubject")]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [ValidateNotNullOrEmpty()]
        [string]$MeetingId,

        [switch]$IncludeSensitiveData,

        [switch]$SkipVersionCheck
    )

    if (-not [string]::IsNullOrWhiteSpace($Subject) -and -not [string]::IsNullOrWhiteSpace($MeetingId)) {
        throw "Specify either Subject or MeetingId, not both."
    }

    $invocationParts = [System.Collections.Generic.List[string]]::new()
    $invocationParts.Add(".\Get-RBASummary.ps1")
    $parameterOrder = @(
        "Identity", "Subject", "MeetingId", "IncludeSensitiveData", "SkipVersionCheck",
        "Verbose", "Debug", "ErrorAction", "WarningAction", "InformationAction",
        "ErrorVariable", "WarningVariable", "InformationVariable", "OutVariable", "OutBuffer", "PipelineVariable"
    )
    foreach ($parameterName in $parameterOrder) {
        if (-not $PSBoundParameters.ContainsKey($parameterName)) {
            continue
        }

        $parameterValue = $PSBoundParameters[$parameterName]
        if ($parameterValue -is [System.Management.Automation.SwitchParameter] -or $parameterValue -is [bool]) {
            $invocationParts.Add("-$parameterName`:$($parameterValue.ToString().ToLowerInvariant())")
        } else {
            $invocationParts.Add("-$parameterName $(ConvertTo-CalendarDiagnosticCommandLineValue -Value $parameterValue)")
        }
    }
    $script:InvocationCommandLine = $invocationParts -join ' '

    $script:BuildVersion = ""

    if (-not $SkipVersionCheck -and (Test-ScriptVersion -AutoUpdate)) {
        # Update was downloaded, so stop here.
        Write-Host "Script was updated. Please rerun the command."  -ForegroundColor Yellow
        return
    }

    Write-Verbose "Script Versions: $BuildVersion"

    $script:runTimestamp = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
    $script:outputFileStem = ConvertTo-CalendarDiagnosticFileNameStem -Value $Identity
    $script:SummaryFilename = "RBA-Summary-For_$outputFileStem`_$runTimestamp.txt"
    $script:JsonFilename = "RBA-Summary-For_$outputFileStem`_$runTimestamp.json"
    $script:RbaLogFilename = $null
    $script:collectorStatuses = [ordered]@{}
    $script:collectionErrors = [System.Collections.Generic.List[object]]::new()
    $script:evaluationErrors = [System.Collections.Generic.List[object]]::new()
    $script:TranscriptStarted = $false
    $script:MeetingLogSearch = $null
    $script:ResourceDelegateIdentitySets = @()
    $script:ResourceDelegateIdentitySetsAvailable = $false
    $script:SanitizedIdentityMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:SanitizedIdentitySequence = 0
    $script:RunStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host -ForegroundColor Cyan "`r`nRBA Summary Output saved as [$SummaryFilename] in the current directory."
    try {
        Start-Transcript -Path $SummaryFilename -ErrorAction Stop | Out-Null
        $script:TranscriptStarted = $true
    } catch {
        Write-Warning "Unable to start transcript '$SummaryFilename': $($_.Exception.Message)"
    }
    Write-Host "Command line: $script:InvocationCommandLine"
    Write-Host "`r`n"

    try {
        # Mailbox existence and type are prerequisites for all RBA collection.
        Invoke-RbaCollectorOperation -Name "Mailbox" -Action { Get-RbaMailboxData }
        if ($script:collectorStatuses["Mailbox"].status -ne "Success") {
            Write-Host -ForegroundColor Red "Unable to resolve '$Identity' to a mailbox. Stopping."
            return
        }
        if ($script:Mailbox.RecipientTypeDetails -notin @("RoomMailbox", "EquipmentMailbox")) {
            return
        }

        # Attempt every remaining independent collector before running dependent evaluations.
        Invoke-RbaCollectorOperation -Name "Place" -Action { Get-RbaPlaceData }
        Invoke-RbaCollectorOperation -Name "InboxRules" -Action { Test-RbaInboxRules }
        Invoke-RbaCollectorOperation -Name "CalendarProcessing" -Action { Get-RbaCalendarProcessing }
        Invoke-RbaCollectorOperation -Name "CalendarFolderPermissions" -Action { Get-RbaCalendarFolderPermissions }
        Invoke-RbaCollectorOperation -Name "MailboxPermissions" -Action { Get-RbaMailboxPermissions }
        Invoke-RbaCollectorOperation -Name "RbaLog" -Action {
            Get-RbaLogData
            if ($script:collectorStatuses["RbaLog"].status -eq "Success") {
                $script:MeetingLogSearch = Get-RbaMeetingLogSearchObject
            }
        }
        if ($null -eq $script:MeetingLogSearch) {
            $script:MeetingLogSearch = Get-RbaMeetingLogSearchObject
        }

        if ($script:collectorStatuses["CalendarProcessing"].status -eq "Success") {
            Invoke-RbaEvaluation -Name "Resource delegate identity enrichment" -Action { Initialize-RbaResourceDelegateIdentitySets }
            Invoke-RbaEvaluation -Name "Calendar processing" -Action { Invoke-RbaCalendarProcessingEvaluation }
            if ($script:collectorStatuses["Mailbox"].status -eq "Success" -and
                (-not $script:Workspace -or $script:collectorStatuses["Place"].status -eq "Success")) {
                Invoke-RbaEvaluation -Name "Workspace" -Action { Test-RbaWorkspace }
            }
            Write-RbaProcessingLogic
            Invoke-RbaEvaluation -Name "Policy criteria" -Action { Write-RbaPolicyCriteria }
            Invoke-RbaEvaluation -Name "Processing routes" -Action { Write-RbaProcessingValidation }
            Invoke-RbaEvaluation -Name "In-policy processing" -Action { Write-RbaInPolicyProcessing }
            Invoke-RbaEvaluation -Name "Out-of-policy processing" -Action { Write-RbaOutOfPolicyProcessing }
            Invoke-RbaEvaluation -Name "Delegate settings" -Action { Write-RbaDelegateSettings }
            Invoke-RbaEvaluation -Name "Post-processing" -Action { Write-RbaPostProcessing; Write-RbaVerbosePostProcessing }
        } else {
            Write-Warning "Calendar processing evaluations were skipped because required evidence is unavailable."
        }

        if ($script:collectorStatuses["Place"].status -eq "Success") {
            Invoke-RbaEvaluation -Name "Room list settings" -Action { Test-RbaRoomListSettings }
        } else {
            Write-Warning "Place evaluations were skipped because required evidence is unavailable."
        }

        Invoke-RbaEvaluation -Name "RBA log summary" -Action { Write-RbaLogSummary }
    } catch {
        $errorInfo = ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_
        $script:evaluationErrors.Add([PSCustomObject]@{
                evaluation            = "Unhandled script operation"
                message               = $errorInfo.message
                exceptionType         = $errorInfo.exceptionType
                category              = $errorInfo.category
                fullyQualifiedErrorId = $errorInfo.fullyQualifiedErrorId
                innerExceptionMessage = $errorInfo.innerExceptionMessage
            })
        Write-Warning "An unexpected reporting error occurred: $($errorInfo.message)"
    } finally {
        if ($script:TranscriptStarted) {
            Write-RbaPhaseVerbose -Message "Stopping transcript."
            Stop-Transcript | Out-Null
            $script:TranscriptStarted = $false
            Write-RbaPhaseVerbose -Message "Transcript stopped."
        }
    }

    try {
        Write-RbaPhaseVerbose -Message "Starting JSON report generation."
        Write-RbaJson
        Write-RbaPhaseVerbose -Message "JSON report generation completed."
        Write-Host -ForegroundColor Cyan "`r`nRBA JSON Output saved as [$JsonFilename] in the current directory."
    } catch {
        Write-Verbose "JSON report failure location: $($_.InvocationInfo.PositionMessage)"
        Write-Verbose "JSON report failure stack: $($_.ScriptStackTrace)"
        $errorInfo = ConvertTo-CalendarDiagnosticErrorInfo -ErrorRecord $_
        Write-Warning "Unable to write RBA JSON output '$JsonFilename': $($errorInfo.message)"
    }

    Write-RbaPhaseVerbose -Message "Building final output file list."
    $outputFileLines = [System.Collections.Generic.List[string]]::new()
    $outputFileLines.Add("RBA output files:")
    $outputFileLines.Add("  Text summary: [$SummaryFilename]")
    if (Test-Path -Path $JsonFilename) {
        $outputFileLines.Add("  JSON report:  [$JsonFilename]")
    }
    if (-not [string]::IsNullOrWhiteSpace($script:RbaLogFilename) -and (Test-Path -Path $script:RbaLogFilename)) {
        $outputFileLines.Add("  RBA logs:     [$script:RbaLogFilename]")
    }
    Write-Host
    $outputFileLines | ForEach-Object { Write-Host -ForegroundColor Cyan $_ }
    if (Test-Path -Path $SummaryFilename) {
        Write-RbaPhaseVerbose -Message "Updating text summary with output file list."
        Add-Content -Path $SummaryFilename -Value ([Environment]::NewLine + ($outputFileLines -join [Environment]::NewLine)) -Encoding utf8
        Write-RbaPhaseVerbose -Message "Text summary update completed."
    }
}
