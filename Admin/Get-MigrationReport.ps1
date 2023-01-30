# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
Version: 2.0
.SYNOPSIS
This script generates all the needed reports to troubleshoot a move request from or to Exchange Online/OnPrem. It can handle multiple mailboxes at once.

.DESCRIPTION
This is a PowerShell script that is used for generating reports related to mailbox migrations in Microsoft Exchange. The script accepts a mandatory parameter called $Identity, which should be an array of mailbox names. The script exports various types of reports as XML files, including:
- MoveRequest: A report containing information about the move request for the specified mailbox.
- MoveRequestStatistics: A report containing statistical information about the move request, including details about the number of items that were moved, failed, or are in a warning state.
- UserMigration
- UserMigrationStatistics
- MigrationBatch
- MigrationEndPoint
- MigrationConfig
The script also exports a report containing statistics for the specified mailbox, as well as a report containing the move history for the specified mailbox. Finally, the script logs any errors that occur during the export process to a log file called LogFile.txt.
.NOTES
    This script should be excuted in exchange online or Exchange OnPrem Powershell module.
.EXAMPLE
    .\Get-MigrationReports -Identity Mustafa@contoso.com
    .\Get-MigrationReports -Identity user1@contoso.com, user2@contoso.com, user3@contoso.com
#>

[CmdletBinding()]
param (
    [Parameter( Mandatory = $true, HelpMessage = 'You must specify the name of a mailbox or mailboxes:')] [string[]] $Identity,
    [string] $OutputFolder = "Get-MigrationReports"
)

# Set the log file path
$LogFile = "$OutputFolder\LogFile.txt"

function Export-XMLReports {
    # Export XML reports:
    try {
        if ($null -ne $MoveRequest) {
            $MoveRequest | Export-Clixml "$OutputFolder\MoveRequest_$Mailbox.xml"
            Add-Content -Path $LogFile -Value " [INFO] The Move Request Report has been generated successfully."
        } else {
            Add-Content -Path $LogFile -Value " [Error] The Move Request not exist."
        }
        if ($null -ne $MoveRequestStatistics) {
            $MoveRequestStatistics | Export-Clixml "$OutputFolder\MoveRequestStatistics_$Mailbox.xml"
            Add-Content -Path $LogFile -Value " [INFO] The Move Request Statistics Report has been generated successfully."
        } else {
            Add-Content -Path $LogFile -Value " [Error] The Move Request Statistics not exist."
        }
        if ($null -ne $UserMigration) {
            $UserMigration | Export-Clixml "$OutputFolder\MigrationUser_$Mailbox.xml"
            Add-Content -Path $LogFile -Value " [INFO] The User Migration Report has been generated successfully."
        } else {
            Add-Content -Path $LogFile -Value " [Error] The Migration User not exist."
        }

        if ($null -ne $UserMigrationStatistics) {
            $UserMigrationStatistics | Export-Clixml "$OutputFolder\MigrationUserStatistics_$Mailbox.xml"
            Add-Content -Path $LogFile -Value " [INFO] The Migration User Statistics Report has been generated successfully."
        } else {
            Add-Content -Path $LogFile -Value " [Error] The Migration User statistics Report not exist."
        }

        if ($null -ne $MigrationBatch) {
            $MigrationBatch | Export-Clixml "$OutputFolder\MigrationBatch_$Mailbox.xml"
            Add-Content -Path $LogFile -Value " [INFO] The Migration Batch Report has been generated successfully."
        } else {
            Add-Content -Path $LogFile -Value " [Error] The Migration Batch not exist."
        }
        if ($null -ne $MigrationEndPoint) {
            $MigrationEndPoint | Export-Clixml "$OutputFolder\MigrationEndpoint_$MigrationEndpoint.xml"
            Add-Content -Path $LogFile -Value " [INFO] The Migration EndPoint Report has been generated successfully."
        } else {
            Add-Content -Path $LogFile -Value " [Error] The Migration EndPoint not exist."
        }
        Get-MigrationConfig | Export-Clixml "$OutputFolder\MigrationConfig.xml"
        Add-Content -Path $LogFile -Value " [INFO] The Migration Config Report has been generated successfully."

        $MailboxStatistics | Export-Clixml "$OutputFolder\MailboxStatistics_$Mailbox.xml"
        $MailboxStatistics.MoveHistory[0] | Export-Clixml "$OutputFolder\MoveReport-History.xml"
        Add-Content -Path $LogFile -Value " [INFO] The Move Request History Report has been generated successfully."
    } catch {
        Add-Content -Path $LogFile -Value '[ERROR] Unable to export the Reports.'
        Add-Content -Path $LogFile -Value $_
        throw
    }
}

function Export-Summary {
    #check the log file
    if (-not (Test-Path -Path $LogFile -ErrorAction Stop )) {
        # Create a new log file if not found.
        New-Item $LogFile  -Type File -Force  -ErrorAction SilentlyContinue
    }

    try {
        if (-not (Test-Path -Path $file -ErrorAction Stop )) {
            # Create a new log file if not found.
            New-Item $file   -Type File -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Add-Content -Path $LogFile -Value '[ERROR] Unable to Create Summary File.'
        Add-Content -Path $LogFile -Value $_
        throw
    }
    $File = "Text-Summary.txt"
    $UniqueFailure = $MoveRequestStatistics.Report.Failures | Select-Object FailureType -Unique
    $detailedFailure = foreach ($U in $UniqueFailure) { $MoveRequestStatistics.Report.Failures | Where-Object { $_.FailureType -like $U.FailureType } | Select-Object Timestamp, FailureType, FailureSide, Message -Last 1 | Format-List }
    New-Item $File -Type file -Force
    "This Move Request has the following infomration:" >> ($File)
    "-----------------------------------------------------------------------" >> ($File)
    "the status of this Move Request is " + $MoveRequestStatistics.Status.ToString() + " with " + $MoveRequestStatistics.Status + " Percent"  >> ($File)
    "" >> ($File)
    $MoveRequestStatistics.Message.ToString() >> ($File)
    "" >> ($File)
    "-----------------------------------------------------------------------" >> ($File)
    "" >> ($File)
    "The Move Request has the following Failures:" >> ($File)
    $MoveRequestStatistics.Report.Failures | Group-Object  FailureType | Format-Table Count, Name >> ($File)
    "-----------------------------------------------------------------------" >> ($File)
    "" >> ($File)
    "Here is more details about each Failure (Note that only the last error is selected in more details):" >> ($File)
    "" >> ($File)
    $detailedFailure >> ($File)
    Add-Content -Path $LogFile -Value "[INFO] the summary report has been created successfully."
}
Function Find-FailureMessage {
    param (
        [string]$failureMessage = $FailureMessages[0].Message
    )
    if ($failureMessage.Contains("User is already being moved")) {
        Write-Host -ForegroundColor Red "Error: User is already being moved. Reference: https://aka.ms/AAjesq4 "
        Add-Content -Path $LogFile -Value "Error: User is already being moved. Reference: https://aka.ms/AAjesq4 "
    } elseif ($failureMessage.Contains("You can't use the domain because it's not an accepted domain for your organization")) {
        Write-Host -ForegroundColor Red "Error: You can't use the domain because it's not an accepted domain for your organization. Reference: https://aka.ms/AAjdrbt "
        Add-Content -Path $LogFile -Value "Error: You can't use the domain because it's not an accepted domain for your organization. Reference: https://aka.ms/AAjdrbt "
    } elseif ($failureMessage.Contains("Target mailbox doesn't have an smtp proxy matching")) {
        Write-Host -ForegroundColor Red "Error: Target mailbox doesn't have an smtp proxy matching *.mail.onmicrosoft.com. Reference: https://aka.ms/AAjdrbu "
        Add-Content -Path $LogFile -Value "Error: Target mailbox doesn't have an smtp proxy matching *.mail.onmicrosoft.com. Reference: https://aka.ms/AAjdrbu "
    } elseif ($failureMessage.contains("MigrationPermanentException: Cannot find a recipient that has mailbox GUID")) {
        Write-Host -ForegroundColor Red "Error: MigrationPermanentException: Cannot find a recipient that has mailbox GUID. Reference: https://aka.ms/AAjdrbv "
        Add-Content -Path $LogFile -Value "Error: MigrationPermanentException: Cannot find a recipient that has mailbox GUID. Reference: https://aka.ms/AAjdrbv "
    } elseif ($failureMessage.contains( "You must specify the PrimaryOnly parameter")) {
        Write-Host -ForegroundColor Red "Error: You must specify the PrimaryOnly parameter. Reference: https://aka.ms/AAjelco "
        Add-Content -Path $LogFile -Value "Error: You must specify the PrimaryOnly parameter. Reference: https://aka.ms/AAjelco "
    } elseif ($failureMessage.contains( "The remote server returned an Error 404")) {
        Write-Host -ForegroundColor Red "Error: The remote server returned an Error 404. Reference: https://aka.ms/AAjdrbz"
        Add-Content -Path $LogFile -Value "Error: The remote server returned an Error 404. Reference: https://aka.ms/AAjdrbz"
    } elseif ($failureMessage.contains( "HTTP request has exceeded the allotted timeout")) {
        Write-Host -ForegroundColor Red "Error: HTTP request has exceeded the allotted timeout. Reference:  https://aka.ms/AAjdrcr "
        Add-Content -Path $LogFile -Value "Error: HTTP request has exceeded the allotted timeout. Reference: https://aka.ms/AAjdrcr "
    } elseif ($failureMessage.contains( "The remote server returned an error: (403) Forbidden")) {
        Write-Host -ForegroundColor Red "Error: The remote server returned an error: (403) Forbidden Reference: https://aka.ms/AAjedt4 "
        Add-Content -Path $LogFile -Value "Error: The remote server returned an error: (403) Forbidden Reference: https://aka.ms/AAjedt4 "
    } elseif ($failureMessage.contains( "Access is denied")) {
        Write-Host -ForegroundColor Red "Error: Access is denied Reference: https://aka.ms/AAjdrcv "
        Add-Content -Path $LogFile -Value "Error: Access is denied Reference: https://aka.ms/AAjdrcv "
    } elseif ($failureMessage.contains( "Couldn't switch the mailbox into Sync Source mode")) {
        Write-Host -ForegroundColor Red "Error: Couldn't switch the mailbox into Sync Source mode. Reference: https://aka.ms/AAjdrcy "
        Add-Content -Path $LogFile -Value "Error: Couldn't switch the mailbox into Sync Source mode. Reference: https://aka.ms/AAjdrcy "
    } elseif ($failureMessage.contains( "CommunicationErrorTransientException - The remote endpoint no longer recognizes this sequence. This is most likely due to an abort on the remote endpoint")) {
        Write-Host -ForegroundColor Red "Error: CommunicationErrorTransientException The remote endpoint no longer recognizes this sequence. This is most likely due to an abort on the remote endpoint. Reference: https://aka.ms/AAjey1r "
        Add-Content -Path $LogFile -Value "Error: CommunicationErrorTransientException The remote endpoint no longer recognizes this sequence. This is most likely due to an abort on the remote endpoint. Reference: https://aka.ms/AAjey1r "
    } elseif ($failureMessage.contains( "The server was unable to process the request due to an internal error")) {
        Write-Host -ForegroundColor Red "Error: The server was unable to process the request due to an internal error. Reference: https://aka.ms/AAjedtb  & https://aka.ms/AAjey1u "
        Add-Content -Path $LogFile -Value "Error: The server was unable to process the request due to an internal error. Reference: https://aka.ms/AAjedtb  & https://aka.ms/AAjey1u"
    } elseif ($failureMessage.contains( "TooManyBadItemsPermanentException - Failed to find a principal from the source forest or target forest")) {
        Write-Host -ForegroundColor Red "Error: TooManyBadItemsPermanentException - Failed to find a principal from the source forest or target forest. Reference: https://aka.ms/AAjesqr "
        Add-Content -Path $LogFile -Value "Error: TooManyBadItemsPermanentException - Failed to find a principal from the source forest or target forest. Reference: https://aka.ms/AAjesqr "
    } elseif ($failureMessage.contains( "The data consistency score (Investigate) for this request is too low")) {
        Write-Host -ForegroundColor Red "Error: The data consistency score (Investigate) for this request is too low. Reference: https://aka.ms/AAjesqu "
        Add-Content -Path $LogFile -Value "Error: The data consistency score (Investigate) for this request is too low. Reference: https://aka.ms/AAjesqu "
    } elseif ($failureMessage.contains( "Exception has been thrown by the target of an invocation")) {
        Write-Host -ForegroundColor Red "Error: Exception has been thrown by the target of an invocation. Reference: https://aka.ms/AAjesqv "
        Add-Content -Path $LogFile -Value "Error: Exception has been thrown by the target of an invocation. Reference: https://aka.ms/AAjesqv "
    } elseif ($failureMessage.contains( "Transient error CommunicationErrorTransientException has occurred. The system will retry")) {
        Write-Host -ForegroundColor Red "Error: Transient error CommunicationErrorTransientException has occurred. The system will retry. Reference: https://aka.ms/AAjdrd3 "
        Add-Content -Path $LogFile -Value "Error: Transient error CommunicationErrorTransientException has occurred. The system will retry. Reference: https://aka.ms/AAjdrd3 "
    } elseif ($failureMessage.contains( "isn't enabled for unified messaging")) {
        Write-Host -ForegroundColor Red "Error: The mailbox is not enabled for unified messaging . Reference: https://aka.ms/AAjdrd4 "
        Add-Content -Path $LogFile -Value "Error: The mailbox is not enabled for unified messaging . Reference: https://aka.ms/AAjdrd4 "
    } elseif ($failureMessage.contains( "Failed to convert the source mailbox 'Primary")) {
        Write-Host -ForegroundColor Red "Error: Failed to convert the source mailbox Primary to mail-enabled user after the move. Reference: https://aka.ms/AAjey1x"
        Add-Content -Path $LogFile -Value "Error: Failed to convert the source mailbox Primary to mail-enabled user after the move. Reference: https://aka.ms/AAjey1x"
    } elseif ($failureMessage.contains( "already has a primary mailbox")) {
        Write-Host -ForegroundColor Red "Error: Target User already has a primary mailbox. Reference: https://aka.ms/AAjey1y "
        Add-Content -Path $LogFile -Value "Error: Target User already has a primary mailbox. Reference: https://aka.ms/AAjey1y "
    } elseif ($failureMessage.contains( "StalledDueTo_Target")) {
        Write-Host -ForegroundColor Red "Error: StalledDueTo_Target. Reference: https://aka.ms/AAjdrd9 "
        Add-Content -Path $LogFile -Value "Error: StalledDueTo_Target. Reference: https://aka.ms/AAjdrd9 "
    } elseif ($failureMessage.contains( "MapiExceptionTooComplex: Unable to query table rows")) {
        Write-Host -ForegroundColor Red "Error: MapiExceptionTooComplex: Unable to query table rows. Reference: https://aka.ms/AAjey20 "
        Add-Content -Path $LogFile -Value "Error: MapiExceptionTooComplex: Unable to query table rows. Reference: https://aka.ms/AAjey20 "
    } elseif ($failureMessage.Contains("Mailbox Replication Proxy Service can't process this request because it has reached the maximum number of active MRS connections allowed")) {
        Write-Host -ForegroundColor Red "Error: Mailbox Replication Proxy Service can't process this request because it has reached the maximum number of active MRS connections allowed. Reference: https://aka.ms/AAjdrda "
        Add-Content -Path $LogFile -Value "Error: Mailbox Replication Proxy Service can't process this request because it has reached the maximum number of active MRS connections allowed. Reference: https://aka.ms/AAjdrda "
    }
}


#===================MAIN======================
New-Item $OutputFolder -ItemType Directory -Force | Out-Null
New-Item $LogFile -Type File -Force -ErrorAction SilentlyContinue | Out-Null

foreach ($Mailbox in $Identity) {
    $MoveRequest = Get-MoveRequest $Mailbox -ErrorAction SilentlyContinue
    $MoveRequestStatistics = Get-MoveRequestStatistics $Mailbox -IncludeReport -ErrorAction SilentlyContinue
    if ($null -eq $MoveRequest) {
        Write-Host -ForegroundColor Red -Value "[ERROR] The MoveRequest for the $Mailbox cannot be found, please check spelling and try again!"
        Add-Content -Path $LogFile -Value "[ERROR] The MoveRequest for the $Mailbox cannot be found, please check spelling and try again!"
    }
    $Batch = $MoveRequestStatistics.BatchName
    $MigrationBatch = Get-MigrationBatch $Batch -IncludeReport  -ErrorAction SilentlyContinue
    $UserMigration = Get-MigrationUser $Mailbox  -ErrorAction SilentlyContinue
    $UserMigrationStatistics = Get-MigrationUserStatistics $Mailbox -IncludeSkippedItems -IncludeReport -ErrorAction SilentlyContinue
    $Endpoint = $MigrationBatch.SourceEndpoint
    $MigrationEndPoint = Get-MigrationEndpoint -Identity $Endpoint -DiagnosticInfo Verbose -ErrorAction SilentlyContinue
    $MailboxStatistics = Get-MailboxStatistics $Mailbox -IncludeMoveReport -IncludeMoveHistory -ErrorAction SilentlyContinue
    $UniqueFailure = $MoveRequestStatistics.Report.Failures | Select-Object FailureType -Unique
    $DetailedFailure = foreach ($U in $UniqueFailure) { $MoveRequestStatistics.Report.Failures | Where-Object { $_.FailureType -like $U.FailureType } | Select-Object Timestamp, FailureType, FailureSide, Message -Last 1 | Format-Table -Wrap }
    $FailureMessages = @(); foreach ($U in $UniqueFailure) { $FailureMessages += $MoveRequestStatistics.Report.Failures | Where-Object { $_.FailureType -like $U.FailureType } | select -Last 1 }; $message = $FailureMessages[0].Message
    $File = "$OutputFolder\Text-Summary_$Mailbox.txt"
    New-Item $file   -Type File -Force -ErrorAction SilentlyContinue | Out-Null

    try {
        Export-XMLReports
        Export-Summary
        Find-FailureMessage
        Write-Host -ForegroundColor "Green" "The MoveRequest reports for $Mailbox exported successfully!"
    } catch {
        Add-Content -Path $LogFile -Value "[ERROR] The MoveRequest for the $Mailbox cannot be found, please check spelling and try again!"
        Add-Content -Path $LogFile -Value $_
        Write-Host -ForegroundColor "Red" "The MoveRequest for the $Mailbox cannot be found, please check spelling and try again!"
        throw
    }
}
