# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
Version: 2.0
#  DISCLAIMER:
# THIS CODE IS SAMPLE CODE. THESE SAMPLES ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
# MICROSOFT FURTHER DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR OF FITNESS FOR
# A PARTICULAR PURPOSE. THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SAMPLES REMAINS WITH YOU. IN NO EVENT SHALL
# MICROSOFT OR ITS SUPPLIERS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS,
# BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF OR INABILITY TO USE THE
# SAMPLES, EVEN IF MICROSOFT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME STATES DO NOT ALLOW THE EXCLUSION OR LIMITATION
# OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES, THE ABOVE LIMITATION MAY NOT APPLY TO YOU.


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

# By Mustafa Nassar, Use at your own risk.  No warranties are given.

#>

[CmdletBinding()]
param (
    [Parameter( Mandatory = $true, HelpMessage = 'You must specify the name of a mailbox or mailboxes:')] [array] $Identity,
    [Parameter(Mandatory = $false, HelpMessage = 'Specify the folder where the reports should be saved')] [string] $OutputFolder
)

# Set the default output folder if none is specified
if (-not $OutputFolder) {
    $OutputFolder = 'Get-MigrationReports'
}
# Set the log file path
$logFile = "$OutputFolder\LogFile.txt"

function Export-XMLReports {
    # Export XML reports:
    try {
        if (-not $null -eq $MoveRequest) {
            $MoveRequest | Export-Clixml "$OutputFolder\MoveRequest_$Mailbox.xml"
            Add-Content -Path $logFile -Value " [INFO] The Move Request Report has been generated successfully."
        } else {
            Add-Content -Path $logFile -Value " [Error] The Move Request not exist."
        }
        if (-not $null -eq $MoveRequestStatistics) {
            $MoveRequestStatistics | Export-Clixml "$OutputFolder\MoveRequestStatistics_$Mailbox.xml"
            Add-Content -Path $logFile -Value " [INFO] The Move Request Statistics Report has been generated successfully."
        } else {
            Add-Content -Path $logFile -Value " [Error] The Move Request Statistics not exist."
        }
        if (-not $null -eq $UserMigration) {
            $UserMigration | Export-Clixml "$OutputFolder\MigrationUser_$Mailbox.xml"
            Add-Content -Path $logFile -Value " [INFO] The User Migration Report has been generated successfully."
        } else {
            Add-Content -Path $logFile -Value " [Error] The Migration User not exist."
        }

        if (-not $null -eq $UserMigrationStatistics) {
            $UserMigrationStatistics | Export-Clixml "$OutputFolder\MigrationUserStatistics_$Mailbox.xml"
            Add-Content -Path $logFile -Value " [INFO] The Migration User Statistics Report has been generated successfully."
        } else {
            Add-Content -Path $logFile -Value " [Error] The Migration User Stistics Report not exist."
        }

        if (-not $null -eq $MigrationBatch) {
            $MigrationBatch | Export-Clixml "$OutputFolder\MigrationBatch_$Mailbox.xml"
            Add-Content -Path $logFile -Value " [INFO] The Migration Batch Report has been generated successfully."
        } else {
            Add-Content -Path $logFile -Value " [Error] The Migration Batch not exist."
        }
        if (-not $null -eq $MigrationEndPoint) {
            $MigrationEndPoint | Export-Clixml "$OutputFolder\MigrationEndpoint_$MigrationEndpoint.xml"
            Add-Content -Path $logFile -Value " [INFO] The Migration EndPoint Report has been generated successfully."
        } else {
            Add-Content -Path $logFile -Value " [Error] The Migration EndPoint not exist."
        }
        Get-MigrationConfig | Export-Clixml "$OutputFolder\MigrationConfig.xml"
        Add-Content -Path $logFile -Value " [INFO] The Migration Config Report has been generated successfully."

        $MailboxStatistics | Export-Clixml "$OutputFolder\MailboxStatistics_$Mailbox.xml"
        $MoveHistory.MoveHistory[0] | Export-Clixml "$OutputFolder\MoveReport-History.xml"
        Add-Content -Path $logFile -Value " [INFO] The Move Request History Report has been generated successfully."
    } catch {
        Add-Content -Path $logFile -Value '[ERROR] Unable to export the Reports.'
        Add-Content -Path $logFile -Value $_
        throw
    }
}

function Export-Summary {
    #check the log file
    if (-not (Test-Path -Path $logfile -ErrorAction Stop )) {
        # Create a new log file if not found.
        New-Item $logfile  -Type File -Force  -ErrorAction SilentlyContinue
    }

    try {
        if (-not (Test-Path -Path $file -ErrorAction Stop )) {
            # Create a new log file if not found.
            New-Item $file   -Type File -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Add-Content -Path $logfile -Value '[ERROR] Unable to Create Summary File.'
        Add-Content -Path $logFile -Value $_
        throw
    }
    $File = "Text-Summary.txt"
    $uniquefailure = $MoveRequestStatistics.Report.Failures | Select-Object FailureType -Unique
    $detailedFailure = foreach ($U in $uniquefailure) { $MoveRequestStatistics.Report.Failures | Where-Object { $_.FailureType -like $U.FailureType } | Select-Object Timestamp, FailureType, FailureSide, Message -Last 1 | Format-List }
    New-Item $File -Type file -Force
    "This Move Request has the following infomration:" >> ($File)
    "-----------------------------------------------------------------------" >> ($File)
    "the status of this Move Request is " + $MoveRequestStatistics.Status.tostring() + " with " + $MoveRequestStatistics.Status + " Percent"  >> ($File)
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
    Add-Content -Path $logFile -Value "[INFO] the summary report has been created successfully."



    <#  [int]       $Percent = $MoveRequestStatistics.PercentComplete
    [string]    $Status  = $MoveRequestStatistics.Status
    [string]    $Message = $MoveRequestStatistics.Message
    $value = "This Move Request has the following infomration:" >> ($File)
    $value = "-----------------------------------------------------------------------" >> ($File)
    $value = "the status of this Move Request is " + $MoveRequestStatistics.Status.tostring() + " with " + $MoveRequestStatistics.Status + " Percent"  >> ($File)
    $value = "" >> ($File)
    $value = $MoveRequestStatistics.Message.ToString() >> ($File)
    $value = "" >> ($File)
    $value = "-----------------------------------------------------------------------" >> ($File)
    $value = "" >> ($File)
    $value = "The Move Request has the following Failures:" >> ($File)
    $value = $MoveRequestStatistics.Report.Failures | Group-Object  FailureType | ft Count, Name >> ($File)
    $value = "-----------------------------------------------------------------------" >> ($File)
    $value = "" >> ($File)
    $value = "Here is more details about each Failure (Note that only the last error is selected in more details):" >> ($File)
    $value = "" >> ($File)
    $detailedFailure >> ($File)
    #>
}

#===================MAIN======================
New-Item $OutputFolder -ItemType Directory -Force | Out-Null
New-Item $logFile -Type File -Force -ErrorAction SilentlyContinue | Out-Null

foreach ($Mailbox in $Identity) {

    $ErrorActionPreference = 'SilentlyContinue'
    $MoveRequest = Get-MoveRequest $Mailbox -ErrorAction SilentlyContinue
    $MoveRequestStatistics = Get-MoveRequestStatistics $Mailbox -IncludeReport -DiagnosticInfo "showtimeslots, showtimeline, verbose" -ErrorAction SilentlyContinue
    if ($null -eq $MoveRequest) {
        Write-Host -ForegroundColor Red -Value "[ERROR] The MoveRequest for the $Mailbox cannot be found, please check spelling and try again!"
        Add-Content -Path $logFile -Value "[ERROR] The MoveRequest for the $Mailbox cannot be found, please check spelling and try again!"
    }
    $Batch = $MoveRequestStatistics.BatchName
    $MigrationBatch = Get-MigrationBatch $Batch -IncludeReport -DiagnosticInfo "showtimeslots, showtimeline, verbose" -ErrorAction SilentlyContinue
    $UserMigration = Get-MigrationUser $Mailbox  -ErrorAction SilentlyContinue
    $UserMigrationStatistics = Get-MigrationUserStatistics $Mailbox -IncludeSkippedItems -IncludeReport -DiagnosticInfo "showtimeslots, showtimeline, verbose" -ErrorAction SilentlyContinue
    $Endpoint = $MigrationBatch.SourceEndpoint
    $MigrationEndPoint = Get-MigrationEndpoint -Identity $Endpoint -DiagnosticInfo Verbose -ErrorAction SilentlyContinue
    $MailboxStatistics = Get-MailboxStatistics $Mailbox -IncludeMoveReport -IncludeMoveHistory -ErrorAction SilentlyContinue
    $MoveHistory = Get-MailboxStatistics $Mailbox -IncludeMoveReport -IncludeMoveHistory -ErrorAction SilentlyContinue
    $Uniquefailure = $MoveRequestStatistics.Report.Failures | Select-Object FailureType -Unique
    $DetailedFailure = foreach ($U in $uniquefailure) { $MoveRequestStatistics.Report.Failures | Where-Object { $_.FailureType -like $U.FailureType } | Select-Object Timestamp, FailureType, FailureSide, Message -Last 1 | Format-Table -Wrap }
    $File = "$OutputFolder\Text-Summary_$Mailbox.txt"
    New-Item $file   -Type File -Force -ErrorAction SilentlyContinue | Out-Null

    try {
        if (-not $null -eq $MoveRequestStatistics ) {
            Export-XMLReports
            Export-Summary
            Write-Host -ForegroundColor "Green" "The MoveRequest reports for $Mailbox exported successfully!"
        }
    } catch {
        Add-Content -Path $logFile -Value "[ERROR] The MoveRequest for the $Mailbox cannot be found, please check spelling and try again!"
        Add-Content -Path $logFile -Value $_
        Write-Host -ForegroundColor "Red" "The MoveRequest for the $Mailbox cannot be found, please check spelling and try again!"
        throw
    }
}

$compress = @{
    Path             = $OutputFolder
    CompressionLevel = "Fastest"
    DestinationPath  = "Migration-Reports.Zip"
}
Compress-Archive @compress
