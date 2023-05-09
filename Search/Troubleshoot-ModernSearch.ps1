﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Exchange On Prem Script to help assist with determining why search might not be working on an Exchange 2019+ Server
[CmdletBinding(DefaultParameterSetName = "SubjectAndFolder")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "SubjectAndFolder")]
    [Parameter(Mandatory = $true, ParameterSetName = "DocumentId")]
    [Parameter(Mandatory = $true, ParameterSetName = "MailboxIndexStatistics")]
    [ValidateNotNullOrEmpty()]
    [string]
    $MailboxIdentity,

    [Parameter(Mandatory = $true, ParameterSetName = "SubjectAndFolder")]
    [ValidateNotNullOrEmpty()]
    [string]
    $ItemSubject,

    [Parameter(Mandatory = $false, ParameterSetName = "SubjectAndFolder")]
    [ValidateNotNullOrEmpty()]
    [string]
    $FolderName,

    [Parameter(Mandatory = $false, ParameterSetName = "SubjectAndFolder")]
    [ValidateNotNullOrEmpty()]
    [switch]
    $MatchSubjectSubstring,

    [Parameter(Mandatory = $true, ParameterSetName = "DocumentId")]
    [int]
    $DocumentId,

    [Parameter(Mandatory = $true, ParameterSetName = "MailboxIndexStatistics")]
    [ValidateSet("All", "Indexed", "PartiallyIndexed", "NotIndexed", "Corrupted", "Stale", "ShouldNotBeIndexed")]
    [string[]]$Category,

    [Parameter(Mandatory = $false, ParameterSetName = "MailboxIndexStatistics")]
    [bool]$GroupMessages = $true,

    [Parameter(Mandatory = $true, ParameterSetName = "ServerSearchInformation")]
    [ValidateNotNullOrEmpty()]
    [string[]]$Server,

    [Parameter(Mandatory = $false, ParameterSetName = "ServerSearchInformation")]
    [ValidateSet("TotalMailboxItems", "TotalBigFunnelSearchableItems", "TotalSearchableItems",
        "BigFunnelIndexedCount", "IndexedCount", "BigFunnelNotIndexedCount", "NotIndexedCount",
        "BigFunnelPartiallyIndexedCount", "PartIndexedCount", "BigFunnelCorruptedCount", "CorruptedCount",
        "BigFunnelStaleCount", "StaleCount", "BigFunnelShouldNotBeIndexedCount", "ShouldNotIndexCount", "FullyIndexPercentage")]
    [ValidateNotNullOrEmpty()]
    [string]$SortByProperty = "FullyIndexPercentage",

    [Parameter(Mandatory = $false, ParameterSetName = "ServerSearchInformation")]
    [ValidateNotNullOrEmpty()]
    [bool]$ExcludeFullyIndexedMailboxes = $true,

    [ValidateNotNullOrEmpty()]
    [string]
    $QueryString,

    [switch]
    $IsArchive,

    [switch]
    $IsPublicFolder,

    [bool]
    $ExportData = $true
)

$BuildVersion = ""

. $PSScriptRoot\Troubleshoot-ModernSearch\Exchange\Get-ActiveDatabasesOnServer.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Exchange\Get-MailboxInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Exchange\Get-MailboxStatisticsOnDatabase.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\Helpers\Invoke-SearchServiceState.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Helpers\Get-CategoryOffStatistics.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-StoreQueryBasicMailboxQueryContext.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-StoreQueryFolderInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-StoreQueryMessageIndexState.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-StoreQueryQueryItemResult.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Helpers\Get-MailboxMessagesForCategory.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-BasicMailboxInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-DataExport.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-Error.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-LogInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-LogsToZip.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\WriteHelpers.ps1

. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\Shared\StoreQueryFunctions.ps1
. $PSScriptRoot\..\Shared\Write-ErrorInformation.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Warning.ps1
. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

$scriptName = $MyInvocation.MyCommand.ToString().Replace(".ps1", "")
$loggingDirectory = "$PSScriptRoot\$scriptName"
$uniqueRunTime = ([DateTime]::Now).ToString('yyyyMMddhhmmss')
$exportDataFilePaths = New-Object "System.Collections.Generic.List[string]"

try {
    # Logger instance will create the directory and can throw.
    $params = @{
        LogDirectory             = $loggingDirectory
        AppendDateTimeToFileName = $false
    }
    $Script:ScriptLogger = Get-NewLoggerInstance @params -LogName "$scriptName`_Log_$($uniqueRunTime)" -AppendDateTime $false
    $Script:ScriptDebugLogger = Get-NewLoggerInstance @params -LogName "$scriptName`_Debug_Log_$($uniqueRunTime)"
} catch {
    Write-Error "Failed to create logging directory: $loggingDirectory. Inner Exception: $_"
    exit
}

try {
    $configuredVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\AdminTools -ErrorAction Stop).ConfiguredVersion

    if ([version]$configuredVersion -lt [version]"15.2.0.0") {
        Write-Error "Not running on an Exchange 2019 server or greater. Stopping Script"
        exit
    }
} catch {
    Write-Error "Failed to determine the configured version of Exchange. Stopping Script"
    exit
}

function Main {
    @("Identity: '$MailboxIdentity'",
        "ItemSubject: '$ItemSubject'",
        "FolderName: '$FolderName'",
        "DocumentId: '$DocumentId'",
        "MatchSubjectSubstring: '$MatchSubjectSubstring'",
        "Category: '$Category'",
        "GroupMessages: '$GroupMessages'",
        "Server: '$Server'",
        "SortByProperty: '$SortByProperty'",
        "ExcludeFullyIndexedMailboxes: '$ExcludeFullyIndexedMailboxes'",
        "QueryString: '$QueryString'",
        "IsArchive: '$IsArchive'",
        "IsPublicFolder: '$IsPublicFolder'",
        "ExportData: '$ExportData'"
    ) | Write-Verbose
    Write-Verbose ""

    if ($PsCmdlet.ParameterSetName -eq "ServerSearchInformation") {

        <#
            Check the Search Services state on the server(s).
            Collect the active mailbox databases on the server(s).
            Then review the mailbox stats on the server(s), based off the active mailbox databases.
            Sort the mailboxes in the order based off possible parameters passed to the script.
            For the top 10 mailboxes, we want to collect additional mailbox information for them.
        #>
        Invoke-SearchServiceState -Servers $Server
        $activeDatabases = Get-ActiveDatabasesOnServer -Server $Server
        $mailboxStatistics = Get-MailboxStatisticsOnDatabase -MailboxDatabase $activeDatabases.DBName

        # Set the Correct SortByProperty
        switch ($SortByProperty) {
            "TotalSearchableItems" { $SortByProperty = "TotalBigFunnelSearchableItems" }
            "IndexedCount" { $SortByProperty = "BigFunnelIndexedCount" }
            "NotIndexedCount" { $SortByProperty = "BigFunnelNotIndexedCount" }
            "PartIndexedCount" { $SortByProperty = "BigFunnelPartiallyIndexedCount" }
            "CorruptedCount" { $SortByProperty = "BigFunnelCorruptedCount" }
            "StaleCount" { $SortByProperty = "BigFunnelStaleCount" }
            "ShouldNotIndexCount" { $SortByProperty = "BigFunnelShouldNotBeIndexedCount" }
        }
        $sortObjectDescending = $SortByProperty -ne "FullyIndexPercentage"

        $filterMailboxes = $mailboxStatistics | Where-Object {
            if ($ExcludeFullyIndexedMailboxes -and
                $_.FullyIndexPercentage -eq 100) {
                # Don't add to the list
            } elseif ($_.TotalBigFunnelSearchableItems -eq 0) {
                Write-Verbose "Not adding mailbox $($_.MailboxGuid) to list because there are no searchable items"
            } else {
                return $_
            }
        } | Sort-Object $SortByProperty -Descending:$sortObjectDescending

        $filterMailboxes |
            Select-Object MailboxGuid,
            @{Name = "TotalSearchableItems"; Expression = { $_.TotalBigFunnelSearchableItems } },
            @{Name = "IndexedCount"; Expression = { $_.BigFunnelIndexedCount } },
            @{Name = "NotIndexedCount"; Expression = { $_.BigFunnelNotIndexedCount } },
            @{Name = "PartIndexedCount"; Expression = { $_.BigFunnelPartiallyIndexedCount } } ,
            @{Name = "CorruptedCount"; Expression = { $_.BigFunnelCorruptedCount } },
            @{Name = "StaleCount"; Expression = { $_.BigFunnelStaleCount } },
            @{Name = "ShouldNotIndexCount"; Expression = { $_.BigFunnelShouldNotBeIndexedCount } },
            FullyIndexPercentage,
            IndexPercentage |
            Format-Table |
            Out-String |
            Write-Host

        # Get the top 10 mailboxes for a list to automatically process
        Write-Host "Getting the top 10 mailboxes category information"
        $topMailboxes = $filterMailboxes |
            Select-Object -First 10 |
            ForEach-Object { return $_ }
        $cacheMailboxInformation = @{}

        # TODO: Write-Progress
        $topMailboxes | ForEach-Object {
            $mbxGuid = $_.MailboxGuid
            $isPublicFolder = $_.MailboxTypeDetail -eq "None" -and $_.MailboxType -like "PublicFolder*"
            $isArchive = $_.IsArchiveMailbox
            try {
                $mailboxInformation = Get-MailboxInformation -Identity $mbxGuid -IsArchive $isArchive -IsPublicFolder $isPublicFolder
                $cacheMailboxInformation.Add($mbxGuid, $mailboxInformation)
            } catch {
                Write-Host "Failed to find mailbox $mbxGuid."
                Write-HostErrorInformation
            }
        }

        # foreach of the mailboxes we got data back from, loop through and collect the data we want.
        $cacheMailboxInformation.Keys | ForEach-Object {
            $mbxGuid = $_
            $mailboxInformation = $cacheMailboxInformation[$mbxGuid]

            # Write Basic Mailbox Information to screen.
            Write-BasicMailboxInformation -MailboxInformation $mailboxInformation

            # Determine the categories that we want to collect
            # Based off default or what is passed. #TODO this action
            $categories = Get-CategoryOffStatistics -MailboxStatistics $mailboxInformation.MailboxStatistics

            # Query the database with store query based off the categories that we have.
            # Each category is another query against the database
            # After each category query, display the information, but add it to a list of found messages.
            # Display is depending on GroupMessages or not.
            $messagesForMailbox = Get-MailboxMessagesForCategory -MailboxInformation $mailboxInformation -Category $categories -GroupMessages $GroupMessages

            if ($ExportData) {
                $params = @{
                    MailboxInformation = $mailboxInformation
                    RootDirectory      = $loggingDirectory
                    LocationExported   = [ref]$exportDataFilePaths
                    Messages           = $messagesForMailbox
                    UniqueId           = $uniqueRunTime
                }
                Write-DataExport @params
            }

            Write-Host
            Write-DashLineBox "----------------------------------------------------"
        }
        return
    }

    <#
        Lookup a single mailbox collection option
            - Find the information about the mailbox (Exchange)
            - Check the status of the Search Services on that active server
            - Get Store Query Information
            - Display the information about the mailbox
            - Then logic detection for what set of parameters were selected
    #>

    # It is possible this can throw and should not be handled to allow the script to bail out here.
    $mailboxInformation = Get-MailboxInformation -Identity $MailboxIdentity -IsArchive $IsArchive -IsPublicFolder $IsPublicFolder

    Invoke-SearchServiceState -Servers $mailboxInformation.PrimaryServer

    $storeQueryHandler = Get-StoreQueryObject -MailboxInformation $mailboxInformation
    $basicMailboxQueryContext = Get-StoreQueryBasicMailboxQueryContext -StoreQueryHandler $storeQueryHandler

    Write-BasicMailboxInformation -MailboxInformation $mailboxInformation
    Write-DisplayObjectInformation -DisplayObject $basicMailboxQueryContext -PropertyToDisplay @(
        "BigFunnelIsEnabled",
        "FastIsEnabled",
        "BigFunnelMailboxCreationVersion",
        "BigFunnelDictionaryVersion",
        "BigFunnelPostingListTableVersion",
        "BigFunnelPostingListTableChunkSize",
        "BigFunnelPostingListTargetTableVersion",
        "BigFunnelPostingListTargetTableChunkSize",
        "BigFunnelMaintainRefiners",
        "CreationTime",
        "MailboxNumber"
    )

    <#
        Logic for determining what we are wanting to lookup.
        - If $Category is set, we only want to find that category information
            - Do this export the data then return
        - Ready the parameters for trying to find the message(s)
            - If $FolderName isn't null, add it to the parameters
        - If messages found display them
        - If $QueryString provided, test Query against the found messages
        - Collect Additional Mailbox Information off of Categories if Mailbox Stats meet the criteria
        - Export the data
    #>

    if ($Category.Count -ge 1) {

        $messagesForMailbox = Get-MailboxMessagesForCategory -MailboxInformation $mailboxInformation -Category $Category -GroupMessages $GroupMessages

        if ($ExportData) {
            $params = @{
                MailboxInformation = $mailboxInformation
                RootDirectory      = $loggingDirectory
                LocationExported   = [ref]$exportDataFilePaths
                Messages           = $messagesForMailbox
                UniqueId           = $uniqueRunTime
            }
            Write-DataExport @params
        }
        return
    }

    # Ready the parameters to pass to Get-StoreQueryMessageIndexState
    $passParams = @{
        BasicMailboxQueryContext = $basicMailboxQueryContext
    }

    if ($null -ne $DocumentId -and
        $DocumentId -ne 0) {
        $passParams["DocumentId"] = $DocumentId
    } else {
        $passParams["MessageSubject"] = $ItemSubject
        $passParams["MatchSubjectSubstring"] = $MatchSubjectSubstring

        if (-not([string]::IsNullOrEmpty($FolderName))) {
            $folderInformation = Get-StoreQueryFolderInformation -BasicMailboxQueryContext $basicMailboxQueryContext -DisplayName $FolderName

            if ($null -ne $folderInformation) {
                $passParams["FolderInformation"] = $folderInformation
            }
        }
    }

    $messagesForMailbox = New-Object 'System.Collections.Generic.List[object]'
    $messages = @(Get-StoreQueryMessageIndexState @passParams)

    if ($messages.Count -gt 0) {

        Write-Host
        Write-DashLineBox @("Found $($messages.Count) different message(s)", "", "Message(s) Index State")
        $messagesForMailbox.AddRange($messages)

        for ($i = 0; $i -lt $messages.Count; $i++) {
            Write-Host ""
            Write-Host "Found Item $($i + 1): "
            $messages[$i] | Out-String | Write-Host
        }

        if (-not([string]::IsNullOrEmpty($QueryString))) {
            $queryItemResults = Get-StoreQueryQueryItemResult -BasicMailboxQueryContext $basicMailboxQueryContext `
                -DocumentId ($messages.MessageDocumentId) `
                -QueryString $QueryString `
                -QueryScope "SearchAllIndexedProps"

            foreach ($item in $queryItemResults) {
                Write-DisplayObjectInformation -DisplayObject $item -PropertyToDisplay @(
                    "DocumentID",
                    "BigFunnelMatchFilter",
                    "BigFunnelMatchPOI"
                )
                Write-Host ""
            }
        }
    } else {

        if ($null -ne $DocumentId -and
            $DocumentId -ne 0) {
            Write-Host "Failed to find message with Document ID: $DocumentId"
        } else {
            Write-Host "Failed to find message with subject '$ItemSubject'"
            Write-Host "Make sure the subject is correct for what you are looking for. We should be able to find the item if it is indexed or not."
        }
    }

    # Check to see if we have any categories of messages that we should look into.
    $categories = Get-CategoryOffStatistics -MailboxStatistics $mailboxInformation.MailboxStatistics

    if ($categories.Count -gt 0) {
        Write-Host ""
        Write-DashLineBox @("Collecting Message Stats on the following Categories:", "", $categories)
        Write-Host "This may take some time to collect."
        [array]$messages = Get-MailboxMessagesForCategory -MailboxInformation $mailboxInformation -Category $categories -GroupMessages $GroupMessages

        if ($messages.Count -gt 0) {
            $messagesForMailbox.AddRange($messages)
        }
    }

    if ($ExportData) {
        $params = @{
            MailboxInformation = $mailboxInformation
            RootDirectory      = $loggingDirectory
            LocationExported   = [ref]$exportDataFilePaths
            Messages           = $messagesForMailbox
            UniqueId           = $uniqueRunTime
        }
        Write-DataExport @params
    }
}

try {
    if (-not (Confirm-Administrator)) {
        Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator."
        exit
    }
    SetWriteHostAction ${Function:Write-LogInformation}
    SetWriteVerboseAction ${Function:Write-DebugLogInformation}
    SetWriteWarningAction ${Function:Write-LogInformation}

    if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/TMS-VersionsUrl")) {
        Write-Warning "Script was updated. Please rerun the command."
        return
    }

    Write-Verbose "Starting Script At: $([DateTime]::Now)"
    Write-Host "Exchange Troubleshot Modern Search Version $BuildVersion"
    Set-ADServerSettings -ViewEntireForest $true
    Main
    Write-Verbose "Finished Script At: $([DateTime]::Now)"

    if ($exportDataFilePaths.Count -gt 0) {
        $exportDataFilePaths.Add($Script:ScriptLogger.FullPath)
        $exportDataFilePaths.Add($Script:ScriptDebugLogger.FullPath)
        Write-LogsToZip -LiteralPath $exportDataFilePaths -DestinationPath ( [System.IO.Path]::Combine($loggingDirectory, "Logs-$uniqueRunTime.zip"))
    } else {
        Write-Host "File Written at: $($Script:ScriptLogger.FullPath)"
    }
} catch {
    Write-HostErrorInformation $_
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}
