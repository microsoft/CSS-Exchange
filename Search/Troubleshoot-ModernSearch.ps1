# Copyright (c) Microsoft Corporation.
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

    [Parameter(Mandatory = $false, ParameterSetName = "MultiMailboxStatistics")]
    [ValidateNotNullOrEmpty()]
    [string[]]$Server,

    [Parameter(Mandatory = $false, ParameterSetName = "MultiMailboxStatistics")]
    [ValidateSet("TotalMailboxItems", "TotalBigFunnelSearchableItems", "TotalSearchableItems",
        "BigFunnelIndexedCount", "IndexedCount", "BigFunnelNotIndexedCount", "NotIndexedCount",
        "BigFunnelPartiallyIndexedCount", "PartIndexedCount", "BigFunnelCorruptedCount", "CorruptedCount",
        "BigFunnelStaleCount", "StaleCount", "BigFunnelShouldNotBeIndexedCount", "ShouldNotIndexCount", "FullyIndexPercentage")]
    [ValidateNotNullOrEmpty()]
    [string]$SortByProperty = "FullyIndexPercentage",

    [Parameter(Mandatory = $false, ParameterSetName = "MultiMailboxStatistics")]
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

. $PSScriptRoot\Troubleshoot-ModernSearch\Exchange\Get-MailboxInformation.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-BasicMailboxQueryContext.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-CategoryOffStatistics.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-FolderInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-MessageIndexState.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-QueryItemResult.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-BasicMailboxInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-CheckSearchProcessState.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-DisplayObjectInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-Error.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-LogInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-MailboxIndexMessageStatistics.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-MailboxStatisticsOnServer.ps1

. $PSScriptRoot\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\Shared\StoreQueryFunctions.ps1
. $PSScriptRoot\..\Shared\Write-ErrorInformation.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Warning.ps1
. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

$Script:ScriptLogging = "$PSScriptRoot\Troubleshoot-ModernSearchLog_$(([DateTime]::Now).ToString('yyyyMMddhhmmss')).log"

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

    if ($null -ne $Server -and
        $Server.Count -ge 1) {

        Write-MailboxStatisticsOnServer -Server $Server -SortByProperty $SortByProperty -ExcludeFullyIndexedMailboxes $ExcludeFullyIndexedMailboxes -ExportData $ExportData
        return
    }

    Write-Host "Getting user mailbox information for $MailboxIdentity"

    $mailboxInformation = Get-MailboxInformation -Identity $MailboxIdentity -IsArchive $IsArchive -IsPublicFolder $IsPublicFolder

    Write-BasicMailboxInformation -MailboxInformation $mailboxInformation
    Write-CheckSearchProcessState -ActiveServer $mailboxInformation.PrimaryServer

    $storeQueryHandler = Get-StoreQueryObject -MailboxInformation $mailboxInformation
    $basicMailboxQueryContext = Get-BasicMailboxQueryContext -StoreQueryHandler $storeQueryHandler

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
    Write-Host "----------------------------------------"

    if ($Category.Count -ge 1) {

        Write-MailboxIndexMessageStatistics -BasicMailboxQueryContext $basicMailboxQueryContext -MailboxStatistics $mailboxInformation.MailboxStatistics -Category $Category -GroupMessages $GroupMessages
        return
    }

    if (-not([string]::IsNullOrEmpty($FolderName))) {
        $folderInformation = Get-FolderInformation -BasicMailboxQueryContext $basicMailboxQueryContext -DisplayName $FolderName
    }

    $passParams = @{
        BasicMailboxQueryContext = $basicMailboxQueryContext
    }

    if ($null -ne $DocumentId -and
        $DocumentId -ne 0) {
        $passParams["DocumentId"] = $DocumentId
    } else {
        $passParams["MessageSubject"] = $ItemSubject
        $passParams["MatchSubjectSubstring"] = $MatchSubjectSubstring

        if ($null -ne $folderInformation) {
            $passParams["FolderInformation"] = $folderInformation
        }
    }

    $messages = @(Get-MessageIndexState @passParams)

    if ($messages.Count -gt 0) {

        Write-Host "Found $($messages.Count) different messages"
        Write-Host "Messages Index State:"

        for ($i = 0; $i -lt $messages.Count; $i++) {
            Write-Host ""
            Write-Host "Found Item $($i + 1): "
            $messages[$i] | Out-String | Write-Host
        }

        if ($ExportData) {
            $filePath = "$PSScriptRoot\MessageResults_$ItemSubject_$(([DateTime]::Now).ToString('yyyyMMddhhmmss')).csv"
            Write-Host "Exporting Full Mailbox Stats out to: $filePath"
            $messages | Export-Csv -Path $filePath
        }

        if (-not([string]::IsNullOrEmpty($QueryString))) {
            $queryItemResults = Get-QueryItemResult -BasicMailboxQueryContext $basicMailboxQueryContext `
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

    $categories = Get-CategoryOffStatistics -MailboxStatistics $mailboxInformation.MailboxStatistics

    if ($categories.Count -gt 0) {
        Write-Host ""
        Write-Host "----------------------------------------"
        Write-Host "Collecting Message Stats on the following Categories:"
        Write-Host ""
        $categories | Out-String | Write-Host
        Write-Host ""
        Write-Host "This may take some time to collect."
        Write-MailboxIndexMessageStatistics -BasicMailboxQueryContext $basicMailboxQueryContext -MailboxStatistics $mailboxInformation.MailboxStatistics -Category $categories -GroupMessages $GroupMessages
    }
}

try {
    if (-not (Confirm-Administrator)) {
        Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator."
        exit
    }
    Out-File -FilePath $Script:ScriptLogging -Force | Out-Null
    SetWriteHostAction ${Function:Write-LogInformation}
    SetWriteVerboseAction ${Function:Write-LogInformation}
    SetWriteWarningAction ${Function:Write-LogInformation}

    if ((Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/TMS-VersionsUrl")) {
        Write-Warning "Script was updated. Please rerun the command."
        return
    }

    Write-Verbose "Starting Script At: $([DateTime]::Now)"
    Write-Host "Exchange Troubleshot Modern Search Version $BuildVersion"
    Main
    Write-Verbose "Finished Script At: $([DateTime]::Now)"
    Write-Host "File Written at: $Script:ScriptLogging"
} catch {
    Write-HostErrorInformation $_
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}
