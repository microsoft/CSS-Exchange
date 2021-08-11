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

#Not sure why yet, but if you do -Verbose with the script, we end up in a loop somehow.
#Going to add in this hard fix for the time being to avoid issues.
$Script:VerbosePreference = "SilentlyContinue"

$BuildVersion = ""

. $PSScriptRoot\Troubleshoot-ModernSearch\Exchange\Get-MailboxInformation.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-BasicMailboxQueryContext.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-CategoryOffStatistics.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-FolderInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-MessageIndexState.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\Get-QueryItemResult.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\StoreQuery\StoreQueryFunctions.ps1

. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-BasicMailboxInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-CheckSearchProcessState.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-DisplayObjectInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-Error.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-LogInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-MailboxIndexMessageStatistics.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-MailboxStatisticsOnServer.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-ScriptOutput.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-Verbose.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write\Write-Warning.ps1

$Script:ScriptLogging = "$PSScriptRoot\Troubleshoot-ModernSearchLog_$(([DateTime]::Now).ToString('yyyyMMddhhmmss')).log"

try {

    $configuredVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\AdminTools -ErrorAction Stop).ConfiguredVersion

    if ([version]$configuredVersion -lt [version]"15.2.0.0") {
        throw "Not running on an Exchange 2019 server or greater."
    }

    $installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    . "$installPath\Scripts\ManagedStoreDiagnosticFunctions.ps1"
} catch {

    throw "Failed to load ManagedStoreDiagnosticFunctions.ps1 Inner Exception: $($Error[0].Exception) Stack Trace: $($Error[0].ScriptStackTrace)"
}

Function Main {
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
    ) | Write-ScriptOutput -Diagnostic
    Write-ScriptOutput "" -Diagnostic

    if ($null -ne $Server -and
        $Server.Count -ge 1) {

        Write-MailboxStatisticsOnServer -Server $Server -SortByProperty $SortByProperty -ExcludeFullyIndexedMailboxes $ExcludeFullyIndexedMailboxes -ExportData $ExportData
        return
    }

    Write-ScriptOutput "Getting user mailbox information for $MailboxIdentity"

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
    Write-ScriptOutput "----------------------------------------"

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

        Write-ScriptOutput "Found $($messages.Count) different messages"
        Write-ScriptOutput "Messages Index State:"

        for ($i = 0; $i -lt $messages.Count; $i++) {
            Write-ScriptOutput ""
            Write-ScriptOutput "Found Item $($i + 1): "
            Write-ScriptOutput $messages[$i]
        }

        if ($ExportData) {
            $filePath = "$PSScriptRoot\MessageResults_$ItemSubject_$(([DateTime]::Now).ToString('yyyyMMddhhmmss')).csv"
            Write-ScriptOutput "Exporting Full Mailbox Stats out to: $filePath"
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
                Write-ScriptOutput ""
            }
        }
    } else {

        if ($null -ne $DocumentId -and
            $DocumentId -ne 0) {
            Write-ScriptOutput "Failed to find message with Document ID: $DocumentId"
        } else {
            Write-ScriptOutput "Failed to find message with subject '$ItemSubject'"
            Write-ScriptOutput "Make sure the subject is correct for what you are looking for. We should be able to find the item if it is indexed or not."
        }
    }

    $categories = Get-CategoryOffStatistics -MailboxStatistics $mailboxInformation.MailboxStatistics

    if ($categories.Count -gt 0) {
        Write-ScriptOutput ""
        Write-ScriptOutput "----------------------------------------"
        Write-ScriptOutput "Collecting Message Stats on the following Categories:"
        Write-ScriptOutput ""
        $categories | Write-ScriptOutput
        Write-ScriptOutput ""
        Write-ScriptOutput "This may take some time to collect."
        Write-MailboxIndexMessageStatistics -BasicMailboxQueryContext $basicMailboxQueryContext -MailboxStatistics $mailboxInformation.MailboxStatistics -Category $categories -GroupMessages $GroupMessages
    }
}

try {
    Out-File -FilePath $Script:ScriptLogging -Force | Out-Null
    Write-ScriptOutput "Starting Script At: $([DateTime]::Now)" -Diagnostic
    Write-ScriptOutput "Build Version: $BuildVersion" -Diagnostic
    Main
    Write-ScriptOutput "Finished Script At: $([DateTime]::Now)" -Diagnostic
    Write-Output "File Written at: $Script:ScriptLogging"
} catch {
    Write-ScriptOutput "$($Error[0].Exception)"
    Write-ScriptOutput "$($Error[0].ScriptStackTrace)"
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}
