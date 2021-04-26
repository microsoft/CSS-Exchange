#Exchange On Prem Script to help assist with determining why search might not be working on an Exchange 2019+ Server
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameter is used')]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
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
    [string]$Category,

    [ValidateNotNullOrEmpty()]
    [string]
    $QueryString,

    [switch]
    $IsArchive,

    [switch]
    $IsPublicFolder
)

. $PSScriptRoot\Troubleshoot-ModernSearch\Get-BasicMailboxQueryContext.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Get-FolderInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Get-MailboxInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Get-MessageIndexState.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Get-QueryItemResult.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Get-StoreQueryHandler.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write-DisplayObjectInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write-LogInformation.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write-MailboxIndexMessageStatistics.ps1
. $PSScriptRoot\Troubleshoot-ModernSearch\Write-ScriptOutput.ps1

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
    Write-ScriptOutput ""
    Write-ScriptOutput "Getting user mailbox information for $MailboxIdentity"
    @("Identity: '$MailboxIdentity'",
        "ItemSubject: '$ItemSubject'",
        "FolderName: '$FolderName'",
        "DocumentId: '$DocumentId'",
        "MatchSubjectSubstring: '$MatchSubjectSubstring'",
        "Category: '$Category'",
        "QueryString: '$QueryString'",
        "IsArchive: '$IsArchive'",
        "IsPublicFolder: '$IsPublicFolder'") | Write-ScriptOutput -Diagnostic
    Write-ScriptOutput "" -Diagnostic

    $mailboxInformation = Get-MailboxInformation -Identity $MailboxIdentity -IsArchive $IsArchive -IsPublicFolder $IsPublicFolder

    Write-ScriptOutput ""
    Write-ScriptOutput "----------------------------------------"
    Write-ScriptOutput "Basic Mailbox Information:"
    Write-ScriptOutput "Mailbox GUID = $($mailboxInformation.MailboxGuid)"
    Write-ScriptOutput "Mailbox Database: $($mailboxInformation.Database)"
    Write-ScriptOutput "Active Server: $($mailboxInformation.PrimaryServer)"
    Write-ScriptOutput "Exchange Server Version: $($mailboxInformation.ExchangeServer.AdminDisplayVersion)"
    Write-ScriptOutput "----------------------------------------"
    Write-ScriptOutput ""
    Write-ScriptOutput "Big Funnel Count Information Based Off Get-MailboxStatistics"
    Write-DisplayObjectInformation -DisplayObject $mailboxInformation.MailboxStatistics -PropertyToDisplay @(
        "BigFunnelMessageCount",
        "BigFunnelIndexedCount",
        "BigFunnelPartiallyIndexedCount",
        "BigFunnelNotIndexedCount",
        "BigFunnelCorruptedCount",
        "BigFunnelStaleCount",
        "BigFunnelShouldNotBeIndexedCount"
    )
    Write-ScriptOutput "----------------------------------------"
    Write-ScriptOutput ""
    Write-ScriptOutput ($mailboxInformation.MailboxStatistics | Format-List) -Diagnostic
    Write-ScriptOutput "" -Diagnostic
    Write-ScriptOutput ($mailboxInformation.DatabaseStatus | Format-List) -Diagnostic
    Write-ScriptOutput "" -Diagnostic
    Write-ScriptOutput ($mailboxInformation.DatabaseCopyStatus | Format-List) -Diagnostic
    Write-ScriptOutput "" -Diagnostic
    Write-ScriptOutput ($mailboxInformation.MailboxInfo | Format-List) -Diagnostic
    Write-ScriptOutput "" -Diagnostic

    $storeQueryHandler = Get-StoreQueryHandler -MailboxInformation $mailboxInformation -VerboseDiagnosticsCaller ${Function:Write-LogInformation}
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

    if (-not([string]::IsNullOrEmpty($Category))) {

        Write-MailboxIndexMessageStatistics -BasicMailboxQueryContext $basicMailboxQueryContext -MailboxStatistics $mailboxInformation.MailboxStatistics -Category $Category
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

    $mailboxStats = $mailboxInformation.MailboxStatistics
    $categories = New-Object 'System.Collections.Generic.List[string]'

    if ($mailboxStats.BigFunnelNotIndexedCount -ge 250) {
        $categories.Add("NotIndexed")
    }

    if ($mailboxStats.BigFunnelCorruptedCount -ge 100) {
        $categories.Add("Corrupted")
    }

    if ($mailboxStats.BigFunnelPartiallyIndexedCount -ge 1000) {
        $categories.Add("PartiallyIndexed")
    }

    if ($mailboxStats.BigFunnelStaleCount -ge 100) {
        $categories.Add("Stale")
    }

    if ($mailboxStats.BigFunnelShouldNotBeIndexedCount -ge 5000) {
        $categories.Add("ShouldNotBeIndexed")
    }

    if ($categories.Count -gt 0) {
        Write-ScriptOutput ""
        Write-ScriptOutput "----------------------------------------"
        Write-ScriptOutput "Collecting Message Stats on the following Categories:"
        Write-ScriptOutput ""
        $categories | Write-ScriptOutput
        Write-ScriptOutput ""
        Write-ScriptOutput "This may take some time to collect."
        Write-MailboxIndexMessageStatistics -BasicMailboxQueryContext $basicMailboxQueryContext -MailboxStatistics $mailboxStats -Category $categories
    }
}

try {
    Out-File -FilePath $Script:ScriptLogging -Force | Out-Null
    Write-ScriptOutput "Starting Script At: $([DateTime]::Now)" -Diagnostic
    Main
    Write-ScriptOutput "Finished Script At: $([DateTime]::Now)" -Diagnostic
    Write-Output "File Written at: $Script:ScriptLogging"
} catch {
    Write-ScriptOutput "$($Error[0].Exception)"
    Write-ScriptOutput "$($Error[0].ScriptStackTrace)"
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}
