[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $UserEmail,

    [Parameter(Mandatory = $true, ParameterSetName = "SubjectAndFolder")]
    [ValidateNotNullOrEmpty()]
    [string]
    $ItemSubject,

    [Parameter(Mandatory = $false, ParameterSetName = "SubjectAndFolder")]
    [ValidateNotNullOrEmpty()]
    [string]
    $FolderName,

    [Parameter(Mandatory = $true, ParameterSetName = "DocumentId")]
    [int]
    $DocumentId,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [switch]
    $MatchSubjectSubstring
)


$installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
. "$installPath\Scripts\ManagedStoreDiagnosticFunctions.ps1"

# Obtain mailbox info for the user.
Write-Host "Getting user mailbox information for $UserEmail" -ForegroundColor White

$info = Get-Mailbox $UserEmail
$guid = $info.ExchangeGuid.Guid
$db = $info.Database
$dbCopyStatus = Get-MailboxDatabaseCopyStatus $db\* | Where-Object { $_.Status -like '*Mounted*' }
$primaryServer = $dbCopyStatus.Name.Substring($dbCopyStatus.Name.IndexOf('\') + 1)
$primaryServerInfo = Get-ExchangeServer $primaryServer
$primaryServerBuild = $primaryServerInfo.AdminDisplayVersion

Write-Host "Mailbox GUID =  $guid"
Write-Host "Mailbox database/primary copy machine/build  =  $db / $primaryServer / $primaryServerBuild"

$dbIdentity = @(Get-MailboxDatabase -Identity $db)

if ($dbIdentity.Count -eq 0) {
    Write-Error "Database $db not found."
    exit
} elseif ($dbIdentity.Count -gt 1) {
    Write-Error "Database $db matches more than one database."
    exit
}

$dbStatus = Get-MailboxDatabase $dbIdentity[0].Name -Status

$result = Get-StoreQuery -Server $dbStatus.MountedOnServer -ProcessId $dbStatus.WorkerProcessId -Query "SELECT BigFunnelIsEnabled, FastIsEnabled, BigFunnelMailboxCreationVersion, BigFunnelDictionaryVersion, BigFunnelPostingListTableVersion, BigFunnelPostingListTableChunkSize, BigFunnelPostingListTargetTableVersion, BigFunnelPostingListTargetTableChunkSize, BigFunnelMaintainRefiners, CreationTime, MailboxNumber FROM Mailbox WHERE MailboxGuid = '$guid'"
$mailboxNum = $result.MailboxNumber

Write-Host ""
Write-Host "BigFunnelIsEnabled                       = " $result.p6781000B
Write-Host "FastIsEnabled                            = " $result.p330F000B
Write-Host "BigFunnelMailboxCreationVersion          = " $result.p33270003
Write-Host "BigFunnelDictionaryVersion               = " $result.p67820003
Write-Host "BigFunnelPostingListTableVersion         = " $result.p3D940003
Write-Host "BigFunnelPostingListTableChunkSize       = " $result.p3D950003
Write-Host "BigFunnelPostingListTargetTableVersion   = " $result.p3D900003
Write-Host "BigFunnelPostingListTargetTableChunkSize = " $result.p3D910003
Write-Host "BigFunnelMaintainRefiners                = " $result.p333E000B
Write-Host "CreationTime                             = " $result.p30070040
Write-Host "MailboxNumber                            = " $mailboxNum

if (-not $MyInvocation.BoundParameters.ContainsKey("DocumentId")) {
    # Get the folder ID specified by user if any
    [string]$folderId = [String]::Empty
    if (-not [String]::IsNullOrEmpty($FolderName)) {
        $folder = Get-StoreQuery -Server $dbStatus.MountedOnServer -ProcessId $dbStatus.WorkerProcessId -Unlimited -Query "select FolderId from Folder where MailboxNumber = $mailboxNum And DisplayName = '$FolderName'"
        $folderId = $folder.FolderId
    }

    Write-Host "FolderId           =  $folderId"
}

# Get properties from ExtendedPropertyNameMapping
$query = "SELECT PropName, PropNumber from ExtendedPropertyNameMapping where MailboxNumber = $mailboxNum and PropGuid = '0B63E350-9CCC-11D0-BCDB-00805FCCCE04' and (PropName = 'BigFunnelCorrelationId' or PropName = 'BigFunnelIndexingStart' or PropName = 'IndexingAttemptCount' or PropName = 'IndexingBatchRetryAttemptCount' or PropName = 'IndexingErrorCode' or PropName = 'IndexingErrorMessage' or PropName = 'ErrorProperties' or PropName = 'ErrorTags' or PropName = 'IsPartiallyIndexed' or PropName = 'IsPermanentFailure' or PropName = 'LastIndexingAttemptTime' or PropName = 'DetectedLanguage')"
$props = Get-StoreQuery -Server $dbStatus.MountedOnServer -ProcessId $dbStatus.WorkerProcessId -Query $query -Unlimited
$propsTable = @{}
for ($i = 0; $i -lt $props.Count; $i++) {
    $propsTable.Add($props.PropName[$i], $props.PropNumber[$i])
}

$bigFunnelCorrelationIdProperty = "p{0:x}0048" -f $propsTable.BigFunnelCorrelationId
$bigFunnelIndexingStartProperty = "p{0:x}0040" -f $propsTable.BigFunnelIndexingStart
$indexingAttemptCountProperty = "p{0:x}0003" -f $propsTable.IndexingAttemptCount
$indexingBatchRetryAttemptCountProperty = "p{0:x}0003" -f $propsTable.IndexingBatchRetryAttemptCount
$indexingErrorCodeProperty = "p{0:x}0003" -f $propsTable.IndexingErrorCode
$indexingErrorMessageProperty = "p{0:x}001F" -f $propsTable.IndexingErrorMessage
$errorPropertiesProperty = "p{0:x}101F" -f $propsTable.ErrorProperties
$errorTagsProperty = "p{0:x}101F" -f $propsTable.ErrorTags
$isPartiallyIndexedProperty = "p{0:x}000B" -f $propsTable.IsPartiallyIndexed
$isPermanentFailureProperty = "p{0:x}000B" -f $propsTable.IsPermanentFailure
$lastIndexingAttemptTimeProperty = "p{0:x}0040" -f $propsTable.LastIndexingAttemptTime
$detectedLanguageProperty = "p{0:x}0003" -f $propsTable.DetectedLanguage

$whereConstraint = "MailboxNumber = $mailboxNum"
if ($MyInvocation.BoundParameters.ContainsKey("DocumentId")) {
    # Find the item in question, using document id
    Write-Host ""
    Write-Host "Querying user mailbox using MessageDocumentId: $DocumentId" -ForegroundColor White

    $whereConstraint += " and MessageDocumentId = $DocumentId"
} else {
    # Find the item in question, using the exact match of the subject
    Write-Host ""

    if ($MatchSubjectSubstring) {
        Write-Host "Querying user mailbox using Subject substring: $ItemSubject" -ForegroundColor White
        $whereConstraint += " and Subject LIKE `"%$ItemSubject%`""
    } else {
        Write-Host "Querying user mailbox using exact Subject : $ItemSubject" -ForegroundColor White
        $whereConstraint += " and Subject = `"$ItemSubject`""
    }

    if (-not [String]::IsNullOrEmpty($folderId)) {
        $whereConstraint += " and FolderId='$folderId'"
    }
}

$query = "select FolderId, $bigFunnelIndexingStartProperty, $indexingAttemptCountProperty, $indexingBatchRetryAttemptCountProperty, $indexingErrorCodeProperty, $indexingErrorMessageProperty, $errorPropertiesProperty, $errorTagsProperty, $isPartiallyIndexedProperty, $isPermanentFailureProperty, $lastIndexingAttemptTimeProperty, MessageDocumentId, MessageClass, $detectedLanguageProperty, $bigFunnelCorrelationIdProperty, BigFunnelPOI, BigFunnelPOIIsUpToDate, BigFunnelPoiNotNeededReason, BigFunnelPOISize, BigFunnelPartialPOI, BigFunnelPOIContentFlags, BigFunnelMessageUncompressedPOIVersion, BigFunnelL1PropertyLengths1V1, BigFunnelL1PropertyLengths1V1Rebuild, BigFunnelL1PropertyLengths2V1, DateCreated, DateReceived from Message where $whereConstraint"
$messages = @(Get-StoreQuery -Server $dbStatus.MountedOnServer -ProcessId $dbStatus.WorkerProcessId -Unlimited -Query $query)

if ([string]::IsNullOrEmpty($messages.MessageDocumentId)) {
    if ($messages.DiagnosticQueryException.Count -gt 0) {
        Write-Host "Get-StoreQuery DiagnosticQueryException : $($messages.DiagnosticQueryException)" -ForegroundColor Yellow
    } elseif ($messages.DiagnosticQueryTranslatorException.Count -gt 0) {
        Write-Host "Get-StoreQuery DiagnosticQueryTranslatorException : $($messages.DiagnosticQueryTranslatorException)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "No item found." -ForegroundColor Yellow
    exit
}

if ($messages.Count -gt 0) {
    for ($i = 0; $i -lt $messages.Count; $i++) {
        Write-Host "Found item ($i + 1) :" -ForegroundColor Green
        Write-Host "FolderId                               = " $messages[$i].FolderId
        Write-Host "BigFunnelIndexingStart                 = " $messages[$i].$bigFunnelIndexingStartProperty
        Write-Host "IndexingAttemptCount                   = " $messages[$i].$indexingAttemptCountProperty
        Write-Host "IndexingBatchRetryAttemptCount         = " $messages[$i].$indexingBatchRetryAttemptCountProperty
        Write-Host "IndexingErrorCode                      = " $messages[$i].$indexingErrorCodeProperty
        Write-Host "IndexingErrorMessage                   = " $messages[$i].$indexingErrorMessageProperty
        Write-Host "ErrorProperties                        = " $messages[$i].$errorPropertiesProperty
        Write-Host "ErrorTags                              = " $messages[$i].$errorTagsProperty
        Write-Host "IsPartiallyIndexed                     = " $messages[$i].$isPartiallyIndexedProperty
        Write-Host "IsPermanentFailure                     = " $messages[$i].$isPermanentFailureProperty
        Write-Host "LastIndexingAttemptTime                = " $messages[$i].$lastIndexingAttemptTimeProperty
        Write-Host "MessageDocumentId                      = " $messages[$i].MessageDocumentId
        Write-Host "MessageClass                           = " $messages[$i].MessageClass
        Write-Host "DetectedLanguage                       = " $messages[$i].$detectedLanguageProperty
        Write-Host "BigFunnelCorrelationId                 = " $messages[$i].$bigFunnelCorrelationIdProperty
        Write-Host "BigFunnelPOI                           = " $messages[$i].BigFunnelPOI
        Write-Host "BigFunnelPOIIsUpToDate                 = " $messages[$i].p3655000B
        Write-Host "BigFunnelPoiNotNeededReason            = " $messages[$i].p365A0003
        Write-Host "BigFunnelPOISize                       = " $messages[$i].BigFunnelPOISize
        Write-Host "BigFunnelPartialPOI                    = " $messages[$i].BigFunnelPartialPOI
        Write-Host "BigFunnelPOIContentFlags               = " $messages[$i].p36630003
        Write-Host "BigFunnelMessageUncompressedPOIVersion = " $messages[$i].p36660003
        Write-Host "BigFunnelL1PropertyLengths1V1          = " $messages[$i].p3D920014
        Write-Host "BigFunnelL1PropertyLengths1V1Rebuild   = " $messages[$i].p3D8E0014
        Write-Host "BigFunnelL1PropertyLengths2V1          = " $messages[$i].p3D8D0014
        Write-Host "DateCreated                            = " $messages[$i].DateCreated
        Write-Host "DateReceived                           = " $messages[$i].DateReceived
    }
}

Write-Host ""
Write-Host "All done!" -ForegroundColor White