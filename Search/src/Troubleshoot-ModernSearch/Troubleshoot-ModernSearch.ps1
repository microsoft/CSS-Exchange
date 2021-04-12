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

    [Parameter(Mandatory = $true, ParameterSetName = "DocumentId")]
    [int]
    $DocumentId,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [switch]
    $MatchSubjectSubstring,

    [ValidateNotNullOrEmpty()]
    [string]
    $QueryString,

    [switch]
    $IsArchive,

    [switch]
    $IsPublicFolder
)

. $PSScriptRoot\Get-BasicMailboxQueryContext.ps1
. $PSScriptRoot\Get-BigFunnelPropertyNameMapping.ps1
. $PSScriptRoot\Get-FolderInformation.ps1
. $PSScriptRoot\Get-MailboxInformation.ps1
. $PSScriptRoot\Get-MessageIndexState.ps1
. $PSScriptRoot\Get-QueryItemResult.ps1
. $PSScriptRoot\Get-StoreQueryHandler.ps1

$Script:ScriptLogging = "$PSScriptRoot\Troubleshoot-ModernSearchLog_$(([DateTime]::Now).ToString('yyyyMMddhhmmss')).log"

Function Write-LogInformation {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [bool]$VerboseEnabled = $VerbosePreference
    )

    process {

        if ($VerboseEnabled) {
            $Object | Write-Verbose -Verbose
        }

        $Object | Out-File -FilePath $Script:ScriptLogging -Append
    }
}

Function Receive-Output {
    param(
        [Parameter(Position = 1, ValueFromPipeline = $true)]
        [object[]]$Object,
        [switch]$Diagnostic
    )

    process {

        if (($Diagnostic -and
                $VerbosePreference) -or
            -not ($Diagnostic)) {
            $Object | Write-Output
        } else {
            $Object | Write-Verbose
        }

        Write-LogInformation $Object -VerboseEnabled $false
    }
}

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

Function Write-DisplayObjectInformation {
    [CmdletBinding()]
    param(
        [object]$DisplayObject,
        [string[]]$PropertyToDisplay
    )
    process {
        $width = 0

        foreach ($property in $PropertyToDisplay) {

            if ($property.Length -gt $width) {
                $width = $property.Length + 1
            }
        }

        foreach ($property in $PropertyToDisplay) {
            Receive-Output ("{0,-$width} = {1}" -f $property, $DisplayObject.($property))
        }
    }
}

Function Main {
    Receive-Output ""
    Receive-Output "Getting user mailbox information for $MailboxIdentity"
    @("Identity: '$MailboxIdentity'",
        "ItemSubject: '$ItemSubject'",
        "FolderName: '$FolderName'",
        "DocumentId: '$DocumentId'",
        "MatchSubjectSubstring: '$MatchSubjectSubstring'",
        "QueryString: '$QueryString'",
        "IsArchive: '$IsArchive'",
        "IsPublicFolder: '$IsPublicFolder'") | Receive-Output -Diagnostic
    Receive-Output "" -Diagnostic

    $mailboxInformation = Get-MailboxInformation -Identity $MailboxIdentity -IsArchive $IsArchive -IsPublicFolder $IsPublicFolder

    Receive-Output ""
    Receive-Output "----------------------------------------"
    Receive-Output "Basic Mailbox Information:"
    Receive-Output "Mailbox GUID = $($mailboxInformation.MailboxGuid)"
    Receive-Output "Mailbox Database: $($mailboxInformation.Database)"
    Receive-Output "Active Server: $($mailboxInformation.PrimaryServer)"
    Receive-Output "Exchange Server Version: $($mailboxInformation.ExchangeServer.AdminDisplayVersion)"
    Receive-Output "----------------------------------------"
    Receive-Output ""
    Receive-Output "Big Funnel Count Information Based Off Get-MailboxStatistics"
    Write-DisplayObjectInformation -DisplayObject $mailboxInformation.MailboxStatistics -PropertyToDisplay @(
        "BigFunnelMessageCount",
        "BigFunnelIndexedCount",
        "BigFunnelPartiallyIndexedCount",
        "BigFunnelNotIndexedCount",
        "BigFunnelCorruptedCount",
        "BigFunnelStaleCount",
        "BigFunnelShouldNotBeIndexedCount"
    )
    Receive-Output "----------------------------------------"
    Receive-Output ""
    Receive-Output ($mailboxInformation.MailboxStatistics | Format-List) -Diagnostic
    Receive-Output "" -Diagnostic

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
    Receive-Output "----------------------------------------"

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

        Receive-Output "Found $($messages.Count) different messages"
        Receive-Output "Messages Index State:"

        for ($i = 0; $i -lt $messages.Count; $i++) {
            Receive-Output ""
            Receive-Output "Found Item $($i + 1): "
            Receive-Output $messages[$i]
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
                Receive-Output ""
            }
        }
    }
}

try {
    Out-File -FilePath $Script:ScriptLogging -Force | Out-Null
    Receive-Output "Starting Script At: $([DateTime]::Now)" -Diagnostic
    Main
    Receive-Output "Finished Script At: $([DateTime]::Now)" -Diagnostic
    Write-Output "File Written at: $Script:ScriptLogging"
} catch {
    Receive-Output "$($Error[0].Exception)"
    Receive-Output "$($Error[0].ScriptStackTrace)"
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}