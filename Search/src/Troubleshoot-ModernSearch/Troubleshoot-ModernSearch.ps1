#Exchange On Prem Script to help assist with determining why search might not be working on an Exchange 2019+ Server
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameter is used')]
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
    $MatchSubjectSubstring,

    [ValidateNotNullOrEmpty()]
    [string]
    $QueryString,

    [bool]
    $IsArchive,

    [bool]
    $IsPublicFolder
)

. $PSScriptRoot\Get-BasicUserQueryContext.ps1
. $PSScriptRoot\Get-BigFunnelPropertyNameMapping.ps1
. $PSScriptRoot\Get-FolderInformation.ps1
. $PSScriptRoot\Get-MessageIndexState.ps1
. $PSScriptRoot\Get-QueryItemResult.ps1
. $PSScriptRoot\Get-StoreQueryHandler.ps1
. $PSScriptRoot\Get-UserInformation.ps1

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
            Write-Output ("{0,-$width} = {1}" -f $property, $DisplayObject.($property))
        }
    }
}

Function Main {
    Write-Output "Getting user mailbox information for $UserEmail"
    $userInformation = Get-UserInformation -UserEmail $UserEmail -IsArchive $IsArchive -IsPublicFolder $IsPublicFolder

    Write-Output "Mailbox GUID = $($userInformation.MailboxGuid)"
    Write-Output "Mailbox Database: $($userInformation.Database)"
    Write-Output "Active Server: $($userInformation.PrimaryServer)"
    Write-Output "Exchange Server Version: $($userInformation.ExchangeServer.AdminDisplayVersion)"

    $storeQueryHandler = Get-StoreQueryHandler -UserInformation $userInformation
    $basicUserQueryContext = Get-BasicUserQueryContext -StoreQueryHandler $storeQueryHandler

    Write-DisplayObjectInformation -DisplayObject $basicUserQueryContext -PropertyToDisplay @(
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

    if (-not([string]::IsNullOrEmpty($FolderName))) {
        $folderInformation = Get-FolderInformation -BasicUserQueryContext $basicUserQueryContext -DisplayName $FolderName
    }

    $passParams = @{
        BasicUserQueryContext = $basicUserQueryContext
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

        for ($i = 0; $i -lt $messages.Count; $i++) {
            Write-Output "Found Item $($i + 1): "
            Write-Output $messages[$i]
            Write-Output ""
        }

        if (-not([string]::IsNullOrEmpty($QueryString))) {
            $queryItemResults = Get-QueryItemResult -BasicUserQueryContext $basicUserQueryContext -DocumentId ($messages.MessageDocumentId) -QueryString $QueryString -QueryScope "SearchAllIndexedProps"

            foreach ($item in $queryItemResults) {
                Write-DisplayObjectInformation -DisplayObject $item -PropertyToDisplay @(
                    "DocumentID",
                    "BigFunnelMatchFilter",
                    "BigFunnelMatchPOI"
                )
                Write-Output ""
            }
        }
    }
}

try {
    Main
} catch {
    Write-Output "$($Error[0].Exception)"
    Write-Output "$($Error[0].ScriptStackTrace)"
    Write-Warning ("Ran into an issue with the script. If possible please email 'ExToolsFeedback@microsoft.com' of the issue that you are facing")
}