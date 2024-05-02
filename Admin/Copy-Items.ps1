[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [string]
    $SourceFolderId,

    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [string]
    $TargetFolderId,

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [switch]
    $BatchMode,

    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [uint]
    $BatchSize = 500,

    [Parameter(Mandatory = $true, ParameterSetName = "CreateAzureApplication")]
    [switch]$CreateAzureApplication,

    [Parameter(Mandatory = $true, ParameterSetName = "DeleteAzureApplication")]
    [switch]$DeleteAzureApplication,

    [Parameter(Mandatory = $false, ParameterSetName = "CreateAzureApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "DeleteAzureApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "Default")]
    [string]$AzureApplicationName = "CSS-Exchange EWS Test",

    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [string]$ImpersonatedUserId,

    [Parameter(Mandatory = $true, ParameterSetName = "Default")]
    [string]$PublicFolderMailbox,

    [Parameter()]
    [ValidateSet("Global", "USGovernmentL4", "USGovernmentL5", "ChinaCloud")]
    [string]$AzureEnvironment = "Global",

    [Parameter(ParameterSetName = "Default")]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = "Default")]
    [string]$AppId,

    [Parameter(ParameterSetName = "Default")]
    [string]$Organization,

    [Parameter(ParameterSetName = "Default")]
    [ValidateScript({ Test-Path $_ })]
    [string]$DLLPath,

    [Parameter(ParameterSetName = "Default")]
    [ValidateRange(1, 2147483)]
    [int]$TimeoutSeconds = 900
)

. $PSScriptRoot\..\Shared\EmailFunctions\Connect-EWSExchangeOnline.ps1

$p = @{
    AzureEnvironment     = $AzureEnvironment
    AzureApplicationName = $AzureApplicationName
}

if (-not [string]::IsNullOrEmpty($DLLPath)) {
    $p.DLLPath = $DLLPath
}

if ($CreateAzureApplication) {
    $p.CreateAzureApplication = $true
    Connect-EWSExchangeOnline @p
    return
}

if ($DeleteAzureApplication) {
    $p.DeleteAzureApplication = $true
    Connect-EWSExchangeOnline @p
    return
}

$p.ImpersonatedUserId = $ImpersonatedUserId
$p.CertificateThumbprint = $CertificateThumbprint
$p.AppId = $AppId
$p.Organization = $Organization
$p.TimeoutSeconds = $TimeoutSeconds

$serviceInfo = Connect-EWSExchangeOnline @p
$serviceInfo.ExchangeService.HttpHeaders.Add("X-AnchorMailbox", $ImpersonatedUserId)
if (-not [string]::IsNullOrEmpty($PublicFolderMailbox)) {
    $serviceInfo.ExchangeService.HttpHeaders.Add("X-PublicFolderMailbox", $PublicFolderMailbox)
}

$sourceFolderEWSId = New-Object Microsoft.Exchange.WebServices.Data.FolderId($SourceFolderId)
$targetFolderEWSId = New-Object Microsoft.Exchange.WebServices.Data.FolderId($TargetFolderId)
$offset = 0
$pageSize = 1000
$findItemsResults = $null
$itemIds = New-Object 'System.Collections.Generic.List[Microsoft.Exchange.WebServices.Data.ItemId]'
do {
    $itemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView($pageSize, $offset)
    $findItemsResults = $serviceInfo.ExchangeService.FindItems($sourceFolderEWSId, $itemView)
    foreach ($item in $findItemsResults.Items) {
        $itemIds.Add($item.Id)
    }

    $offset = $findItemsResults.NextPageOffset
} while ($findItemsResults.MoreAvailable)

if ($itemIds.Count -lt 1) {
    Write-Host "No items found in source folder."
    return
}

Write-Host "$(Get-Date) Found $($itemIds.Count) items."
$sw = New-Object System.Diagnostics.Stopwatch
$sw.Start()

if ($BatchMode) {
    for ($i = 0; $i -lt $itemIds.Count; $i += $BatchSize) {
        $count = $BatchSize
        if ($i + $count -ge $itemIds.Count) {
            $count = $itemIds.Count - $i
        }

        Write-Host "$(Get-Date) Copying $count items..."
        $thisBatch = $itemIds.GetRange($i, $count)
        [void]$serviceInfo.ExchangeService.CopyItems($thisBatch, $targetFolderEWSId)
    }
} else {
    foreach ($itemId in $itemIds) {
        [Microsoft.Exchange.WebServices.Data.ItemId[]]$itemCollection = @($itemId)
        [void]$serviceInfo.ExchangeService.CopyItems($itemCollection, $targetFolderEWSId)
    }
}

$sw.Stop()
Write-Host "$(Get-Date) Done. Elapsed time: $($sw)"
