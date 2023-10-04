# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-AnalyzedResultInformation.ps1
. $PSScriptRoot\Get-DisplayResultsGroupingKey.ps1

function Invoke-AnalyzerOrganizationInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ref]$AnalyzeResults,

        [Parameter(Mandatory = $true)]
        [object]$HealthServerObject,

        [Parameter(Mandatory = $true)]
        [int]$Order
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $organizationInformation = $HealthServerObject.OrganizationInformation

    $baseParams = @{
        AnalyzedInformation = $AnalyzeResults
        DisplayGroupingKey  = (Get-DisplayResultsGroupingKey -Name "Organization Information"  -DisplayOrder $Order)
    }

    $params = $baseParams + @{
        Name    = "MAPI/HTTP Enabled"
        Details = $organizationInformation.MapiHttpEnabled
    }
    Add-AnalyzedResultInformation @params

    $params = $baseParams + @{
        Name    = "Enable Download Domains"
        Details = $organizationInformation.EnableDownloadDomains
    }
    Add-AnalyzedResultInformation @params

    if ($null -ne $organizationInformation.GetOrganizationConfig -and
        $organizationInformation.EnableDownloadDomains.ToString() -eq "Unknown") {
        $params = $baseParams + @{
            Details                = "This is 'Unknown' because EMS is connected to an Exchange Version that doesn't know about Enable Download Domains in Get-OrganizationConfig"
            DisplayCustomTabNumber = 2
            DisplayWriteType       = "Yellow"
        }
        Add-AnalyzedResultInformation @params
    }

    $params = $baseParams + @{
        Name    = "AD Split Permissions"
        Details = $organizationInformation.IsSplitADPermissions
    }
    Add-AnalyzedResultInformation @params

    $displayWriteType = "Green"

    if ($organizationInformation.ADSiteCount -ge 750) {
        $displayWriteType = "Yellow"
    } elseif ( $organizationInformation.ADSiteCount -ge 1000) {
        $displayWriteType = "Red"
    }

    $params = $baseParams + @{
        Name             = "Total AD Site Count"
        Details          = $organizationInformation.ADSiteCount
        DisplayWriteType = $displayWriteType
    }
    Add-AnalyzedResultInformation @params

    if ($displayWriteType -ne "Green") {
        $params = $baseParams + @{
            Details                = "More Information: https://aka.ms/HC-ADSiteCount"
            DisplayCustomTabNumber = 2
            DisplayWriteType       = $displayWriteType
        }
        Add-AnalyzedResultInformation @params
    }

    if ($null -ne $organizationInformation.GetDynamicDgPublicFolderMailboxes -and
        $organizationInformation.GetDynamicDgPublicFolderMailboxes.Count -ne 0) {
        $displayWriteType = "Green"

        if ($organizationInformation.GetDynamicDgPublicFolderMailboxes.Count -gt 1) {
            $displayWriteType = "Red"
        }

        $params = $baseParams + @{
            Name             = "Dynamic Distribution Group Public Folder Mailboxes Count"
            Details          = $organizationInformation.GetDynamicDgPublicFolderMailboxes.Count
            DisplayWriteType = $displayWriteType
        }

        Add-AnalyzedResultInformation @params

        if ($displayWriteType -ne "Green") {
            $params = $baseParams + @{
                Details                = "More Information: https://aka.ms/HC-DynamicDgPublicFolderMailboxes"
                DisplayCustomTabNumber = 2
                DisplayWriteType       = "Yellow"
            }

            Add-AnalyzedResultInformation @params
        }
    } else {
        Write-Verbose "No Dynamic Distribution Group Public Folder Mailboxes found to review."
    }
}
