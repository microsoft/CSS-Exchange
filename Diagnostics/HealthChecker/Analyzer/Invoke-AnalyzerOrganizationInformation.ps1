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

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
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

    # Domain Trusts
    if ($null -ne $organizationInformation.TrustedDomain -and $organizationInformation.TrustedDomain.Count -gt 0) {
        $displayTrustObject = New-Object System.Collections.Generic.List[object]
        foreach ($trustDomain in $organizationInformation.TrustedDomain) {
            Write-Verbose "Working on creating display object for $($trustDomain.DistinguishedName)"
            $systemKey = ",CN=System,"
            $systemKeyIndex = $trustDomain.DistinguishedName.IndexOf($systemKey)
            if ($systemKeyIndex -ge 0) {
                $domainName = $trustDomain.DistinguishedName.Substring($systemKeyIndex).Replace($systemKey, "").Replace("DC=", "").Replace(",", ".")
            } else {
                Write-Verbose "Expected pattern '$systemKey' not found in DistinguishedName: $($trustDomain.DistinguishedName). Using full DistinguishedName as domain name."
                $domainName = $trustDomain.DistinguishedName
            }
            $displayTrustObject.Add([PSCustomObject]@{
                    DomainName      = $domainName
                    TrustPartner    = $trustDomain.TrustPartner
                    TrustAttributes = $trustDomain.TrustAttributes
                    EncryptionTypes = $trustDomain.SupportedEncryptionTypes
                })
        }
        $displayTrustObject = $displayTrustObject | Sort-Object DomainName

        $params = $baseParams + @{
            Name             = "Domain Trusts"
            AddHtmlDetailRow = $false
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            OutColumns = ([PSCustomObject]@{
                    DisplayObject = $displayTrustObject
                    IndentSpaces  = 12
                })
            HtmlName   = "Domain Trusts"
        }
        Add-AnalyzedResultInformation @params
    }

    # Legacy Exchange security groups (security best practice cleanup).
    # These groups were created by Exchange 2000/2003, are not used by modern Exchange, and still
    # carry elevated AD permissions. We surface them here (Organization Information) as a Yellow
    # best-practice warning - this is a configuration cleanup recommendation, not a vulnerability.
    $legacySecurityGroups = $organizationInformation.LegacySecurityGroups

    if ($null -ne $legacySecurityGroups -and $legacySecurityGroups.Count -gt 0) {
        Write-Verbose "Found $($legacySecurityGroups.Count) legacy Exchange security group(s) to review"

        $params = $baseParams + @{
            Name                = "Legacy Exchange Security Groups"
            Details             = $true
            DisplayWriteType    = "Yellow"
            DisplayTestingValue = $true
            AddHtmlDetailRow    = $false
        }
        Add-AnalyzedResultInformation @params

        $legacyGroupsDisplay = New-Object System.Collections.Generic.List[object]
        foreach ($legacyGroup in $legacySecurityGroups) {
            $legacyGroupsDisplay.Add([PSCustomObject]@{
                    DistinguishedName = $legacyGroup.DistinguishedName
                    Scope             = $legacyGroup.Scope
                    Members           = $legacyGroup.MemberCount
                })
        }

        # Legacy groups are always flagged Yellow. The Members cell is only highlighted when the
        # group actually has members; an empty Members count (0) is left at the default color.
        $legacyGroupsColorizer = {
            param ($o, $p)
            if ($p -eq "Members") {
                if ($o.$p -gt 0) {
                    "Yellow"
                }
            } else {
                "Yellow"
            }
        }

        $params = $baseParams + @{
            OutColumns           = ([PSCustomObject]@{
                    DisplayObject      = $legacyGroupsDisplay
                    ColorizerFunctions = @($legacyGroupsColorizer)
                    IndentSpaces       = 12
                })
            OutColumnsColorTests = @($legacyGroupsColorizer)
            HtmlName             = "Legacy Exchange Security Groups"
            TestingName          = "Legacy Exchange Security Groups Table"
        }
        Add-AnalyzedResultInformation @params

        $params = $baseParams + @{
            Details                = "These legacy Exchange security groups are not used by modern Exchange and carry elevated AD permissions. As a security best practice, review their membership and delete them if they are no longer required. More Information: https://aka.ms/HC-LegacyExchangeGroups"
            DisplayWriteType       = "Yellow"
            DisplayCustomTabNumber = 1
        }
        Add-AnalyzedResultInformation @params
    } else {
        Write-Verbose "No legacy Exchange security groups found."
    }

    Write-Verbose "Completed: $($MyInvocation.MyCommand) and took $($stopWatch.Elapsed.TotalSeconds) seconds"
}
