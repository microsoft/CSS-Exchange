# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are being used in functions')]
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [String] $tdEXOOrgRelDomainNamesColor
)
function ExoOrgRelCheck () {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-OrganizationRelationship  | Where{($_.DomainNames -like $ExchangeOnPremDomain )} | Select Identity,DomainNames,FreeBusy*,TarGet*,Enabled"
    PrintDynamicWidthLine
    $ExoOrgRel
    PrintDynamicWidthLine
    Write-Host  -ForegroundColor Green " Summary - Organization Relationship"
    PrintDynamicWidthLine
    Write-Host  " Domain Names:"
    if ($exoOrgRel.DomainNames -like $ExchangeOnPremDomain) {
        Write-Host -ForegroundColor Green "  Domain Names Include the $ExchangeOnPremDomain Domain"
        $tdEXOOrgRelDomainNames = $exoOrgRel.DomainNames
        $tdEXOOrgRelDomainNamesColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Domain Names do Not Include the $ExchangeOnPremDomain Domain"
        $exoOrgRel.DomainNames
        $tdEXOOrgRelDomainNames = "$($exoOrgRel.DomainNames) - Domain Names do Not Include the $ExchangeOnPremDomain Domain"
        $tdEXOOrgRelDomainNamesColor = "green"
    }
    #FreeBusyAccessEnabled
    Write-Host  " FreeBusyAccessEnabled:"
    if ($exoOrgRel.FreeBusyAccessEnabled -like "True" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessEnabled is set to True"
        $tdEXOOrgRelFreeBusyAccessEnabled = "$($exoOrgRel.FreeBusyAccessEnabled)"
        $tdEXOOrgRelFreeBusyAccessEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  FreeBusyAccessEnabled : False"
        $tdEXOOrgRelFreeBusyAccessEnabled = "$($exoOrgRel.FreeBusyAccessEnabled). Free busy access is not enabled for the organization Relationship"
        $tdEXOOrgRelFreeBusyAccessEnabledColor = "Red"
    }
    #FreeBusyAccessLevel
    Write-Host  " FreeBusyAccessLevel:"
    if ($exoOrgRel.FreeBusyAccessLevel -like "AvailabilityOnly" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessLevel is set to AvailabilityOnly"
        $tdEXOOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $tdEXOOrgRelFreeBusyAccessLevelColor = "green"
    }
    if ($exoOrgRel.FreeBusyAccessLevel -like "LimitedDetails" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessLevel is set to LimitedDetails"
        $tdEXOOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $tdEXOOrgRelFreeBusyAccessLevelColor = "green"
    }
    if ($exoOrgRel.FreeBusyAccessLevel -NE "AvailabilityOnly" -AND $exoOrgRel.FreeBusyAccessLevel -NE "LimitedDetails") {
        Write-Host -ForegroundColor Red "  FreeBusyAccessEnabled : False"
        $tdEXOOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $tdEXOOrgRelFreeBusyAccessLevelColor = "red"
    }
    #TarGetApplicationUri
    Write-Host  " TarGetApplicationUri:"
    $a = "FYDIBOHF25SPDLT." + $ExchangeOnPremDomain
    $HybridAgentTargetSharingEpr = "http://outlook.office.com/"
    $HATargetAutodiscoverEpr = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc/"
    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MSAppProxy.net/EWS/Exchange.asmx") {
        if ($exoOrgRel.TarGetApplicationUri -like $HybridAgentTargetSharingEpr) {
            Write-Host -ForegroundColor Green "  TarGetApplicationUri is $($exoOrgRel.TarGetSharingEpr) . This is correct when Hybrid Agent is in use"
            $tdEXOOrgRelTarGetApplicationUri = "  TarGetApplicationUri is $($exoOrgRel.TarGetSharingEpr) . This is correct when Hybrid Agent is in use"
            $tdEXOOrgRelTarGetApplicationUriColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetApplicationUri should be  $HybridAgentTargetSharingEpr when Hybrid Agent is used"
            $tdEXOOrgRelTarGetApplicationUri = "  TarGetApplicationUri should be $HybridAgentTargetSharingEpr when Hybrid Agent is used. Please Check if Exchange On Premise Federation is correctly configured."
            $tdEXOOrgRelTarGetApplicationUriColor = "red"
        }
    } else {
        if ($exoOrgRel.TarGetApplicationUri -like $FedTrust.ApplicationUri) {
            Write-Host -ForegroundColor Green "  TarGetApplicationUri is" $FedTrust.ApplicationUri.OriginalString
            $tdEXOOrgRelTarGetApplicationUri = "  TarGetApplicationUri is $($FedTrust.ApplicationUri.OriginalString)"
            $tdEXOOrgRelTarGetApplicationUriColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetApplicationUri should be " $a
            $tdEXOOrgRelTarGetApplicationUri = "  TarGetApplicationUri should be $a. Please Check if Exchange On Premise Federation is correctly configured."
            $tdEXOOrgRelTarGetApplicationUriColor = "red"
        }
    }
    #TarGetSharingEpr
    Write-Host  " TarGetSharingEpr:"
    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx") {
        Write-Host -ForegroundColor Green "  TarGetSharingEpr is points to resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx. This means Hybrid Agent is in use."
        $tdEXOOrgRelTarGetSharingEpr = "TarGetSharingEpr is points to resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx. This means Hybrid Agent is in use."
        $tdEXOOrgRelTarGetSharingEprColor = "green"
    } else {
        if ([string]::IsNullOrWhitespace($exoOrgRel.TarGetSharingEpr)) {
            Write-Host -ForegroundColor Green "  TarGetSharingEpr is blank. This is the standard Value."
            $tdEXOOrgRelTarGetSharingEpr = "TarGetSharingEpr is blank. This is the standard Value."
            $tdEXOOrgRelTarGetSharingEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetSharingEpr should be blank. If it is set, it should be the On-Premises Exchange Servers EWS ExternalUrl endpoint."
            $tdEXOOrgRelTarGetSharingEpr = "  TarGetSharingEpr should be blank. If it is set, it should be the On-Premises Exchange Servers EWS ExternalUrl endpoint."
            $tdEXOOrgRelTarGetSharingEprColor = "red"
        }
    }
    Write-Host  " TarGetAutoDiscoverEpr:"
    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MSAppProxy.net/EWS/Exchange.asmx") {

        if ($exoOrgRel.TarGetAutoDiscoverEpr -like $HATargetAutodiscoverEpr) {
            Write-Host -ForegroundColor Green "  TarGetAutoDiscoverEpr is $($exoOrgRel.TarGetAutoDiscoverEpr) . This is correct when Hybrid Agent is in use"

            $tdEXOOrgRelTarGetAutoDiscoverEpr = "TarGetAutoDiscoverEpr is $($exoOrgRel.TarGetAutoDiscoverEpr) . This is correct when Hybrid Agent is in use"
            $tdEXOOrgRelTarGetAutoDiscoverEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetAutoDiscoverEpr is not $HATargetAutodiscoverEpr . This is the correct  value when Hybrid Agent is in use."
            $tdEXOOrgRelTarGetAutoDiscoverEpr = "  TarGetAutoDiscoverEpr is not $HATargetAutodiscoverEpr. This is the correct  value when Hybrid Agent is in use."
            $tdEXOOrgRelTarGetAutoDiscoverEprColor = "red"
        }
    }

    else {

        if ($exoOrgRel.TarGetAutoDiscoverEpr -like $FedInfoEOP.TarGetAutoDiscoverEpr) {
            Write-Host -ForegroundColor Green "  TarGetAutoDiscoverEpr is" $exoOrgRel.TarGetAutoDiscoverEpr
            $tdEXOOrgRelTarGetAutoDiscoverEpr = $exoOrgRel.TarGetAutoDiscoverEpr
            $tdEXOOrgRelTarGetAutoDiscoverEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetAutoDiscoverEpr is not" $FedInfoEOP.TarGetAutoDiscoverEpr
            $tdEXOOrgRelTarGetAutoDiscoverEpr = "  TarGetAutoDiscoverEpr is not $($FedInfoEOP.TarGetAutoDiscoverEpr)"
            $tdEXOOrgRelTarGetAutoDiscoverEprColor = "red"
        }
    }
    #Enabled
    Write-Host  " Enabled:"
    if ($exoOrgRel.enabled -like "True" ) {
        Write-Host -ForegroundColor Green "  Enabled is set to True"
        $tdEXOOrgRelEnabled = "  True"
        $tdEXOOrgRelEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Enabled is set to False."
        $tdEXOOrgRelEnabled = "  False"
        $tdEXOOrgRelEnabledColor = "red"
    }
    ExoOrgRelCheckhtml
}
function EXOFedOrgIdCheck {
    Write-Host -ForegroundColor Green " Get-FederatedOrganizationIdentifier | select AccountNameSpace,Domains,Enabled"
    PrintDynamicWidthLine
    $exoFedOrgId = Get-FederatedOrganizationIdentifier | Select-Object AccountNameSpace, Domains, Enabled
    $eFedOrgID = $exoFedOrgId | Format-List
    $eFedOrgID
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Online Federated Organization Identifier"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " Domains: "
    if ($exoFedOrgId.Domains -like "*$ExchangeOnlineDomain*") {
        Write-Host -ForegroundColor Green " " $exoFedOrgId.Domains
        $tdEXOFedOrgIdDomains = $exoFedOrgId.Domains
        $tdEXOFedOrgIdDomainsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " Domains are NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnlineMDomain"
        $tdEXOFedOrgIdDomains = "$($exoFedOrgId.Domains) . Domains Should contain the $ExchangeOnlineMDomain"
        $tdEXOFedOrgIdDomainsColor = "red"
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($exoFedOrgId.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $tdEXOFedOrgIdEnabled = $exoFedOrgId.Enabled
        $tdEXOFedOrgIdEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Enabled is NOT correct."
        Write-Host -ForegroundColor White " Should be True"
        $tdEXOFedOrgIdEnabled = $exoFedOrgId.Enabled
        $tdEXOFedOrgIdEnabledColor = "green"
    }
    EXOFedOrgIdCheckHtml
}
function SharingPolicyCheck {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-SharingPolicy | select Domains,Enabled,Name,Identity"
    PrintDynamicWidthLine
    $Script:SPOnline = Get-SharingPolicy | Select-Object  Domains, Enabled, Name, Identity
    $SPOnline | Format-List
    $domain1 = (($SPOnline.domains[0] -split ":") -split " ")
    $domain2 = (($SPOnline.domains[1] -split ":") -split " ")
    $SPOnpremDomain1 = $SPOnprem.Domains.Domain[0]
    $SPOnpremAction1 = $SPOnprem.Domains.Actions[0]
    $SPOnpremDomain2 = $SPOnprem.Domains.Domain[1]
    $SPOnpremAction2 = $SPOnprem.Domains.Actions[1]
    $SPOnlineDomain1 = $domain1[0]
    $SPOnlineAction1 = $domain1[1]
    $SPOnlineDomain2 = $domain2[0]
    $SPOnlineAction2 = $domain2[1]
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Sharing Policy"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " Exchange On Premises Sharing domains:`n"
    Write-Host -ForegroundColor White "  Domain:"
    Write-Host "   " $SPOnpremDomain1
    Write-Host -ForegroundColor White "  Action:"
    Write-Host "   " $SPOnpremAction1
    Write-Host -ForegroundColor White "  Domain:"
    Write-Host "   " $SPOnpremDomain2
    Write-Host -ForegroundColor White "  Action:"
    Write-Host "   " $SPOnpremAction2
    Write-Host -ForegroundColor White "`n  Exchange Online Sharing Domains: `n"
    Write-Host -ForegroundColor White "  Domain:"
    Write-Host "   " $SPOnlineDomain1
    Write-Host -ForegroundColor White "  Action:"
    Write-Host "   " $SPOnlineAction1
    Write-Host -ForegroundColor White "  Domain:"
    Write-Host "   " $SPOnlineDomain2
    Write-Host -ForegroundColor White "  Action:"
    Write-Host "   " $SPOnlineAction2
    #PrintDynamicWidthLine

    if ($SPOnpremDomain1 -eq $SPOnlineDomain1 -and $SPOnpremAction1 -eq $SPOnlineAction1) {
        if ($SPOnpremDomain2 -eq $SPOnlineDomain2 -and $SPOnpremAction2 -eq $SPOnlineAction2) {
            Write-Host -ForegroundColor Green "`n  Exchange Online Sharing Policy Domains match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy matches Exchange On Premise Sharing Policy Domain"
            $tdSharpingPolicyCheckColor = "green"
        }

        else {
            Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
            Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheckColor = "red"
        }
    } elseif ($SPOnpremDomain1 -eq $SPOnlineDomain2 -and $SPOnpremAction1 -eq $SPOnlineAction2) {
        if ($SPOnpremDomain2 -eq $SPOnlineDomain1 -and $SPOnpremAction2 -eq $SPOnlineAction1) {
            Write-Host -ForegroundColor Green "`n  Exchange Online Sharing Policy Domains match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy matches Exchange On Premise Sharing Policy Domain"
            $tdSharpingPolicyCheckColor = "green"
        }

        else {
            Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
            Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
            $tdSharpingPolicyCheckColor = "red"
        }
    } else {
        Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
        Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
        $tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
        $tdSharpingPolicyCheckColor = "red"
    }
    PrintDynamicWidthLine
    SharingPolicyCheckHtml
}
function ExoTestOrgRelCheck {
    $exoIdentity = $ExoOrgRel.Identity
    $exoOrgRelTarGetApplicationUri = $exoOrgRel.TarGetApplicationUri
    $exoOrgRelTarGetOWAUrl = $ExoOrgRel.TarGetOwAUrl
    Write-Host -ForegroundColor Green " Test-OrganizationRelationship -Identity $exoIdentity -UserIdentity $UserOnline"
    PrintDynamicWidthLine
    if ((![string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) -and (![string]::IsNullOrWhitespace($exoOrgRelTarGetOWAUrl))) {
        $ExoTestOrgRel = Test-OrganizationRelationship -Identity $exoIdentity -UserIdentity $UserOnline -WarningAction SilentlyContinue
        $i = 2
        while ($i -lt $ExoTestOrgRel.Length) {
            $element = $ExoTestOrgRel[$i]
            $aux = "0"
            if ($element -like "*RESULT:*" -and $aux -like "0") {
                $el = $element.TrimStart()
                if ($element -like "*Success.*") {
                    Write-Host -ForegroundColor Green "  $el"
                    $aux = "1"
                } elseif ($element -like "*Error*" -or $element -like "*Unable*") {
                    Write-Host -ForegroundColor Red "  $el"
                    $aux = "1"
                }
            } elseif ($aux -like "0" ) {
                if ($element -like "*STEP*" -or $element -like "*Complete*") {
                    Write-Host -ForegroundColor White "  $element"
                    $aux = "1"
                } else {
                    $ID = $element.ID
                    $Status = $element.Status
                    $Description = $element.Description
                    if (![string]::IsNullOrWhitespace($ID)) {
                        Write-Host -ForegroundColor White "`n  ID         : $ID"
                        if ($Status -like "*Success*") {
                            Write-Host -ForegroundColor White "  Status     : $Status"
                        }
                        if ($status -like "*error*") {
                            Write-Host -ForegroundColor White "  Status     : $Status"
                        }
                        Write-Host -ForegroundColor White "  Description: $Description"
                        Write-Host -ForegroundColor yellow "  Note: Test-Organization Relationship fails on Step 3 with error MismatchedFederation if Hybrid Agent is in use"
                    }
                    #$element
                    $aux = "1"
                }
            }
            $i++
        }
    }

    elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) -and ([string]::IsNullOrWhitespace($exoOrgRelTarGetOWAUrl)))) {
        Write-Host -ForegroundColor Red "  Error: Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri and TarGetOwAUrl are not set"
    } elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) )) {
        Write-Host -ForegroundColor Red "  Error: Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetApplicationUri is not set"
    } elseif ((([string]::IsNullOrWhitespace($exoOrgRelTarGetApplicationUri)) )) {
        Write-Host -ForegroundColor Red "  Error: Exchange Online Test-OrganizationRelationship cannot be run if the Organization Relationship TarGetOwAUrl is not set"
    }
    ExoTestOrgRelCheckhtml
}

