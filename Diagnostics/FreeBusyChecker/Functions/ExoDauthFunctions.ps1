# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function ExoOrgRelCheck () {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-EOOrganizationRelationship  | Where{($_.DomainNames -like $ExchangeOnPremDomain )} | Select Identity,DomainNames,FreeBusy*,TarGet*,Enabled"
    PrintDynamicWidthLine
    $ExoOrgRel
    PrintDynamicWidthLine
    Write-Host  -ForegroundColor Green " Summary - Organization Relationship"
    PrintDynamicWidthLine
    Write-Host  " Domain Names:"
    if ($exoOrgRel.DomainNames -like $ExchangeOnPremDomain) {
        Write-Host -ForegroundColor Green "  Domain Names Include the $ExchangeOnPremDomain Domain"
        $Script:tdExoOrgRelDomainNames = $exoOrgRel.DomainNames
        $Script:tdExoOrgRelDomainNamesColor = "green"
        if ($Script:tdExoOrgRelDomainNamesData -or $Script:tdExoOrgRelDomainNamesColor) {
        }
    } else {
        Write-Host -ForegroundColor Red "  Domain Names do Not Include the $ExchangeOnPremDomain Domain"
        $exoOrgRel.DomainNames
        $Script:tdExoOrgRelDomainNames = "$($exoOrgRel.DomainNames) - Domain Names do Not Include the $ExchangeOnPremDomain Domain"
        $Script:tdExoOrgRelDomainNamesColor = "green"
    }
    #FreeBusyAccessEnabled
    Write-Host  " FreeBusyAccessEnabled:"
    if ($exoOrgRel.FreeBusyAccessEnabled -like "True" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessEnabled is set to True"
        $Script:tdExoOrgRelFreeBusyAccessEnabled = "$($exoOrgRel.FreeBusyAccessEnabled)"
        $Script:tdExoOrgRelFreeBusyAccessEnabledColor = "green"
        if ($Script:tdExoOrgRelFreeBusyAccessEnabled -or $Script:tdExoOrgRelFreeBusyAccessEnabledColor) {
        }
    } else {
        Write-Host -ForegroundColor Red "  FreeBusyAccessEnabled : False"
        $Script:tdExoOrgRelFreeBusyAccessEnabled = "$($exoOrgRel.FreeBusyAccessEnabled). Free busy access is not enabled for the organization Relationship"
        $Script:tdExoOrgRelFreeBusyAccessEnabledColor = "Red"
    }
    #FreeBusyAccessLevel
    Write-Host  " FreeBusyAccessLevel:"
    if ($exoOrgRel.FreeBusyAccessLevel -like "AvailabilityOnly" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessLevel is set to AvailabilityOnly"
        $Script:tdExoOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $Script:tdExoOrgRelFreeBusyAccessLevelColor = "green"
    }
    if ($exoOrgRel.FreeBusyAccessLevel -like "LimitedDetails" ) {
        Write-Host -ForegroundColor Green "  FreeBusyAccessLevel is set to LimitedDetails"
        $Script:tdExoOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $Script:tdExoOrgRelFreeBusyAccessLevelColor = "green"
    }
    if ($exoOrgRel.FreeBusyAccessLevel -NE "AvailabilityOnly" -AND $exoOrgRel.FreeBusyAccessLevel -NE "LimitedDetails") {
        Write-Host -ForegroundColor Red "  FreeBusyAccessEnabled : False"
        $Script:tdExoOrgRelFreeBusyAccessLevel = "$($exoOrgRel.FreeBusyAccessLevel)"
        $Script:tdExoOrgRelFreeBusyAccessLevelColor = "red"
    }
    #TarGetApplicationUri
    Write-Host  " TarGetApplicationUri:"
    $a = "FYDIBOHF25SPDLT." + $ExchangeOnPremDomain
    $HybridAgentTargetSharingEpr = "http://outlook.office.com/"
    $HATargetAutodiscoverEpr = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc/"
    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MSAppProxy.net/EWS/Exchange.asmx") {
        if ($exoOrgRel.TarGetApplicationUri -like $HybridAgentTargetSharingEpr) {
            Write-Host -ForegroundColor Green "  TarGetApplicationUri is $($exoOrgRel.TarGetSharingEpr) . This is correct when Hybrid Agent is in use"
            $Script:tdExoOrgRelTarGetApplicationUri = "  TarGetApplicationUri is $($exoOrgRel.TarGetSharingEpr) . This is correct when Hybrid Agent is in use"
            $Script:tdExoOrgRelTarGetApplicationUriColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetApplicationUri should be  $HybridAgentTargetSharingEpr when Hybrid Agent is used"
            $Script:tdExoOrgRelTarGetApplicationUri = "  TarGetApplicationUri should be $HybridAgentTargetSharingEpr when Hybrid Agent is used. Please Check if Exchange On Premise Federation is correctly configured."
            $Script:tdExoOrgRelTarGetApplicationUriColor = "red"
        }
    } else {
        if ($exoOrgRel.TarGetApplicationUri -like $FedTrust.ApplicationUri) {
            Write-Host -ForegroundColor Green "  TarGetApplicationUri is" $FedTrust.ApplicationUri.OriginalString
            $Script:tdExoOrgRelTarGetApplicationUri = "  TarGetApplicationUri is $($FedTrust.ApplicationUri.OriginalString)"
            $Script:tdExoOrgRelTarGetApplicationUriColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetApplicationUri should be " $a
            $Script:tdExoOrgRelTarGetApplicationUri = "  TarGetApplicationUri should be $a. Please Check if Exchange On Premise Federation is correctly configured."
            $Script:tdExoOrgRelTarGetApplicationUriColor = "red"
        }
    }
    #TarGetSharingEpr
    Write-Host  " TarGetSharingEpr:"
    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx") {
        Write-Host -ForegroundColor Green "  TarGetSharingEpr is points to resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx. This means Hybrid Agent is in use."
        $Script:tdExoOrgRelTarGetSharingEpr = "TarGetSharingEpr is points to resource.mailboxMigration.his.MsAppProxy.net/EWS/Exchange.asmx. This means Hybrid Agent is in use."
        $Script:tdExoOrgRelTarGetSharingEprColor = "green"
    } else {
        if ([string]::IsNullOrWhitespace($exoOrgRel.TarGetSharingEpr)) {
            Write-Host -ForegroundColor Green "  TarGetSharingEpr is blank. This is the standard Value."
            $Script:tdExoOrgRelTarGetSharingEpr = "TarGetSharingEpr is blank. This is the standard Value."
            $Script:tdExoOrgRelTarGetSharingEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetSharingEpr should be blank. If it is set, it should be the On-Premises Exchange Servers EWS ExternalUrl endpoint."
            $Script:tdExoOrgRelTarGetSharingEpr = "  TarGetSharingEpr should be blank. If it is set, it should be the On-Premises Exchange Servers EWS ExternalUrl endpoint."
            $Script:tdExoOrgRelTarGetSharingEprColor = "red"
        }
    }
    Write-Host  " TarGetAutoDiscoverEpr:"
    if ($exoOrgRel.TarGetSharingEpr -like "*resource.mailboxMigration.his.MSAppProxy.net/EWS/Exchange.asmx") {

        if ($exoOrgRel.TarGetAutoDiscoverEpr -like $HATargetAutodiscoverEpr) {
            Write-Host -ForegroundColor Green "  TarGetAutoDiscoverEpr is $($exoOrgRel.TarGetAutoDiscoverEpr) . This is correct when Hybrid Agent is in use"

            $Script:tdExoOrgRelTarGetAutoDiscoverEpr = "TarGetAutoDiscoverEpr is $($exoOrgRel.TarGetAutoDiscoverEpr) . This is correct when Hybrid Agent is in use"
            $Script:tdExoOrgRelTarGetAutoDiscoverEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetAutoDiscoverEpr is not $HATargetAutodiscoverEpr . This is the correct  value when Hybrid Agent is in use."
            $Script:tdExoOrgRelTarGetAutoDiscoverEpr = "  TarGetAutoDiscoverEpr is not $HATargetAutodiscoverEpr. This is the correct  value when Hybrid Agent is in use."
            $Script:tdExoOrgRelTarGetAutoDiscoverEprColor = "red"
        }
    }

    else {

        if ($exoOrgRel.TarGetAutoDiscoverEpr -like $FedInfoEOP.TarGetAutoDiscoverEpr) {
            Write-Host -ForegroundColor Green "  TarGetAutoDiscoverEpr is" $exoOrgRel.TarGetAutoDiscoverEpr
            $Script:tdExoOrgRelTarGetAutoDiscoverEpr = $exoOrgRel.TarGetAutoDiscoverEpr
            $Script:tdExoOrgRelTarGetAutoDiscoverEprColor = "green"
        } else {
            Write-Host -ForegroundColor Red "  TarGetAutoDiscoverEpr is not" $FedInfoEOP.TarGetAutoDiscoverEpr
            $Script:tdExoOrgRelTarGetAutoDiscoverEpr = "  TarGetAutoDiscoverEpr is not $($FedInfoEOP.TarGetAutoDiscoverEpr)"
            $Script:tdExoOrgRelTarGetAutoDiscoverEprColor = "red"
        }
    }
    #Enabled
    Write-Host  " Enabled:"
    if ($exoOrgRel.enabled -like "True" ) {
        Write-Host -ForegroundColor Green "  Enabled is set to True"
        $Script:tdExoOrgRelEnabled = "  True"
        $Script:tdExoOrgRelEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Enabled is set to False."
        $Script:tdExoOrgRelEnabled = "  False"
        $Script:tdExoOrgRelEnabledColor = "red"
    }
    ExoOrgRelCheckHtml
}
function ExoFedOrgIdCheck {
    Write-Host -ForegroundColor Green " Get-FederatedOrganizationIdentifier | select AccountNameSpace,Domains,Enabled"
    PrintDynamicWidthLine
    $ExoFedOrgId = Get-EOFederatedOrganizationIdentifier | Select-Object AccountNameSpace, Domains, Enabled
    $eFedOrgID = $ExoFedOrgId | Format-List
    $eFedOrgID
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Summary - Online Federated Organization Identifier"
    PrintDynamicWidthLine
    Write-Host -ForegroundColor White " Domains: "
    if ($ExoFedOrgId.Domains -like "*$ExchangeOnlineDomain*") {
        Write-Host -ForegroundColor Green " " $ExoFedOrgId.Domains
        $Script:tdExoFedOrgIdDomains = $ExoFedOrgId.Domains
        $Script:tdExoFedOrgIdDomainsColor = "green"
    } else {
        Write-Host -ForegroundColor Red " Domains are NOT correct."
        Write-Host -ForegroundColor White " Should contain the $ExchangeOnlineMDomain"
        $Script:tdExoFedOrgIdDomains = "$($ExoFedOrgId.Domains) . Domains Should contain the $ExchangeOnlineMDomain"
        $Script:tdExoFedOrgIdDomainsColor = "red"
    }
    Write-Host -ForegroundColor White " Enabled: "
    if ($ExoFedOrgId.Enabled -like "True") {
        Write-Host -ForegroundColor Green "  True "
        $Script:tdExoFedOrgIdEnabled = $ExoFedOrgId.Enabled
        $Script:tdExoFedOrgIdEnabledColor = "green"
    } else {
        Write-Host -ForegroundColor Red "  Enabled is NOT correct."
        Write-Host -ForegroundColor White " Should be True"
        $Script:tdExoFedOrgIdEnabled = $ExoFedOrgId.Enabled
        $Script:tdExoFedOrgIdEnabledColor = "green"
    }
    ExoFedOrgIdCheckHtml
}
function SharingPolicyCheck {
    PrintDynamicWidthLine
    Write-Host -ForegroundColor Green " Get-SharingPolicy | select Domains,Enabled,Name,Identity"
    PrintDynamicWidthLine
    $Script:SPOnline = Get-EOSharingPolicy | Select-Object  Domains, Enabled, Name, Identity
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
            $Script:tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy matches Exchange On Premise Sharing Policy Domain"
            $Script:tdSharpingPolicyCheckColor = "green"
        }

        else {
            Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
            Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
            $Script:tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
            $Script:tdSharpingPolicyCheckColor = "red"
        }
    } elseif ($SPOnpremDomain1 -eq $SPOnlineDomain2 -and $SPOnpremAction1 -eq $SPOnlineAction2) {
        if ($SPOnpremDomain2 -eq $SPOnlineDomain1 -and $SPOnpremAction2 -eq $SPOnlineAction1) {
            Write-Host -ForegroundColor Green "`n  Exchange Online Sharing Policy Domains match Exchange On Premise Sharing Policy Domains"
            $Script:tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy matches Exchange On Premise Sharing Policy Domain"
            $Script:tdSharpingPolicyCheckColor = "green"
        }

        else {
            Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
            Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
            $Script:tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
            $Script:tdSharpingPolicyCheckColor = "red"
        }
    } else {
        Write-Host -ForegroundColor Red "`n   Sharing Domains appear not to be correct."
        Write-Host -ForegroundColor White "   Exchange Online Sharing Policy Domains appear not to match Exchange On Premise Sharing Policy Domains"
        $Script:tdSharpingPolicyCheck = "`n  Exchange Online Sharing Policy Domains not match Exchange On Premise Sharing Policy Domains"
        $Script:tdSharpingPolicyCheckColor = "red"
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
        $ExoTestOrgRel = Test-EOOrganizationRelationship -Identity $exoIdentity -UserIdentity $UserOnline -WarningAction SilentlyContinue
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
    ExoTestOrgRelCheckHtml
}

