# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-ExchangeSchema {
    [CmdletBinding()]

    # cSpell:disable
    $requiredSchemaEntries = @(
        [PSCustomObject]@{ SchemaObject = "User"; AttributeName = "systemAuxiliaryClass"; RequiredValues = @("mailRecipient") },
        [PSCustomObject]@{ SchemaObject = "Group"; AttributeName = "systemAuxiliaryClass"; RequiredValues = @("mailRecipient") },
        [PSCustomObject]@{ SchemaObject = "mail-Recipient"; AttributeName = "mayContain"; RequiredValues =
            @("altRecipient", "altRecipientBL", "assistant", "authOrig", "authOrigBL", "autoReplyMessage",
                "company", "delivContLength", "deliverAndRedirect", "deliveryMechanism", "delivExtContTypes", "department",
                "dLMemDefault", "dLMemRejectPerms", "dLMemRejectPermsBL", "dLMemSubmitPerms", "dLMemSubmitPermsBL", "dnQualifier",
                "enabledProtocols", "expirationTime", "extensionData", "folderPathname", "formData", "forwardingAddress",
                "homeMTA", "importedFrom", "internetEncoding", "labeledURI", "language", "languageCode", "mail", "mailNickname",
                "mAPIRecipient", "msDS-ExternalDirectoryObjectId", "msDS-GeoCoordinatesAltitude", "msDS-GeoCoordinatesLatitude",
                "msDS-GeoCoordinatesLongitude", "msDS-HABSeniorityIndex", "msDS-PhoneticDisplayName", "msExchAddressBookFlags",
                "msExchAdministrativeUnitLink", "msExchAggregationSubscriptionCredential", "msExchArbitrationMailbox",
                "msExchArchiveRelease", "msExchAssistantName", "msExchAuditAdmin", "msExchAuditDelegate", "msExchAuditDelegateAdmin",
                "msExchAuditOwner", "msExchAuthPolicyLink", "msExchAuxMailboxParentObjectIdLink", "msExchBlockedSendersHash",
                "msExchBypassAudit", "msExchBypassModerationBL", "msExchBypassModerationFromDLMembersBL",
                "msExchBypassModerationFromDLMembersLink", "msExchBypassModerationLink", "msExchCalculatedTargetAddress",
                "msExchCalendarRepairDisabled", "msExchCapabilityIdentifiers", "msExchCoManagedObjectsBL", "msExchConfigurationXML",
                "msExchCustomProxyAddresses", "msExchDirsyncID", "msExchDirsyncSourceObjectClass", "msExchEdgeSyncRetryCount",
                "msExchEnableModeration", "msExchEwsApplicationAccessPolicy", "msExchEwsEnabled", "msExchEwsExceptions",
                "msExchEwsWellKnownApplicationPolicies", "msExchExpansionServerName", "msExchExternalSyncState", "msExchFBURL",
                "msExchForeignGroupSID", "msExchGenericForwardingAddress", "msExchGroupExternalMemberCount", "msExchGroupMemberCount",
                "msExchGroupSecurityFlags", "msExchHABShowInDepartments", "msExchHomeMTASL", "msExchImmutableId", "msExchImmutableSid",
                "msExchIntendedMailboxPlanLink", "msExchInterruptUserOnAuditFailure", "msExchLabeledURI", "msExchLicenseToken",
                "msExchLitigationHoldDate", "msExchLitigationHoldOwner", "msExchLocalizationFlags", "msExchMailboxAuditEnable",
                "msExchMailboxAuditLastAdminAccess", "msExchMailboxAuditLastDelegateAccess", "msExchMailboxAuditLastExternalAccess",
                "msExchMailboxAuditLogAgeLimit", "msExchMailboxFolderSet", "msExchMailboxFolderSet2", "msExchMailboxMoveBatchName",
                "msExchMailboxMoveFlags", "msExchMailboxMoveRemoteHostName", "msExchMailboxMoveSourceArchiveMDBLink",
                "msExchMailboxMoveSourceArchiveMDBLinkSL", "msExchMailboxMoveSourceMDBLink", "msExchMailboxMoveSourceMDBLinkSL",
                "msExchMailboxMoveStatus", "msExchMailboxMoveTargetArchiveMDBLink", "msExchMailboxMoveTargetArchiveMDBLinkSL",
                "msExchMailboxMoveTargetMDBLink", "msExchMailboxMoveTargetMDBLinkSL", "msExchMailboxPlanType", "msExchMailboxRelease",
                "msExchMailboxSecurityDescriptor", "msExchMasterAccountSid", "msExchMessageHygieneFlags",
                "msExchMessageHygieneSCLDeleteThreshold", "msExchMessageHygieneSCLJunkThreshold",
                "msExchMessageHygieneSCLQuarantineThreshold", "msExchMessageHygieneSCLRejectThreshold", "msExchModeratedByLink",
                "msExchModeratedObjectsBL", "msExchModerationFlags", "msExchMultiMailboxDatabasesLink", "msExchObjectID",
                "msExchOrganizationUpgradeRequest", "msExchOrganizationUpgradeStatus", "msExchOWAPolicy", "msExchParentPlanLink",
                "msExchPartnerGroupID", "msExchPoliciesExcluded", "msExchPoliciesIncluded", "msExchPolicyEnabled",
                "msExchPolicyOptionList", "msExchPreviousAccountSid", "msExchPreviousRecipientTypeDetails", "msExchProvisioningFlags",
                "msExchProxyCustomProxy", "msExchPublicFolderMailbox", "msExchPublicFolderSmtpAddress", "msExchRBACPolicyLink",
                "msExchRecipientDisplayType", "msExchRecipientSoftDeletedStatus", "msExchRecipientTypeDetails", "msExchRecipLimit",
                "msExchRemoteRecipientType", "msExchRequireAuthToSendTo", "msExchResourceCapacity", "msExchResourceDisplay",
                "msExchResourceMetaData", "msExchResourceSearchProperties", "msExchRetentionComment", "msExchRetentionURL",
                "msExchRMSComputerAccountsLink", "msExchRoleGroupType", "msExchSafeRecipientsHash", "msExchSafeSendersHash",
                "msExchSendAsAddresses", "msExchSenderHintTranslations", "msExchShadowWhenSoftDeletedTime",
                "msExchSharingAnonymousIdentities", "msExchSharingPartnerIdentities", "msExchSharingPolicyLink", "msExchSignupAddresses",
                "msExchStsRefreshTokensValidFrom", "msExchSupervisionDLLink", "msExchSupervisionOneOffLink", "msExchSupervisionUserLink",
                "msExchSyncAccountsPolicyDN", "msExchTextMessagingState", "msExchThrottlingPolicyDN",
                "msExchTransportRecipientSettingsFlags", "msExchUCVoiceMailSettings", "msExchUGEventSubscriptionLink", "msExchUGMemberLink",
                "msExchUMAddresses", "msExchUMCallingLineIDs", "msExchUMDtmfMap", "msExchUMListInDirectorySearch",
                "msExchUMRecipientDialPlanLink", "msExchUMSpokenName", "msExchUsageLocation", "msExchUserAccountControl",
                "msExchUserHoldPolicies", "msExchWhenMailboxCreated", "msExchWhenSoftDeletedTime", "msExchWindowsLiveID", "pOPCharacterSet",
                "pOPContentFormat", "protocolSettings", "publicDelegates", "publicDelegatesBL", "replicationSensitivity", "secretary",
                "securityProtocol", "submissionContLength", "targetAddress", "unauthOrig", "unauthOrigBL", "userSMIMECertificate",
                "versionNumber")
        }
    )
    # cSpell:enable

    $schemaPath = ([ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")).Properties["schemaNamingContext"][0]

    $schemaIsGood = $true

    foreach ($o in $requiredSchemaEntries) {
        $schemaObject = [ADSI]("LDAP://CN=$($o.SchemaObject),$schemaPath")
        $attributeValues = $schemaObject.Properties[$o.AttributeName]
        $missingValues = $o.RequiredValues | Where-Object { $attributeValues -notcontains $_ }
        if ($missingValues) {
            Write-Host "$($o.SchemaObject) missing $($o.AttributeName): $missingValues"
            $schemaIsGood = $false
        }
    }

    return $schemaIsGood
}
