# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 5.0

<#
.SYNOPSIS
    This script can be used to configure the dedicated Exchange hybrid application.
    More information can be found in https://aka.ms/ConfigureExchangeHybridApplication
.DESCRIPTION
    This script configures and enables the dedicated Exchange hybrid application feature.
    It supports both All-in-one Configuration and Split Execution Configuration modes.
    Additionally, the script can reset the keyCredentials of the first-party service principal object or renew the Auth Certificate,
    which must be uploaded to the service principal of the newly created application.The script utilizes native Graph API calls to perform the configuration in Entra ID,
    acquiring an access token for the Graph API using the OAuth 2.0 authorization code flow with PKCE (Proof Key for Code Exchange).
.PARAMETER FullyConfigureExchangeHybridApplication
    Use this switch parameter fully configure the dedicated Exchange hybrid application feature.
.PARAMETER CreateApplication
    Use this switch parameter to create the application in Microsoft Entra ID.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
.PARAMETER DeleteApplication
    Use this switch parameter to delete an existing application in Microsoft Entra ID. Note that the script will only delete the application.
    The script doesn't undo any changes, e.g. to Auth Server objects and doesn't remove the Setting Override.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
.PARAMETER UpdateCertificate
    Use this switch parameter to upload the Auth Certificate to the application in Microsoft Entra ID.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
.PARAMETER ConfigureAuthServer
    Use this switch parameter to configure the Auth Server object. The script will add the appId of the newly created application to the "EvoSTS" or
    "EvoSTS - {Guid}" Auth Server object.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
.PARAMETER CustomAppId
    Use this parameter to provide the Application (client) ID (also known as appId) of a custom application in Microsoft Entra ID.
    In most cases this parameter does not need to be used.
.PARAMETER TenantId
    Use this parameter to provide the ID of your tenant in Microsoft Entra ID.
    In most cases this parameter does not need to be used.
.PARAMETER RemoteRoutingDomain
    Use this parameter to provide the remote routing domain of your tenant in Microsoft Entra ID.
    In most cases this parameter does not need to be used.
.PARAMETER ConfigureTargetSharingEpr
    Use this switch parameter to configure the Organization Relationship between Exchange Server and Exchange Online.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
.PARAMETER EnableExchangeHybridApplicationOverride
    Use this switch parameter to create the Setting Override which enables the dedicated Exchange hybrid application feature.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
.PARAMETER ResetFirstPartyServicePrincipalKeyCredentials
    Use this switch parameter to remove a specific or all available Key Credentials from the Service Principal of the "Office 365 Exchange Online" application
    By default, all existing Key Credentials will be removed. If you provide the thumbprint of a certificate by using the "CertificateInformation" parameter,
    only the specified and all expired certificates will be removed.
.PARAMETER AzureEnvironment
    Use this parameter to run the script against non-Global cloud environments, for example, Microsoft 365 operated by 21Vianet.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
    Values that can be used with this parameter are: Global, USGovernmentL4, USGovernmentL5, ChinaCloud
    The default value is: Global
.PARAMETER CustomClientId
    This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
.PARAMETER CustomGraphApiUri
    This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
.PARAMETER CustomEntraAuthUri
    This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
.PARAMETER CustomInitialCloudDomains
    This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
.PARAMETER CustomMicrosoftDomains
    This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
.PARAMETER CertificateMethod
    Use this parameter to specify the method which should be used by the script to search for the Auth Certificate. By default, the script will
    try to export the current, and if already set, the new next Auth Certificate and will upload them to the application in Microsoft Entra ID.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
    Values that can be used with this parameter are: Thumbprint, File, Automated
    The default value is: Automated
.PARAMETER CertificateInformation
    Use this parameter to provide the thumbprint of the certificate that you want the script to export and upload or the file path to the
    certificate file, for example, "c:\temp\certificate.cer". You don't need to use this parameter if CertificateMethod is set to "Automated".
    If you provide the thumbprint, the script searches and exports the certificate with the thumbprint provided from the local machines certificate
    store. If you provide the file path, the script uploads the certificate, which was specified.
    This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
.PARAMETER ScriptUpdateOnly
    This optional parameter allows you to only update the script without performing any other actions.
.PARAMETER SkipVersionCheck
    This optional parameter allows you to skip the automatic version check and script update.
.EXAMPLE
    PS C:\> .\ConfigureExchangeHybridApplication.ps1 -FullyConfigureExchangeHybridApplication
    It will create the application in Microsoft Entra ID, upload the current and, if configured, the new next Auth Certificate, configure the Auth Server object,
    and create a global Setting Override to enable the feature.
    The script will also validate if the Auth Certificates are available as keyCredentials of the "Office 365 Exchange Online" first-party applications Service Principal and tries to remove them.
.EXAMPLE
    PS C:\> .\ConfigureExchangeHybridApplication.ps1 -UpdateCertificate
    It will upload the current and, if configured, the new next Auth Certificate to the application in Microsoft Entra ID. You can use this syntax if the Auth Certificate has been renewed.
    The script will also validate if the certificates are available as keyCredentials of the "Office 365 Exchange Online" first-party applications Service Principal and tries to remove them.
.EXAMPLE
    PS C:\> .\ConfigureExchangeHybridApplication.ps1 -ConfigureTargetSharingEpr
    It will update all enabled Organization Relationship objects that have the TargetAutodiscoverEpr set but not the TargetSharingEpr,
    and where DomainNames contain domains related to organizations hosted in Exchange Online.
.EXAMPLE
    PS C:\> .\ConfigureExchangeHybridApplication.ps1 -ResetFirstPartyServicePrincipalKeyCredentials
    It will delete all certificates of the "Office 365 Exchange Online" first-party applications Service Principal.
.EXAMPLE
    PS C:\> .\ConfigureExchangeHybridApplication.ps1 -ResetFirstPartyServicePrincipalKeyCredentials -CertificateInformation "1234567890ABCDEF1234567890ABCDEF12345678"
    It will remove the certificate with thumbprint 1234567890ABCDEF1234567890ABCDEF12345678 of the "Office 365 Exchange Online" first-party applications Service Principal.
    It will also remove all certificates that have already expired.
.EXAMPLE
    PS C:\> .\ConfigureExchangeHybridApplication.ps1 -DeleteApplication
    It will delete the application in Microsoft Entra ID. It doesn't undo any changes, such as to Auth Server objects, and it doesn't remove the Setting Override.
.EXAMPLE
    PS C:\> .\ConfigureExchangeHybridApplication.ps1 -CreateApplication -UpdateCertificate -CertificateMethod "File" -CertificateInformation "c:\temp\certificate.cer"
    It will create the application in Microsoft Entra ID and upload the certificate provided to the newly created application.
    The script will also validate if the certificates are available as keyCredentials of the "Office 365 Exchange Online" first-party application's Service Principal and tries to remove them.
    You can use this syntax if your Exchange Server doesn't provide outbound connectivity to Microsoft Graph API and you want to run the script on a machine with Microsoft Graph API connectivity.
    You need to export the Auth Certificate first (make sure NOT TO export the private key) and copy it over to the machine where the script is executed.
.EXAMPLE
    PS C:\> .\ConfigureExchangeHybridApplication.ps1 -ConfigureAuthServer -EnableExchangeHybridApplicationOverride -CustomAppId <appId> -TenantId <tenantId> -RemoteRoutingDomain <targetDeliveryDomain>
    It will configure the Auth Server object and enable the dedicated Exchange hybrid application feature. The script will not try to create the application in Microsoft Entra ID and will not try to upload the Auth Certificate.
    It uses of the App ID which is provided. The script will not verify if the App ID is correct as it will not perform any Graph API calls.
    You can use this syntax if the application was already created by using a different non-Exchange Server machine as described in the previous example.
    It's intended for environments where Exchange Server has no outgoing connection to Microsoft Graph API.
#>

[CmdletBinding(DefaultParameterSetName = "FullyConfigureExchangeHybridApplication", SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "FullyConfigureExchangeHybridApplication")]
    [switch]$FullyConfigureExchangeHybridApplication,

    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [switch]$CreateApplication,

    [Parameter(Mandatory = $true, ParameterSetName = "Delete")]
    [switch]$DeleteApplication,

    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [switch]$UpdateCertificate,

    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Parameter(Mandatory = $false, ParameterSetName = "CustomAppId")]
    [switch]$ConfigureAuthServer,

    [Parameter(Mandatory = $true, ParameterSetName = "CustomAppId")]
    [ValidatePattern("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$CustomAppId,

    [Parameter(Mandatory = $true, ParameterSetName = "CustomAppId")]
    [ValidatePattern("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$TenantId,

    [Parameter(Mandatory = $true, ParameterSetName = "CustomAppId")]
    [string]$RemoteRoutingDomain,

    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Parameter(Mandatory = $false, ParameterSetName = "CustomAppId")]
    [switch]$ConfigureTargetSharingEpr,

    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Parameter(Mandatory = $false, ParameterSetName = "CustomAppId")]
    [switch]$EnableExchangeHybridApplicationOverride,

    [Parameter(Mandatory = $false, ParameterSetName = "FirstPartyKeyCredentialsCleanup")]
    [switch]$ResetFirstPartyServicePrincipalKeyCredentials,

    [ValidateSet("Global", "USGovernmentL4", "USGovernmentL5", "ChinaCloud")]
    [Parameter(Mandatory = $false, ParameterSetName = "FullyConfigureExchangeHybridApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "FirstPartyKeyCredentialsCleanup")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Parameter(Mandatory = $false, ParameterSetName = "Delete")]
    [string]$AzureEnvironment = "Global",

    [Parameter(Mandatory = $false, ParameterSetName = "FullyConfigureExchangeHybridApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "FirstPartyKeyCredentialsCleanup")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Parameter(Mandatory = $false, ParameterSetName = "Delete")]
    [ValidatePattern("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$CustomClientId = $null,

    [Parameter(Mandatory = $false, ParameterSetName = "FullyConfigureExchangeHybridApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "FirstPartyKeyCredentialsCleanup")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Parameter(Mandatory = $false, ParameterSetName = "Delete")]
    [string]$CustomGraphApiUri = $null,

    [Parameter(Mandatory = $false, ParameterSetName = "FullyConfigureExchangeHybridApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "FirstPartyKeyCredentialsCleanup")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Parameter(Mandatory = $false, ParameterSetName = "Delete")]
    [string]$CustomEntraAuthUri = $null,

    [Parameter(Mandatory = $false, ParameterSetName = "FullyConfigureExchangeHybridApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [string[]]$CustomInitialCloudDomains = $null,

    [Parameter(Mandatory = $false, ParameterSetName = "FullyConfigureExchangeHybridApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [string[]]$CustomMicrosoftDomains = $null,

    [ValidateSet("Thumbprint", "File", "Automated")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [string]$CertificateMethod = "Automated",

    [Parameter(Mandatory = $false, ParameterSetName = "FirstPartyKeyCredentialsCleanup")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [string]$CertificateInformation,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly,

    [Parameter(Mandatory = $false, ParameterSetName = "FullyConfigureExchangeHybridApplication")]
    [Parameter(Mandatory = $false, ParameterSetName = "FirstPartyKeyCredentialsCleanup")]
    [Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Parameter(Mandatory = $false, ParameterSetName = "Delete")]
    [switch]$SkipVersionCheck
)

begin {
    $versionsUrl = "https://aka.ms/ConfigureExchangeHybridApplication-VersionsURL"

    . $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\..\Shared\Confirm-ExchangeManagementShell.ps1
    . $PSScriptRoot\..\..\Shared\Export-CertificateToMemory.ps1
    . $PSScriptRoot\..\..\Shared\GenericScriptStartLogging.ps1
    . $PSScriptRoot\..\..\Shared\Get-ExchangeSettingOverride.ps1
    . $PSScriptRoot\..\..\Shared\Get-PSSessionDetails.ps1
    . $PSScriptRoot\..\..\Shared\Get-ProtocolEndpointViaAutoDv2.ps1
    . $PSScriptRoot\..\..\Shared\Show-Disclaimer.ps1
    . $PSScriptRoot\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeOrganizationGuid.ps1
    . $PSScriptRoot\..\..\Shared\AzureFunctions\Get-GraphAccessToken.ps1
    . $PSScriptRoot\..\..\Shared\AzureFunctions\Get-CloudServiceEndpoint.ps1
    . $PSScriptRoot\..\..\Shared\AzureFunctions\Get-NewJsonWebToken.ps1
    . $PSScriptRoot\..\..\Shared\AzureFunctions\Get-NewOAuthToken.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\Add-CertificateToAzureApplication.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\Get-AzureApplication.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\Get-AzureAppRoleAssignments.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\Get-AzureServicePrincipal.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\Get-AzureTenantDomainList.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\New-EwsAzureApplication.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\Remove-AzureApplication.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\Remove-CertificateFromAzureServicePrincipal.ps1
    . $PSScriptRoot\..\..\Shared\GraphApiFunctions\Test-AzureApplicationPermission.ps1
    . $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1
    . $PSScriptRoot\..\..\Shared\Get-ProcessedServerList.ps1

    function Show-AuthCertificateInvalidWarning {
        param()

        Write-Host ""
        Write-Warning "If the script was already run from an elevated Exchange Management Shell (EMS), ensure the Auth Certificate is valid"
        Write-Warning "For more details, see: https://aka.ms/MonitorExchangeAuthCertificate"
    }

    function Get-XForEnabledFeature {
        param(
            [bool]$Value
        )

        if ($Value) {
            return "X"
        }

        return " "
    }

    #region Constants
    # Base build number on which the Exchange Server 2019 CU15 release is based
    [System.Version]$exchangeServer2019Cu15BaseBuild = "15.2.1748.0"

    # IDs that we need to create the application in Microsoft Entra ID
    $resourceAppId = "00000002-0000-0ff1-ce00-000000000000" # Office 365 Exchange Online
    $resourceAccessId = "dc890d15-9560-4a4c-9b7f-a736ec74ec40" # full_access_as_app (Use Exchange Web Services with full access to all mailboxes)

    # Arbitration mailbox that exists in all tenants (regardless of the cloud environment), which is used in AutoD v2 calls against EXO
    $arbitrationMailbox = "Migration.8f3e7716-2011-43e4-96b1-aba62d229136"

    # cSpell:disable
    # List of initial cloud domains that we use to filter out all Organization Relationships between Exchange Server and EXO
    $initialCloudDomainsDefault = @("onmicrosoft.com", "partner.onmschina.cn", "onmicrosoft.us")

    # List of Microsoft cloud domains which could be used as part of the TargetAutodiscoverEpr
    $microsoftDomainsDefault = @("office365.com", "office365.us", "office365-net.us", "office.com", "cloud.microsoft", "outlook.com", "outlook.cn", "apps.mil")
    # cSpell:enable

    # Notes that we set on the Enterprise Application and Service Principal to highlight the intended use of the app in Entra ID
    $notes = "Used by Exchange Server as part of the hybrid configuration to enable hybrid features such as Free/Busy, MailTips, and Profile Picture sharing between Exchange Server and Exchange Online."

    # Exchange Server logo as this will be added to the Enterprise Application in Entra ID
    $logo = Get-Content ".\Logos\ExchangeServerLogo.png" -AsByteStream -Raw
    #endregion

    # List to store the Exchange servers which are running on an older Exchange Server build
    $outdatedExchangeServersList = New-Object System.Collections.Generic.List[string]

    # List to store the Exchange servers which are offline and therefore can't be verified supporting dedicated Exchange hybrid application feature
    $offlineExchangeServersList = New-Object System.Collections.Generic.List[string]

    # List to store the certificates that needs to be uploaded
    $certificateListObject = New-Object System.Collections.Generic.List[object]

    # List to store the setting overrides configurations
    $3pSettingOverridesObject = New-Object System.Collections.Generic.List[object]
} process {
    Get-PSSessionDetails
    Write-Verbose "Url to check for new versions of the script is: $versionsUrl"

    # Prevent the script from running on PowerShell Core - there are adjustments needed which must be tested before release
    # We can't use requires PSEdition Desktop because it's not compatible with PowerShell version 3 and 4
    if ($null -ne $PSVersionTable.PSEdition -and $PSVersionTable.PSEdition -eq "Core") {
        Write-Warning "This script isn't supported in PowerShell Core - use PowerShell 5.1 or earlier"

        return
    }

    #region Pre-Configuration
    # Gets the Fqdn of the local computer
    $localServerFqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName

    # Endpoints which we need to run the Graph API calls against
    $cloudService = Get-CloudServiceEndpoint $Script:AzureEnvironment

    $azureADEndpoint = $cloudService.AzureADEndpoint

    # Add all default domains here - we need them in the ConfigureTargetSharingEpr region
    $Script:CustomInitialCloudDomains = $Script:CustomInitialCloudDomains + $initialCloudDomainsDefault

    # Add all Microsoft domains here - we need them in the ConfigureTargetSharingEpr region
    $Script:CustomMicrosoftDomains = $Script:CustomMicrosoftDomains + $microsoftDomainsDefault

    # HashSet to store unique values for initial cloud domains (e.g., onmicrosoft.com)
    $initialCloudDomains = New-Object System.Collections.Generic.HashSet[string]

    # Add the initial domains one by one to the HashSet
    foreach ($customInitialDomain in $Script:CustomInitialCloudDomains) {
        $initialCloudDomains.Add($customInitialDomain) | Out-Null
    }

    if (-not([System.String]::IsNullOrWhiteSpace($Script:CustomEntraAuthUri))) {
        Write-Verbose "Custom Entra Authentication Endpoint was provided and will be used: $Script:CustomEntraAuthUri"
        $azureADEndpoint = $Script:CustomEntraAuthUri
    }

    $graphApiEndpoint = $cloudService.GraphApiEndpoint

    if (-not([System.String]::IsNullOrWhiteSpace($Script:CustomGraphApiUri))) {
        Write-Verbose "Custom Graph Api Endpoint was provided and will be used: $Script:CustomGraphApiUri"
        $graphApiEndpoint = $Script:CustomGraphApiUri
    }

    if (-not $Script:ResetFirstPartyServicePrincipalKeyCredentials) {
        # Query the guid of the Exchange organization and set the name of the application that we create in Azure and working with
        $organizationGuid = Get-ExchangeOrganizationGuid
    }

    if ($null -eq $organizationGuid -and
        -not $Script:ResetFirstPartyServicePrincipalKeyCredentials) {
        Write-Warning "Unable to query the guid of the Exchange organization - please try to run the script again"

        return
    }

    $azureApplicationName = "ExchangeServerApp-$organizationGuid"

    if ($Script:FullyConfigureExchangeHybridApplication) {
        Write-Verbose "FullyConfigureExchangeHybridApplication was used to run the script - all tasks to configure the dedicated Exchange hybrid application feature will be executed"

        $Script:CreateApplication = $true
        $Script:UpdateCertificate = $true
        $Script:ConfigureAuthServer = $true
        $Script:ConfigureTargetSharingEpr = $true
        $Script:EnableExchangeHybridApplicationOverride = $true
    }
    #endregion

    #region Prerequisites
    # Make sure that PowerShell runs in elevated mode - if it doesn't we don't need to proceed further - stop the script run
    if (-not (Confirm-Administrator)) {
        Write-Warning "This script must be executed in elevated mode - start the PowerShell as an Administrator and try again"

        return
    }

    # Set the disclaimer text that will be shown when script is executed
    $targetMessage = "[{0}] CreateApplication`r`n[{1}] UpdateCertificate`r`n[{2}] EnableExchangeHybridApplicationOverride`r`n[{3}] ConfigureTargetSharingEpr`r`n[{4}] ConfigureAuthServer" -f
    $(Get-XForEnabledFeature $Script:CreateApplication),
    $(Get-XForEnabledFeature $Script:UpdateCertificate),
    $(Get-XForEnabledFeature $Script:EnableExchangeHybridApplicationOverride),
    $(Get-XForEnabledFeature $Script:ConfigureTargetSharingEpr),
    $(Get-XForEnabledFeature $Script:ConfigureAuthServer)

    if ($Script:DeleteApplication) {
        $targetMessage = "[{0}] DeleteApplication" -f $(Get-XForEnabledFeature $Script:DeleteApplication)
        $targetMessage = $targetMessage + @"
        `r`n`r`nIMPORTANT: The application which was created in Microsoft Entra ID to enable the dedicated Exchange hybrid application feature will be deleted
        `rThis can lead to a broken hybrid state if the dedicated Exchange hybrid application feature is still enabled and configured to use this Entra application
"@
    } elseif ($Script:ResetFirstPartyServicePrincipalKeyCredentials) {
        # Add additional context about the reset first-party keyCredentials operation
        $targetMessage = "[{0}] ResetFirstPartyServicePrincipalKeyCredentials" -f $(Get-XForEnabledFeature $Script:ResetFirstPartyServicePrincipalKeyCredentials)

        $keyCredentialsCleanUpTargetMessage = "All existing KeyCredentials will be removed from the first-party Service Principal"

        if (-not([System.String]::IsNullOrEmpty($Script:CertificateInformation))) {
            $keyCredentialsCleanUpTargetMessage = "The certificate with thumbprint: $Script:CertificateInformation will be removed from the first-party Service Principal"
        }

        Write-Verbose $keyCredentialsCleanUpTargetMessage

        $targetMessage = $targetMessage + @"
        `r`n`r`nIMPORTANT: $keyCredentialsCleanUpTargetMessage
        `rMake sure that all Exchange servers in your organization are running on a build that supports the dedicated Exchange hybrid application feature
        `rServers that do not run a supported build may end up in a broken hybrid state after running the clean-up operation
"@
    }

    $params = @{
        Message   = "Show warning about Microsoft Entra ID application configuration"
        Target    = "The script was executed to perform the following operations:" +
        "`r`n`r`n$targetMessage" +
        "`r`n`r`nMore information about the script and each operation can be found under: https://aka.ms/ConfigureExchangeHybridApplication-Docs#changes-made-by-the-script" +
        "`r`n`r`nDo you want to continue?"
        Operation = "Configure dedicated Exchange hybrid application feature"
    }

    Show-Disclaimer @params

    # This combination needs some special treatment like running on a mailbox server and via EMS
    $isAutomatedCertificateUpload = $Script:UpdateCertificate -and $Script:CertificateMethod -eq "Automated"

    if (-not(Confirm-ExchangeManagementShell)) {
        $notRunViaEmsString = "To perform the {0} configuration, the script must be executed from an elevated Exchange Management Shell (EMS)"

        Write-Host ""

        # Script must be executed via EMS if 'UpdateCertificate' parameter is used and CertificateMethod is set to 'Automated'
        if ($isAutomatedCertificateUpload) {
            Write-Warning "To perform the automated export and upload of the Auth Certificate, the script must be executed on an Exchange server"
            Write-Warning "Make sure to run the script from an elevated Exchange Management Shell (EMS)"
            Write-Warning "Otherwise you can specify the certificate by using the '-CertificateInformation' parameter"
            Show-AuthCertificateInvalidWarning

            return
        }

        # Script must be executed via EMS if 'ConfigureAuthServer' parameter is used - this is because we need to run the 'Set-AuthServer' cmdlet
        if ($Script:ConfigureAuthServer) {
            Write-Warning ($notRunViaEmsString -f "Auth Server")
            Show-AuthCertificateInvalidWarning

            return
        }

        # Script must be executed via EMS if 'ConfigureTargetSharingEpr' parameter is used - this is because we need to run the 'Set-OrganizationRelationship' cmdlet
        if ($Script:ConfigureTargetSharingEpr) {
            Write-Warning ($notRunViaEmsString -f "TargetSharingEpr")
            Show-AuthCertificateInvalidWarning

            return
        }

        # Script must be executed via EMS if 'EnableExchangeHybridApplicationOverride' parameter is used - this is because we need to run the 'New-SettingOverride' cmdlet
        if ($Script:EnableExchangeHybridApplicationOverride) {
            Write-Warning ($notRunViaEmsString -f "Setting Override")
            Show-AuthCertificateInvalidWarning

            return
        }
    }

    # For some of the scenarios, we must validate additional data from the Exchange server (e.g., build number or role) - we run these checks in this section
    # If the script was run to configure TargetSharingEpr or AuthServer only, we don't need to perform a Exchange Hybrid Application feature supported build check
    if (($Script:ConfigureTargetSharingEpr -or
            $Script:ConfigureAuthServer) -and
        $Script:EnableExchangeHybridApplicationOverride -eq $false) {
        Write-Verbose "Script was run to only configure TargetSharingEpr or AuthServer - dedicated Exchange hybrid application feature build check will be skipped"
    } elseif ($isAutomatedCertificateUpload -or
        $Script:EnableExchangeHybridApplicationOverride) {
        $exchangeServersList = Get-ProcessedServerList -MinimumSU "Apr25HU" -DisplayOutdatedServers $false

        $isLocalServerMailboxServer = ($exchangeServersList.GetExchangeServer | Where-Object {
                $_.Fqdn -eq $localServerFqdn
            }).ServerRole -eq "Mailbox"

        # Stop processing if the server where the script runs isn't a Mailbox server
        if ($isLocalServerMailboxServer -eq $false) {
            Write-Host "Processing stopped: The selected configuration must be executed on a Mailbox server" -ForegroundColor Red

            return
        }

        # It's safe to enable dedicated Exchange hybrid application feature while not all servers in the organization running a supported build
        # older builds will continue using the first-party application
        foreach ($server in $exchangeServersList.GetExchangeServer) {
            Write-Verbose "Processing server: $($server.Fqdn) running Exchange CU build: $($server.AdminDisplayVersion.ToString())"

            if ($server.ServerRole -eq "Edge") {
                Write-Verbose "Server is running Edge Transport role - dedicated Exchange hybrid application is not supported on this role"

                continue
            }

            if ($server.AdminDisplayVersion -lt $exchangeServer2019Cu15BaseBuild) {
                Write-Verbose "Build is lower than the Exchange Server 2019 CU15 base build - validating SU build"

                if ($exchangeServersList.OfflineExchangeServerFqdn -contains $server.Fqdn) {
                    Write-Verbose "Server is offline - we can't validate if the build supports dedicated Exchange hybrid application feature"
                    $offlineExchangeServersList.Add($server.Fqdn)

                    continue
                }

                if ($exchangeServersList.OutdatedBuildExchangeServerFqdn -contains $server.Fqdn) {
                    Write-Verbose "Server build doesn't support dedicated Exchange hybrid application feature"
                    $outdatedExchangeServersList.Add($server.Fqdn)

                    continue
                }
            }

            Write-Verbose "Server supports dedicated Exchange hybrid application feature"
        }

        if ($outdatedExchangeServersList.Count -ge 1 -or
            $offlineExchangeServersList.Count -ge 1) {
            # Make sure that the computer which runs the script, is not running an outdated build because of the setting override that is created by the script
            if ($outdatedExchangeServersList -contains $localServerFqdn) {
                Write-Host "The script needs to be run on an Exchange server that supports the dedicated Exchange hybrid application feature" -ForegroundColor Red

                return
            }

            $outdatedServersDisclaimerParams = @{
                Message   = "Show warning about outdated Exchange server builds"
                Target    = "The following Exchange servers are either running a build that does not support the dedicated Exchange hybrid application feature or were offline and could not be validated:" +
                "`r`nOutdated: $([System.String]::Join(", ", $outdatedExchangeServersList))" +
                "`r`nOffline: $([System.String]::Join(", ", $offlineExchangeServersList))" +
                "`r`nOutdated servers will continue to use the first-party application even after dedicated Exchange hybrid application feature is enabled." +
                "`r`n`r`nDo you want to continue?"
                Operation = "Configure dedicated Exchange hybrid application feature"
            }

            Show-Disclaimer @outdatedServersDisclaimerParams
        }
    }
    #endregion

    # Scenarios where we need the access token or tenant id are the following
    # CreateApplication, DeleteApplication, UpdateCertificate, ConfigureAuthServer, EnableExchangeHybridApplicationOverride, ResetFirstPartyServicePrincipalKeyCredentials
    if ($Script:CreateApplication -or
        $Script:DeleteApplication -or
        $Script:UpdateCertificate -or
        $Script:ConfigureAuthServer -or
        $Script:EnableExchangeHybridApplicationOverride -or
        $Script:ResetFirstPartyServicePrincipalKeyCredentials) {
        Write-Verbose "Access token or tenant information are required to process the current scenario selection"

        # Acquire Graph access token to run calls against Graph Api but only do if no custom AppId was passed
        if ([System.String]::IsNullOrEmpty($Script:CustomAppId)) {
            Write-Verbose "Acquiring Microsoft Graph API access token"
            $getGraphAccessTokenParams = @{
                AzureADEndpoint = $azureADEndpoint
                GraphApiUrl     = $graphApiEndpoint
            }

            if (-not [System.String]::IsNullOrEmpty($Script:CustomClientId)) {
                Write-Verbose "CustomClientId $Script:CustomClientId was provided and will be used"
                $getGraphAccessTokenParams.Add("ClientId", $Script:CustomClientId)
            }

            $graphAccessToken = Get-GraphAccessToken @getGraphAccessTokenParams

            if ($null -eq $graphAccessToken) {
                Write-Warning "Failed to acquire an access token - the script cannot continue"

                return
            }

            # Get the tenantId from the access token as we need it later
            $Script:TenantId = $graphAccessToken.TenantId
        }

        # Built the Graph API basic params including the Graph Api Access Token
        $graphApiBaseParams = @{
            GraphApiUrl      = $graphApiEndpoint
            AzAccountsObject = $graphAccessToken
        }

        if (-not $Script:ResetFirstPartyServicePrincipalKeyCredentials) {
            # We need the application information for running any kind of sub-task and therefore query it first
            if ([System.String]::IsNullOrEmpty($Script:CustomAppId)) {
                Write-Verbose "No App ID was provided via 'CustomAppId' parameter"
                $azureApplicationInformation = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $azureApplicationName

                # Get-AzureApplication returns $null if the Graph API call has failed (StatusCode != 200)
                if ($null -eq $azureApplicationInformation) {
                    Write-Warning "Graph API call to validate the existence of the application has failed"
                    Write-Warning "Please run the script again or provide the App ID by using the 'CustomAppId' parameter"

                    return
                }
            }

            # We also need the list of domains which are registered for a tenant to locate the remote routing domains
            if ([System.String]::IsNullOrWhiteSpace($Script:RemoteRoutingDomain)) {
                Write-Verbose "No Remote Routing Domain ID was provided via 'RemoteRoutingDomain' parameter"
                $domainList = Get-AzureTenantDomainList @graphApiBaseParams
            }
        }
    }

    #region DeleteApplication
    if ($Script:DeleteApplication) {
        Write-Host "`r`nPerforming operation: DeleteApplication" -ForegroundColor Cyan
        Write-Host "Trying to delete application: $azureApplicationName"

        # Check if the Azure Application exists - if it doesn't exist we don't need to do anything
        if ($azureApplicationInformation.ApplicationExists -eq $false) {
            Write-Warning "Application: $azureApplicationName doesn't exist"

            return
        }

        $deleteApplicationReturn = Remove-AzureApplication @graphApiBaseParams -AzureApplicationName $azureApplicationName

        if ($deleteApplicationReturn -eq $false) {
            Write-Warning "Something went wrong while deleting the application"

            return
        }

        Write-Host "Application: $azureApplicationName was deleted successfully" -ForegroundColor Green
        return
    }
    #endregion

    #region CreateApplication
    if ($Script:CreateApplication) {
        Write-Host "`r`nPerforming operation: CreateApplication" -ForegroundColor Cyan

        # First, check if the Azure Application already exists - if that's the case, we don't need to do anything except validating it
        if ($azureApplicationInformation.ApplicationExists) {
            $testAzureApplicationParams = $graphApiBaseParams + @{
                AzureApplicationObject = $azureApplicationInformation
                ResourceAppId          = $resourceAppId
                ResourceAccessId       = $resourceAccessId
                Type                   = "Role"
            }

            $testAzureApplicationPermissionReturn = Test-AzureApplicationPermission @testAzureApplicationParams

            if ($testAzureApplicationPermissionReturn.PermissionsAsExpected -eq $false -or
                $testAzureApplicationPermissionReturn.AdminConsentGranted -eq $false) {
                Write-Verbose "Application: $azureApplicationName App ID: $($azureApplicationInformation.AppId) is not configured as expected"
                Write-Verbose "PermissionsAsExpected: $($testAzureApplicationPermissionReturn.PermissionsAsExpected) AdminConsentGranted: $($testAzureApplicationPermissionReturn.AdminConsentGranted)"

                Write-Warning "Application: $azureApplicationName with App ID: $($azureApplicationInformation.AppId) already exists but seems not to be configured as expected"
                Write-Warning "Please delete the application by executing the script as follows:"
                Write-Warning "`t.\$($script:MyInvocation.MyCommand.Name) -DeleteApplication"

                return
            }

            Write-Host "Application: $azureApplicationName with App ID: $($azureApplicationInformation.AppId) already exists and is configured as expected"
        } else {
            $newEwsAzureApplicationParams = $graphApiBaseParams + @{
                AzureApplicationName                  = $azureApplicationName
                AskForConsent                         = $true
                PngByteArray                          = $logo
                Notes                                 = $notes
                AllowCreationWithoutConsentPermission = $true
            }

            # Try to create the EWS Azure Application
            $newEwsApplicationReturn = New-EwsAzureApplication @newEwsAzureApplicationParams

            if ($null -eq $newEwsApplicationReturn.AppId) {
                Write-Warning "Something went wrong while creating application: $azureApplicationName"

                return
            }

            Write-Verbose "Application: $azureApplicationName Tenant: $Script:TenantId App ID: $($newEwsApplicationReturn.AppId) AdminConsent? $($newEwsApplicationReturn.AdminConsent) was created"

            Write-Host "`r`nApplication: $azureApplicationName was successfully created - take a note of the following values:" -ForegroundColor Green
            Write-Host "App ID: $($newEwsApplicationReturn.AppId)"
            Write-Host "Tenant ID: $Script:TenantId"

            if ($newEwsApplicationReturn.AdminConsent -eq $false) {
                Write-Warning "`r`nIMPORTANT: The application was created without tenant-wide admin consent, which is required to enable the dedicated Exchange hybrid application feature"
                Write-Warning "To complete the configuration, please ensure that you grant admin consent in the Microsoft Entra portal"
            }
        }
    }
    #endregion

    #region UpdateCertificate
    if ($Script:UpdateCertificate) {
        Write-Host "`r`nPerforming operation: UpdateCertificate" -ForegroundColor Cyan

        # First, check if the Azure Application already exists - if the application doesn't exist, we can't update the certificate
        $azureApplicationInformation = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $azureApplicationName

        if ($null -eq $azureApplicationInformation) {
            Write-Warning "Graph API call to validate the existence of the application has failed"

            return
        }

        if ($azureApplicationInformation.ApplicationExists -eq $false) {
            Write-Warning "Application: $azureApplicationName doesn't exist - use the parameter 'CreateApplication' to create it first"

            return
        }

        # Now we're trying to export the certificate(s) from the specified location (MachineStore, File or auto-detected from the MachineStore based on the output from Get-AuthConfig)
        if (($Script:CertificateMethod -eq "Thumbprint") -and
            (-not([System.String]::IsNullOrEmpty($Script:CertificateInformation)))) {
            # Try to export the certificate from the machine store
            try {
                $certificateObject = Export-CertificateToMemory -Certificate (Get-ChildItem -Path "Cert:\LocalMachine\My\$Script:CertificateInformation")
                $certificateListObject.Add($certificateObject)
            } catch {
                Write-Warning "Unable to query and export certificate with thumbprint: $Script:CertificateInformation - Exception: $_"

                return
            }
        }

        if (($Script:CertificateMethod -eq "File") -and
            (-not([System.String]::IsNullOrEmpty($Script:CertificateInformation)))) {
            if ((Test-Path -Path $Script:CertificateInformation) -eq $false) {
                Write-Warning "The certificate file: $Script:CertificateInformation doesn't exist"

                return
            }

            # Try to import the certificate from a file object
            $x509CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            try {
                $x509CertificateObject.Import($Script:CertificateInformation)

                $certificateObject = Export-CertificateToMemory -Certificate $x509CertificateObject
                $certificateListObject.Add($certificateObject)
            } catch {
                Write-Warning "Unable to import the certificate: $Script:CertificateInformation - Exception: $_"

                return
            }
        }

        if ($Script:CertificateMethod -eq "Automated") {
            # Query the current Auth Certificate and new next Auth Certificate and try to export the certificate from the machine store
            try {
                $authConfig = Get-AuthConfig

                # Export the current Auth Certificate
                $currentAuthCertificate = Export-CertificateToMemory -Certificate (Get-ChildItem -Path "Cert:\LocalMachine\My\$($authConfig.CurrentCertificateThumbprint)")
                $certificateListObject.Add($currentAuthCertificate)

                # Export the new next Auth Certificate if it's set
                if (-not([System.String]::IsNullOrEmpty($authConfig.NextCertificateThumbprint))) {
                    $newNextAuthCertificate = Export-CertificateToMemory -Certificate (Get-ChildItem -Path "Cert:\LocalMachine\My\$($authConfig.NextCertificateThumbprint)")
                    $certificateListObject.Add($newNextAuthCertificate)
                }
            } catch {
                Write-Warning "Unable to query and export Exchange Server Auth Certificate - Exception: $_"

                return
            }
        }

        # Validate that we have at least one certificate in the list object as we need this for further processing
        if ($certificateListObject.Count -eq 0) {
            Write-Warning "No valid certificate was found - processing will be stopped"

            return
        }

        # Now process the certificates and add each of them as key credential to the Azure Application
        foreach ($certificate in $certificateListObject) {
            Write-Host "Certificate: $($certificate.CertificateThumbprint) is now being processed"
            $addCertificateReturn = Add-CertificateToAzureApplication @graphApiBaseParams -AzureApplicationName $azureApplicationName -CertificateObject $certificate

            if ($addCertificateReturn) {
                Write-Host "The certificate was successfully added to the application" -ForegroundColor Green
            } else {
                Write-Warning "Something went wrong while adding the certificate to the application"

                return
            }
        }
    }
    #endregion

    #region ConfigureAuthServer
    if ($Script:ConfigureAuthServer) {
        Write-Host "`r`nPerforming operation: ConfigureAuthServer" -ForegroundColor Cyan

        if ([System.String]::IsNullOrEmpty($Script:CustomAppId)) {
            # Run Get-AzureApplication again in case that it was not run before or in case that ApplicationExists was false in the previous run
            if ($null -eq $azureApplicationInformation -or
                $azureApplicationInformation.ApplicationExists -eq $false) {
                $azureApplicationInformation = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $azureApplicationName
            }

            # If we still don't have any value for the Azure Application, it means that the Graph API call has failed for whatever reason - we can't continue
            if ($null -eq $azureApplicationInformation) {
                Write-Warning "Graph API call to validate the existence of the application has failed"

                return
            }

            # We can't continue if the call was successful but no application was found
            if ($azureApplicationInformation.ApplicationExists -eq $false) {
                Write-Warning "Application: $azureApplicationName doesn't exist - use the parameter 'CreateApplication' to create it first"

                return
            }

            $appId = $azureApplicationInformation.AppId
        } else {
            $appId = $Script:CustomAppId
        }

        try {
            $authServers = Get-AuthServer -ErrorAction Stop
        } catch {
            Write-Warning "Unable to run the 'Get-AuthServer' cmdlet - Exception: $_"

            return
        }

        if ($authServers.Count -eq 0) {
            Write-Warning "We did not find an Auth Server - script can't continue"

            return
        }

        # Search for the AzureAD Auth Server object, new syntax is 'EvoSts - {Guid}'; old syntax is just 'EvoSTS'
        # Type must be AzureAD and Realm must be the Tenant Id
        $evoStsAuthServer = $authServers | Where-Object {
            (($_.Name -match "^EvoSts - [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") -or
            ($_.Name -match "EvoSTS")) -and
            $_.Type -eq "AzureAD" -and
            $_.Realm -match "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$" -and
            $_.Enabled
        }

        if ($evoStsAuthServer.Count -eq 0) {
            # No Auth Server object was found - we can't continue processing
            Write-Warning "We did not find an Auth Server which is valid for hybrid usage - script can't continue"

            return
        }

        if ($evoStsAuthServer.Count -gt 1) {
            # If there are multiple Auth Server objects, this indicates a multi-tenant configuration
            Write-Host "We found multiple Auth Server which are valid for hybrid use - trying to find the one for tenant $Script:TenantId"
            $evoStsAuthServer = $evoStsAuthServer | Where-Object { $_.Realm -eq $Script:TenantId }

            if ($evoStsAuthServer.Count -le 0) {
                Write-Warning "We did not find an Auth Server which is configured for your tenant"

                return
            }

            if ($evoStsAuthServer.Count -gt 1) {
                Write-Warning "More than one EvoSTS Auth Server was found that is configured for your tenant"
                Write-Warning "Re-run Hybrid Configuration Wizard (HCW) or manually  remove the duplicate EvoSTS Auth Server"

                return
            }
        }

        # We've detected a matching Auth Server object which we'll configure for dedicated Exchange hybrid application feature
        Write-Host "'$($evoStsAuthServer.Identity)' was identified as matching Auth Server"
        if (($evoStsAuthServer.DomainName).Count -ge 1) {
            Write-Verbose "Previous DomainName entries: $([System.String]::Join(", ", [array]$evoStsAuthServer.DomainName))"
        } else {
            Write-Verbose "Previous DomainName entries were empty"
        }

        # Search for the MicrosoftACS Auth Server object (it should be there if HCW was executed in this environment)
        $acsAuthServer = $authServers | Where-Object {
            $_.Type -eq "MicrosoftACS" -and
            $_.Realm -eq $Script:TenantId -and
            $_.DomainName.Count -ge 1 -and
            $_.Enabled
        }

        if ($acsAuthServer.Count -eq 1) {
            # If there is already an MicrosoftACS auth server object, we'll simply copy the values from the DomainName property to the EvoSTS auth server
            Write-Verbose "We've detected an existing MicrosoftACS Auth Server object from which we'll copy the DomainName information"
            Write-Verbose "$([System.String]::Join(", ", [array]$acsAuthServer.DomainName)) will be added to the EvoSTS Auth Server"

            $domainsToAdd = $acsAuthServer.DomainName.Domain
        } else {
            if ([System.String]::IsNullOrWhiteSpace($Script:RemoteRoutingDomain) -and
                ($domainList.Count -le 0)) {
                # We're ending up here in case that no domain was provided via RemoteRoutingDomain parameter and Graph API call didn't return anything
                Write-Warning "We couldn't find any domains assigned to your tenant, and no domain was provided using the RemoteRoutingDomain parameter"

                return
            }

            try {
                $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop

                if ($acceptedDomains.Count -le 0) {
                    Write-Warning "We couldn't find any accepted domain in your Exchange organization"

                    return
                }

                Write-Verbose "We found $($acceptedDomains.Count) accepted domains in this Exchange organization"

                $domainsToAdd = $Script:RemoteRoutingDomain

                if ([System.String]::IsNullOrWhiteSpace($Script:RemoteRoutingDomain)) {
                    # Filter out any domain that exists in both worlds - exclude the initial (onmicrosoft.com) domain
                    $domainsToAdd = $acceptedDomains.DomainName.Domain | Where-Object {
                        $domainList.Id -contains $_ -and
                        $domainList.IsInitial -eq $false
                    }

                    if ($domainsToAdd.Count -ge 1) {
                        Write-Verbose "We found $($domainsToAdd.Count) accepted domains that exist in on-premises and online organization"
                        Write-Verbose "Domains are: $([System.String]::Join(", ", $domainsToAdd))"
                    } else {
                        Write-Warning "We did not find any domain that exists in on-premises and online organization"

                        return
                    }
                }
            } catch {
                Write-Warning "Unable to run the 'Get-AcceptedDomain' cmdlet - Exception: $_"

                return
            }
        }

        # Configure the Auth Server object to use the newly created Application (client) ID - we override the existing DomainName values to avoid issues caused by misconfigured DomainName entries
        try {
            Set-AuthServer -Identity "$($evoStsAuthServer.Identity)" -ApplicationIdentifier "$appId" -DomainName $domainsToAdd -ErrorAction Stop
            Write-Host "Auth Server: $($evoStsAuthServer.Identity) was successfully configured to use the following App ID: $appId" -ForegroundColor Green
        } catch {
            $formattedDomainString = [System.String]::Join(",", $($domainsToAdd | ForEach-Object { "`"$_`"" }))

            Write-Warning "Unable to perform the Auth Server configuration - please run the following command from an EMS:"
            Write-Warning "`tSet-AuthServer -Identity `"$($evoStsAuthServer.Identity)`" -ApplicationIdentifier `"$appId`" -DomainName $formattedDomainString"
            Write-Verbose "We hit the following exception: $_"

            return
        }
    }
    #endregion

    #region ConfigureTargetSharingEpr
    if ($Script:ConfigureTargetSharingEpr) {
        # The script will continue in case that TargetSharingEpr can't be configured on OrgRel objects because it's not a hard requirement for making dedicated Exchange hybrid application feature in general work
        Write-Host "`r`nPerforming operation: ConfigureTargetSharingEpr" -ForegroundColor Cyan

        # Sort out any OrgRel objects, which doesn't fulfil the following requirements:
        # Enabled $true - TargetAutodiscoverEpr not $null / empty - TargetSharingEpr is $null / empty
        $organizationRelationships = Get-OrganizationRelationship | Where-Object {
            ($_.Enabled) -and
            (-not([System.String]::IsNullOrEmpty($_.TargetAutodiscoverEpr))) -and
            ([System.String]::IsNullOrEmpty($_.TargetSharingEpr))
        }

        if ($organizationRelationships.Count -ne 0) {
            Write-Verbose "$($organizationRelationships.Count) OrganizationRelationship object(s) found which is in scope of the following operation"

            foreach ($relationshipObject in $organizationRelationships) {
                Write-Host "`r`nProcessing OrganizationRelationship: $($relationshipObject.Identity)"
                Write-Verbose "Validating OrganizationRelationship: $($relationshipObject.Identity) - TargetAutodiscoverEpr: $($relationshipObject.TargetAutodiscoverEpr)"

                $matchingDomainName = $null
                $matchingSmtpRoutingDomainName = $null

                # Iterate through all Microsoft-owned domains and check if the TargetAutodiscoverEpr host name makes use of them
                # If it does, we assume that this OrgRel is between on-premises and online
                foreach ($msDomain in $Script:CustomMicrosoftDomains) {
                    Write-Verbose "Processing Microsoft domain: $msDomain"

                    try {
                        if ((($relationshipObject.TargetAutodiscoverEpr).ToString()).IndexOf($msDomain) -ne -1) {
                            # If the Microsoft domain is part of the TargetAutodiscoverEpr, we check if the DomainNames multi-valued property contains a initial cloud domain as we would prefer for the AutoD v2
                            Write-Verbose "Exchange Online AutoDiscover endpoint detected!"

                            foreach ($initialDomain in $initialCloudDomains) {
                                Write-Verbose "Processing initial cloud domain: $initialDomain"

                                # We use RegEx matching to match anything like contoso.onmicrosoft.com but exclude contoso.mail.onmicrosoft.com as this can't be used to run AutoD v2 calls
                                $matchingDomainName = $relationshipObject.DomainNames.Domain | Where-Object {
                                    $_ -match "^(?!.*\.mail\.).*\.$initialDomain"
                                } | Select-Object -First 1

                                # Find a SMTP routing domain that we could use for fallback in case that no other matching domain names were found
                                if ($matchingSmtpRoutingDomainName.Count -eq 0) {
                                    $matchingSmtpRoutingDomainName = $relationshipObject.DomainNames.Domain | Where-Object {
                                        $_ -match "^(?=.*\.mail\.).*\.$initialDomain"
                                    } | Select-Object -First 1
                                }

                                if ($matchingDomainName.Count -eq 1) {
                                    Write-Verbose "Matching domain name found: $matchingDomainName"

                                    break
                                }
                            }

                            # If we don't have a match to an initial cloud domain, use the first domain from the DomainNames multi-valued property that fulfills our requirements
                            if ($matchingDomainName.Count -ne 1) {
                                Write-Verbose "No matching initial cloud domain detected - fallback using the SMTP routing domain (if there is one)"

                                # If there is a SMTP routing domain in the list of domains names, use it and replace the .mail. part of it
                                if ($matchingSmtpRoutingDomainName.Count -eq 1) {
                                    Write-Verbose "Initiating fallback using the SMTP routing domain"

                                    try {
                                        $matchingDomainName = $matchingSmtpRoutingDomainName.Replace(".mail.", ".")
                                    } catch {
                                        Write-Warning "Processing SMTP routing domain failed - we can't update this OrganizationRelationship - Exception: $_"
                                    }
                                }

                                # If there is still no domain available that we can use for the AutoD v2 request, fallback to using the first non-Microsoft domain of the list
                                if ($matchingDomainName.Count -ne 1) {
                                    Write-Verbose "Still no usable domain was found - fallback to using the first domain of the list"

                                    # We exclude any domain here that contains a mail sub-domain - we do that to avoid taking something like contoso.mail.onmicrosoft.com into account
                                    # A sub-domain like mail.contoso.com is allowed and is safe to be used - we wan't to be extra careful here and therefore perform this check again
                                    $matchingDomainName = $relationshipObject.DomainNames | Where-Object {
                                        $_ -notmatch "\.mail\."
                                    } | Select-Object -First 1
                                }
                            }
                            break
                        }

                        Write-Verbose "Domain is not part of the TargetAutodiscoverEpr Url"
                    } catch {
                        Write-Warning "TargetAutodiscoverEpr validation failed - Exception: $_"

                        continue
                    }
                }

                # Validate that we have a matching domain - if we don't have one this could mean that the OrgRel is misconfigured
                # or that the previous logic has failed for what ever reason
                if ($matchingDomainName.Count -ne 1) {
                    Write-Verbose "OrganizationRelationship is not between Exchange Server and Exchange Online and will be skipped"
                    Write-Host "This OrganizationRelationship seems not to be related to Exchange Online and can't be updated by the script"

                    continue
                }

                Write-Verbose "Selected domain that will be used for AutoD v2 call is: $matchingDomainName"

                # Now, query the EWS endpoint by using AutoD v2 - we use an arbitration mailbox that exists in all tenants, regardless of the cloud or region
                $autoDiscoverInformation = Get-ProtocolEndpointViaAutoDv2 -SmtpAddress "$arbitrationMailbox@$matchingDomainName" -Protocol "EWS"

                # We can't continue if no information via AutoD v2 were returned
                if ([System.String]::IsNullOrEmpty($autoDiscoverInformation.Url)) {
                    Write-Warning "Unable to query EWS endpoint by using AutoDiscover for the following domain: $matchingDomainName"
                    Write-Warning "If the relationship is between Exchange Server and Exchange Online, run the following command and replace '<ExchangeOnlineEwsUrl>' with the associated Url:"
                    Write-Warning "`tSet-OrganizationRelationship -Identity `"$($relationshipObject.Identity)`" -TargetSharingEpr `"<ExchangeOnlineEwsUrl>`""

                    continue
                }

                if ($autoDiscoverInformation.ServerLocation -eq "Exchange Online") {
                    Write-Verbose "ServerLocation is Exchange Online"

                    $ewsUrl = $autoDiscoverInformation.Url

                    try {
                        # Set the TargetSharingEpr to ensure that AutoD v1 is no longer being used
                        Write-Verbose "Set-OrganizationRelationship will be executed for identity: $($relationshipObject.Identity) with TargetSharingEpr: $ewsUrl"

                        Set-OrganizationRelationship -Identity "$($relationshipObject.Identity)" -TargetSharingEpr $ewsUrl -ErrorAction Stop

                        Write-Host "TargetSharingEpr was successfully configured" -ForegroundColor Green
                    } catch {
                        Write-Warning "Unable to perform the TargetSharingEpr configuration - please run the following command via EMS:"
                        Write-Warning "`tSet-OrganizationRelationship -Identity `"$($relationshipObject.Identity)`" -TargetSharingEpr `"$ewsUrl`""

                        Write-Verbose "We hit the following exception: $_"
                    }

                    continue
                }

                Write-Verbose "EWS ServerLocation is not Exchange Online - TargetSharingEpr was therefore not configured"
            }
        }
    }
    #endregion

    #region EnableExchangeHybridApplicationOverride
    if ($Script:EnableExchangeHybridApplicationOverride) {
        Write-Host "`r`nPerforming operation: CreateSettingOverride" -ForegroundColor Cyan

        if ([System.String]::IsNullOrEmpty($Script:CustomAppId)) {
            if ($null -eq $testAzureApplicationPermissionReturn) {
                # We end up here in case that we don't have the application permission information from the previous CreateApplication call - we must query them
                # Run Get-AzureApplication again in case that it was not run before or in case that ApplicationExists was false in the previous run
                if ($null -eq $azureApplicationInformation -or
                    $azureApplicationInformation.ApplicationExists -eq $false) {
                    $azureApplicationInformation = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $azureApplicationName
                }

                # If we still don't have any value for the Azure Application, it means that the Graph API call has failed for whatever reason - we can't continue
                if ($null -eq $azureApplicationInformation) {
                    Write-Warning "Graph API call to validate the existence of the application has failed"

                    return
                }

                # We can't continue if the call was successful but no application was found
                if ($azureApplicationInformation.ApplicationExists -eq $false) {
                    Write-Warning "Unable to validate the application permission and tenant-wide admin consent - make sure that the application $azureApplicationName exists and is configured as expected"

                    return
                }

                $testAzureApplicationParams = $graphApiBaseParams + @{
                    AzureApplicationObject = $azureApplicationInformation
                    ResourceAppId          = $resourceAppId
                    ResourceAccessId       = $resourceAccessId
                    Type                   = "Role"
                }

                $testAzureApplicationPermissionReturn = Test-AzureApplicationPermission @testAzureApplicationParams
            }

            $adminConsentGiven = $testAzureApplicationPermissionReturn.PermissionsAsExpected -and $testAzureApplicationPermissionReturn.AdminConsentGranted
        } else {
            # We can't validate the admin consent in case that a custom app id is provided - therefore set this flag to true
            $adminConsentGiven = $true
        }

        # Ensure that the override is not created unless admin consent has been granted
        if ($adminConsentGiven -eq $false) {
            Write-Warning "Unable to create the Setting Override to enable the feature because tenant-wide admin consent has not yet been granted"

            return
        }

        # Check if the setting override already exists and if it doesn't, create the setting override to enable the feature run Get-ExchangeDiagnosticInfo first to avoid caching issues
        Get-ExchangeDiagnosticInfo -Process "Microsoft.Exchange.Directory.TopologyService" -Component "VariantConfiguration" -Argument "Refresh" | Out-Null
        $settingOverrides = Get-ExchangeSettingOverride -Server $env:COMPUTERNAME

        # Check if we have at least one setting override
        if (($null -ne $settingOverrides) -and
            ($settingOverrides.SimpleSettingOverrides.Count -gt 0)) {
            # Filter out the overrides which enable or disable the ExchangeOnpremAsThirdPartyAppId feature
            $3pOverrides = $settingOverrides.SimpleSettingOverrides | Where-Object {
                ($_.SectionName -eq "ExchangeOnpremAsThirdPartyAppId") -and
                ($_.ComponentName -eq "Global")
            }

            if ($null -ne $3pOverrides) {
                Write-Warning "The following Setting Override(s) already exist:"

                # If we find some, check whether they enable or disable the feature explicitly
                foreach ($o in $3pOverrides) {
                    if ($o.Parameters -eq "Enabled=true") {
                        Write-Host "`tSetting Override: $($o.Name) - Enables the dedicated Exchange hybrid application feature"
                    } elseif ($o.Parameters -eq "Enabled=false") {
                        Write-Host "`tSetting Override: $($o.Name) - Disables the dedicated Exchange hybrid application feature"
                    } else {
                        Write-Host "`tSetting Override: $($o.Name) - Contains an unexpected Parameters value: $($o.Parameters)"
                    }

                    $3pSettingOverridesObject.Add($o)
                }

                Write-Warning "Run the following command if you want to remove the existing Setting Override(s):"
                Write-Warning "`tGet-SettingOverride | Where-Object {`$_.ComponentName -eq `"Global`" -and `$_.SectionName -eq `"ExchangeOnpremAsThirdPartyAppId`"} | Remove-SettingOverride -Confirm:`$false"

                return
            }
        }

        # If no setting overrides, which control the dedicated Exchange hybrid application feature, exists we'll create a new global override, otherwise, do nothing and display the name of the existing overrides
        if ($3pSettingOverridesObject.Count -eq 0) {
            try {
                $newSettingOverrideParams = @{
                    Name       = "EnableExchangeHybrid3PAppFeature"
                    Component  = "Global"
                    Section    = "ExchangeOnpremAsThirdPartyAppId"
                    Parameters = "Enabled=true"
                    Reason     = "Created by $($script:MyInvocation.MyCommand.Name) on $(Get-Date)"
                }
                # Execute the commands to create the new setting override and to refresh the variant configuration
                New-SettingOverride @newSettingOverrideParams -ErrorAction Stop | Out-Null
                Get-ExchangeDiagnosticInfo -Process "Microsoft.Exchange.Directory.TopologyService" -Component "VariantConfiguration" -Argument "Refresh" | Out-Null

                Write-Host "Setting Override to enable the dedicated Exchange hybrid application feature was successfully created" -ForegroundColor Green
            } catch {
                Write-Warning "Unable to create the new Setting Override - Exception: $_"

                return
            }
        }
    }
    #endregion

    #region ResetFirstPartyServicePrincipalKeyCredentials
    if ($Script:ResetFirstPartyServicePrincipalKeyCredentials) {
        Write-Host "`r`nPerforming operation: ResetFirstPartyServicePrincipalKeyCredentials" -ForegroundColor Cyan
        $reset1PKeyCredentialsForegroundColor = "Yellow"

        $removeCertificateFromAzureServicePrincipalParams = $graphApiBaseParams + @{
            WellKnownApplicationId = $resourceAppId
            RemoveAllCertificates  = $true
        }

        # We need to use different parameters when calling Remove-CertificateFromAzureServicePrincipal if a thumbprint was provided
        if (-not([System.String]::IsNullOrEmpty($Script:CertificateInformation))) {
            $removeCertificateFromAzureServicePrincipalParams = $graphApiBaseParams + @{
                WellKnownApplicationId = $resourceAppId
                CertificateThumbprint  = $Script:CertificateInformation
            }
        }

        $1pCleanUpReturn = Remove-CertificateFromAzureServicePrincipal @removeCertificateFromAzureServicePrincipalParams

        if ($1pCleanUpReturn.Successful) {
            $reset1PKeyCredentialsForegroundColor = "Green"

            Write-Host "The Service Principal for the first-party application was processed successfully" -ForegroundColor $reset1PKeyCredentialsForegroundColor
        }

        if ($1pCleanUpReturn.Successful -eq $false) {
            Write-Host "An error occurred while updating the Service Principal for the first-party application" -ForegroundColor $reset1PKeyCredentialsForegroundColor
        }

        if ($null -ne $1pCleanUpReturn.Message) {
            Write-Host $1pCleanUpReturn.Message -ForegroundColor $reset1PKeyCredentialsForegroundColor
        }
    }
    #endregion
} end {
    if ($Script:EnableExchangeHybridApplicationOverride) {
        Write-Host ""
        Write-Warning "******************************************************************************************************"
        Write-Warning "* After confirming the dedicated hybrid app works, run the script in service principal clean-up mode *"
        Write-Warning "* https://aka.ms/ConfigureExchangeHybridApplication-Docs#service-principal-clean-up-mode             *"
        Write-Warning "******************************************************************************************************"
    }

    Write-Host ""
    Write-Host "Do you have feedback regarding the script? Please email ExchOnPremFeedback@microsoft.com." -ForegroundColor Green
    Write-Host ""
}
