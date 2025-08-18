# ConfigureExchangeHybridApplication

Download the latest release: [ConfigureExchangeHybridApplication.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ConfigureExchangeHybridApplication.ps1)

This documentation focuses on different scenarios and how they can be configured using this script. More information about the dedicated Exchange hybrid application and prerequisites that must be fulfilled before the script can be used can be found in the [Deploy dedicated Exchange hybrid app](https://aka.ms/ConfigureExchangeHybridApplication-Docs) documentation.

## How to use the script

The script must be run from PowerShell version 5 or greater. Running the script from PowerShell Core is not supported.

This section contains examples of some of the most common scenarios in which the script can be used. These examples aim to provide clear guidance on how to configure various settings and features using the script, ensuring that administrators can effectively apply it to their specific needs.

## Logging

If you encounter issues while using the script, check the debug log generated during execution. The log files are stored in the same directory as the script and follow this naming format:
`ConfigureExchangeHybridApplication.ps1-Debug_<timestamp>.txt`

### Examples

The script will create the application in Microsoft Entra ID, upload the current Auth Certificate, and if configured, the new next Auth Certificate. It will also configure the Auth Server object and create a global setting override to enable the feature. Additionally, the script will validate the availability of the Auth Certificates as `keyCredentials` of the `Office 365 Exchange Online` first-party application's Service Principal and attempt to remove them if necessary.

```powershell
.\ConfigureExchangeHybridApplication.ps1 -FullyConfigureExchangeHybridApplication
```

By default, the script runs against the `Microsoft 365 Worldwide` cloud. If your Microsoft 365 tenant is in a different cloud, use the AzureEnvironment parameter. In the following example, the application is created in the `Microsoft 365 operated by 21Vianet` cloud:

```powershell
.\ConfigureExchangeHybridApplication.ps1 -FullyConfigureExchangeHybridApplication -AzureEnvironment "ChinaCloud"
```

The script will create the application in Microsoft Entra ID and upload the provided Auth Certificate to the newly created application. It will also validate if the Auth Certificates are available as `keyCredentials` of the` Office 365 Exchange Online` first-party application's Service Principal and attempt to remove them if necessary. Use this syntax if your Exchange Server lacks outbound connectivity to Microsoft Graph API and you need to run the script on a machine with Microsoft Graph API connectivity. First, export the Auth Certificate (ensure **NOT TO** export the private key) and transfer it to the machine where the script will be executed.

```powershell
.\ConfigureExchangeHybridApplication.ps1 -CreateApplication -UpdateCertificate -CertificateMethod "File" -CertificateInformation "c:\temp\certificate.cer"
```

The script will configure the Auth Server object and enable the dedicated Exchange hybrid application without creating the application in Microsoft Entra ID or uploading the Auth Certificate. Instead, it uses the provided App ID without verifying its correctness, as it does not perform any Graph API calls. This syntax is suitable for environments where the application was already created on a different non-Exchange Server machine, and the Exchange Server has no outgoing connection to Microsoft Graph API.

```powershell
.\ConfigureExchangeHybridApplication.ps1 -ConfigureAuthServer -EnableExchangeHybridApplicationOverride -CustomAppId <appId> -TenantId <tenantId> -RemoteRoutingDomain <targetDeliveryDomain>
```

The script will upload the current Auth Certificate and, if configured, the new next Auth Certificate to the application in Microsoft Entra ID. This syntax is useful if the Auth Certificate has been renewed. Additionally, the script will validate the availability of the Auth Certificates as `keyCredentials` of the `Office 365 Exchange Online` first-party application's Service Principal and attempt to remove them if necessary.

```powershell
.\ConfigureExchangeHybridApplication.ps1 -UpdateCertificate
```

The script will delete all certificates of the `Office 365 Exchange Online` first-party application's Service Principal. This action ensures that any outdated or unnecessary certificates are removed, maintaining the security and integrity of the application. Use this syntax when you need to clean up the `keyCredentials` of the first-party Service Principal.

```powershell
.\ConfigureExchangeHybridApplication.ps1 -ResetFirstPartyServicePrincipalKeyCredentials
```

The script will remove the certificate with thumbprint `1234567890ABCDEF1234567890ABCDEF12345678` from the `Office 365 Exchange Online` first-party application's Service Principal. Additionally, it will remove all certificates that have already expired. This ensures that only valid and necessary certificates are retained, maintaining the security and integrity of the application.

```powershell
.\ConfigureExchangeHybridApplication.ps1 -ResetFirstPartyServicePrincipalKeyCredentials -CertificateInformation "1234567890ABCDEF1234567890ABCDEF12345678"
```

The script will delete the application in Microsoft Entra ID without undoing any changes to Auth Server objects or removing the Setting Override. This ensures that the application is removed while preserving the existing configurations and overrides. This could be useful if, for example, the application in Entra ID was misconfigured and you want to delete and re-create it.

```powershell
.\ConfigureExchangeHybridApplication.ps1 -DeleteApplication
```

## Parameters

Parameter | Description
----------|------------
FullyConfigureExchangeHybridApplication | Use this switch parameter fully configure the dedicated Exchange hybrid application.
CreateApplication | Use this switch parameter to create the application in Microsoft Entra ID. This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
DeleteApplication | Use this switch parameter to delete an existing application in Microsoft Entra ID. Note that the script will only delete the application. The script doesn't undo any changes, e.g. to Auth Server objects and doesn't remove the Setting Override. This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
UpdateCertificate | Use this switch parameter to upload the Auth Certificate to the application in Microsoft Entra ID. This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
ConfigureAuthServer | Use this switch parameter to configure the Auth Server object. The script will add the appId of the newly created application to the `EvoSTS` or `EvoSTS - {Guid}` Auth Server object. This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
CustomAppId | Use this parameter to provide the Application (client) ID (also known as appId) of a custom application in Microsoft Entra ID. In most cases this parameter does not need to be used.
TenantId | Use this parameter to provide the ID of your tenant in Microsoft Entra ID. In most cases this parameter does not need to be used.
RemoteRoutingDomain | Use this parameter to provide the remote routing domain of your tenant in Microsoft Entra ID. In most cases this parameter does not need to be used.
ConfigureTargetSharingEpr | Use this switch parameter to configure the Organization Relationships between Exchange Server and Exchange Online tenants.
EnableExchangeHybridApplicationOverride | Use this switch parameter to create the Setting Override which enables the dedicated Exchange hybrid application. This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
ResetFirstPartyServicePrincipalKeyCredentials | Use this switch parameter to remove a specific or all available Key Credentials from the Service Principal of the `Office 365 Exchange Online` application. By default, all existing Key Credentials will be removed. If you provide the thumbprint of a certificate by using the `CertificateInformation` parameter, only the specified and all expired certificates will be removed.
AzureEnvironment | Use this parameter to run the script against non-Global cloud environments, for example, `Microsoft 365 operated by 21Vianet`. This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone. Values that can be used with this parameter are: `Global`, `USGovernmentL4`, `USGovernmentL5`, `ChinaCloud`. The default value is: `Global`
CustomClientId | This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
CustomGraphApiUri | This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
CustomEntraAuthUri | This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
CustomInitialCloudDomains | This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
CustomMicrosoftDomains | This parameter is reserved for internal Microsoft use. Do not use it unless explicitly advised by Microsoft.
CertificateMethod | Use this parameter to specify the method which should be used by the script to search for the Auth Certificate. By default, the script will try to export the current, and if already set, the new next Auth Certificate and will upload them to the application in Microsoft Entra ID. This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone. Values that can be used with this parameter are: `Thumbprint`, `File`, `Automated`. The default value is: `Automated`
CertificateInformation | Use this parameter to provide the thumbprint of the certificate that you want the script to export and upload or the file path to the certificate file, for example, `c:\temp\certificate.cer`. You don't need to use this parameter if `CertificateMethod` is set to `Automated`. If you provide the thumbprint, the script searches and exports the certificate with the thumbprint provided from the local machines certificate store. If you provide the file path, the script uploads the certificate, which was specified. This parameter allows you to run granular configurations. Note that some of the tasks depend on others and can't be run alone.
ScriptUpdateOnly | This optional parameter allows you to only update the script without performing any other actions.
SkipVersionCheck | This optional parameter allows you to skip the automatic version check and script update.
