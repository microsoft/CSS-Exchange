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

    [Parameter(Mandatory = $false, ParameterSetName = "ExchangeOrgGUID")]
    [Parameter(Mandatory = $false, ParameterSetName = "FirstPartyKeyCredentialsCleanup")]
    [ValidatePattern("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
    [string]$ExchangeOrgGUID,

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


function Confirm-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )

    return $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
}

<#
.SYNOPSIS
    Returns True if we are running inside Exchange Management Shell, and False otherwise.
#>
function Confirm-ExchangeManagementShell {
    $cmd = Get-Command "Get-EventLogLevel" -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        return $false
    }

    $level = Get-EventLogLevel | Select-Object -First 1
    if (($level.GetType().Name -eq "EventCategoryObject") -or
        (($level.GetType().Name -eq "PSObject") -and
        ($null -ne $level.SerializationData))) {
        return $true
    }

    return $false
}

<#
    .SYNOPSIS
    Exports a given certificate to the memory of the computer.

    .DESCRIPTION
    This function takes a certificate object of type [System.Security.Cryptography.X509Certificates.X509Certificate2] and exports it to the memory of the computer.
    It creates a memory stream to hold the certificate data and returns a custom object containing the certificate's thumbprint, Base64-encoded data, and raw bytes.

    .PARAMETER Certificate
    The certificate object to be exported.

    .NOTES
    If the provided certificate is null, the function outputs a message indicating that a valid certificate object must be provided and then exits.
    If an exception occurs during the export process, it outputs an error message with the exception details.
    The memory stream is disposed of to free up resources.

    .EXAMPLE
    $cert = Get-Item Cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678
    $certObject = Export-CertificateToMemory -Certificate $cert
#>
function Export-CertificateToMemory {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if ($null -eq $Certificate) {
        Write-Verbose "The provided certificate object is null. Please ensure you pass a valid X509Certificate2 object to the function"
        return
    }

    $memoryStream = New-Object System.IO.MemoryStream

    try {
        $certificateBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert, $memoryStream)

        $certificateObject = [PSCustomObject]@{
            CertificateThumbprint = $Certificate.thumbprint
            CertificateBase64     = [Convert]::ToBase64String($certificateBytes)
            CertificateBytes      = $certificateBytes
        }
    } catch {
        Write-Verbose "An exception occurred during the export process: $_"
    } finally {
        $memoryStream.Dispose()
    }

    return $certificateObject
}

<#
    This file is designed to inline code that we use to start the scripts and handle the logging.
#>


function Write-Host {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Proper handling of write host with colors')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [object]$Object,
        [switch]$NoNewLine,
        [string]$ForegroundColor
    )
    process {
        $consoleHost = $host.Name -eq "ConsoleHost"

        if ($null -ne $Script:WriteHostManipulateObjectAction) {
            $Object = & $Script:WriteHostManipulateObjectAction $Object
        }

        $params = @{
            Object    = $Object
            NoNewLine = $NoNewLine
        }

        if ([string]::IsNullOrEmpty($ForegroundColor)) {
            if ($null -ne $host.UI.RawUI.ForegroundColor -and
                $consoleHost) {
                $params.Add("ForegroundColor", $host.UI.RawUI.ForegroundColor)
            }
        } elseif ($ForegroundColor -eq "Yellow" -and
            $consoleHost -and
            $null -ne $host.PrivateData.WarningForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.WarningForegroundColor)
        } elseif ($ForegroundColor -eq "Red" -and
            $consoleHost -and
            $null -ne $host.PrivateData.ErrorForegroundColor) {
            $params.Add("ForegroundColor", $host.PrivateData.ErrorForegroundColor)
        } else {
            $params.Add("ForegroundColor", $ForegroundColor)
        }

        Microsoft.PowerShell.Utility\Write-Host @params

        if ($null -ne $Script:WriteHostDebugAction -and
            $null -ne $Object) {
            &$Script:WriteHostDebugAction $Object
        }
    }
}

function SetProperForegroundColor {
    $Script:OriginalConsoleForegroundColor = $host.UI.RawUI.ForegroundColor

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.WarningForegroundColor) {
        Write-Verbose "Foreground Color matches warning's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }

    if ($Host.UI.RawUI.ForegroundColor -eq $Host.PrivateData.ErrorForegroundColor) {
        Write-Verbose "Foreground Color matches error's color"

        if ($Host.UI.RawUI.ForegroundColor -ne "Gray") {
            $Host.UI.RawUI.ForegroundColor = "Gray"
        }
    }
}

function RevertProperForegroundColor {
    $Host.UI.RawUI.ForegroundColor = $Script:OriginalConsoleForegroundColor
}

function SetWriteHostAction ($DebugAction) {
    $Script:WriteHostDebugAction = $DebugAction
}

function SetWriteHostManipulateObjectAction ($ManipulateObject) {
    $Script:WriteHostManipulateObjectAction = $ManipulateObject
}

function Write-Progress {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Warning from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Activity = "",

        [switch]$Completed,

        [string]$CurrentOperation,

        [Parameter(Position = 2)]
        [int]$Id,

        [int]$ParentId = -1,

        [int]$PercentComplete,

        [int]$SecondsRemaining = -1,

        [int]$SourceId,

        [Parameter(Position = 1)]
        [string]$Status
    )

    process {
        $params = @{
            Activity         = $Activity
            Completed        = $Completed
            CurrentOperation = $CurrentOperation
            Id               = $Id
            ParentId         = $ParentId
            PercentComplete  = $PercentComplete
            SecondsRemaining = $SecondsRemaining
            SourceId         = $SourceId
        }

        if (-not([string]::IsNullOrEmpty($Status))) {
            $params.Add("Status", $Status)
        }

        Microsoft.PowerShell.Utility\Write-Progress @params

        $message = "Write-Progress Activity: '$Activity' Completed: $Completed CurrentOperation: '$CurrentOperation' Id: $Id" +
        " ParentId: $ParentId PercentComplete: $PercentComplete SecondsRemaining: $SecondsRemaining SourceId: $SourceId Status: '$Status'"

        if ($null -ne $Script:WriteProgressDebugAction) {
            & $Script:WriteProgressDebugAction $message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteProgressDebugAction) {
            & $Script:WriteRemoteProgressDebugAction $message
        }
    }
}

function SetWriteProgressAction ($DebugAction) {
    $Script:WriteProgressDebugAction = $DebugAction
}

function SetWriteRemoteProgressAction ($DebugAction) {
    $Script:WriteRemoteProgressDebugAction = $DebugAction
}

function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {

        if ($null -ne $Script:WriteVerboseManipulateMessageAction) {
            $Message = & $Script:WriteVerboseManipulateMessageAction $Message
        }

        if ($PSSenderInfo -and
            $null -ne $Script:WriteVerboseRemoteManipulateMessageAction) {
            $Message = & $Script:WriteVerboseRemoteManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Verbose $Message

        if ($null -ne $Script:WriteVerboseDebugAction) {
            & $Script:WriteVerboseDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteVerboseDebugAction) {
            & $Script:WriteRemoteVerboseDebugAction $Message
        }
    }
}

function SetWriteVerboseAction ($DebugAction) {
    $Script:WriteVerboseDebugAction = $DebugAction
}

function SetWriteRemoteVerboseAction ($DebugAction) {
    $Script:WriteRemoteVerboseDebugAction = $DebugAction
}

function SetWriteVerboseManipulateMessageAction ($DebugAction) {
    $Script:WriteVerboseManipulateMessageAction = $DebugAction
}

function SetWriteVerboseRemoteManipulateMessageAction ($DebugAction) {
    $Script:WriteVerboseRemoteManipulateMessageAction = $DebugAction
}

function Write-Warning {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Warning from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )
    process {

        if ($null -ne $Script:WriteWarningManipulateMessageAction) {
            $Message = & $Script:WriteWarningManipulateMessageAction $Message
        }

        Microsoft.PowerShell.Utility\Write-Warning $Message

        # Add WARNING to beginning of the message by default.
        $Message = "WARNING: $Message"

        if ($null -ne $Script:WriteWarningDebugAction) {
            & $Script:WriteWarningDebugAction $Message
        }

        # $PSSenderInfo is set when in a remote context
        if ($PSSenderInfo -and
            $null -ne $Script:WriteRemoteWarningDebugAction) {
            & $Script:WriteRemoteWarningDebugAction $Message
        }
    }
}

function SetWriteWarningAction ($DebugAction) {
    $Script:WriteWarningDebugAction = $DebugAction
}

function SetWriteRemoteWarningAction ($DebugAction) {
    $Script:WriteRemoteWarningDebugAction = $DebugAction
}

function SetWriteWarningManipulateMessageAction ($DebugAction) {
    $Script:WriteWarningManipulateMessageAction = $DebugAction
}

function Get-NewLoggerInstance {
    [CmdletBinding()]
    param(
        [string]$LogDirectory = (Get-Location).Path,

        [ValidateNotNullOrEmpty()]
        [string]$LogName = "Script_Logging",

        [bool]$AppendDateTime = $true,

        [bool]$AppendDateTimeToFileName = $true,

        [int]$MaxFileSizeMB = 10,

        [int]$CheckSizeIntervalMinutes = 10,

        [int]$NumberOfLogsToKeep = 10
    )

    $fileName = if ($AppendDateTimeToFileName) { "{0}_{1}.txt" -f $LogName, ((Get-Date).ToString('yyyyMMddHHmmss')) } else { "$LogName.txt" }
    $fullFilePath = [System.IO.Path]::Combine($LogDirectory, $fileName)

    if (-not (Test-Path $LogDirectory)) {
        try {
            New-Item -ItemType Directory -Path $LogDirectory -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to create Log Directory: $LogDirectory. Inner Exception: $_"
        }
    }

    return [PSCustomObject]@{
        FullPath                 = $fullFilePath
        AppendDateTime           = $AppendDateTime
        MaxFileSizeMB            = $MaxFileSizeMB
        CheckSizeIntervalMinutes = $CheckSizeIntervalMinutes
        NumberOfLogsToKeep       = $NumberOfLogsToKeep
        BaseInstanceFileName     = $fileName.Replace(".txt", "")
        Instance                 = 1
        NextFileCheckTime        = ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
        PreventLogCleanup        = $false
        LoggerDisabled           = $false
    } | Write-LoggerInstance -Object "Starting Logger Instance $(Get-Date)"
}

function Write-LoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance,

        [Parameter(Mandatory = $true, Position = 1)]
        [object]$Object
    )
    process {
        if ($LoggerInstance.LoggerDisabled) { return }

        if ($LoggerInstance.AppendDateTime -and
            $Object.GetType().Name -eq "string") {
            $Object = "[$([System.DateTime]::Now)] : $Object"
        }

        # Doing WhatIf:$false to support -WhatIf in main scripts but still log the information
        $Object | Out-File $LoggerInstance.FullPath -Append -WhatIf:$false

        #Upkeep of the logger information
        if ($LoggerInstance.NextFileCheckTime -gt [System.DateTime]::Now) {
            return
        }

        #Set next update time to avoid issues so we can log things
        $LoggerInstance.NextFileCheckTime = ([System.DateTime]::Now).AddMinutes($LoggerInstance.CheckSizeIntervalMinutes)
        $item = Get-ChildItem $LoggerInstance.FullPath

        if (($item.Length / 1MB) -gt $LoggerInstance.MaxFileSizeMB) {
            $LoggerInstance | Write-LoggerInstance -Object "Max file size reached rolling over" | Out-Null
            $directory = [System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)
            $fileName = "$($LoggerInstance.BaseInstanceFileName)-$($LoggerInstance.Instance).txt"
            $LoggerInstance.Instance++
            $LoggerInstance.FullPath = [System.IO.Path]::Combine($directory, $fileName)

            $items = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*"

            if ($items.Count -gt $LoggerInstance.NumberOfLogsToKeep) {
                $item = $items | Sort-Object LastWriteTime | Select-Object -First 1
                $LoggerInstance | Write-LoggerInstance "Removing Log File $($item.FullName)" | Out-Null
                $item | Remove-Item -Force
            }
        }
    }
    end {
        return $LoggerInstance
    }
}

function Invoke-LoggerInstanceCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance
    )
    process {
        if ($LoggerInstance.LoggerDisabled -or
            $LoggerInstance.PreventLogCleanup) {
            return
        }

        Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*" |
            Remove-Item -Force
    }
}

function Write-DebugLog ($Message) {
    $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $Message
}

function Write-HostLogAndDebugLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
    Write-DebugLog $Message
}

$Script:DebugLogger = Get-NewLoggerInstance -LogName "$($script:MyInvocation.MyCommand.Name)-Debug"

SetWriteVerboseAction ${Function:Write-DebugLog}
SetWriteProgressAction ${Function:Write-DebugLog}
SetWriteWarningAction ${Function:Write-DebugLog}

# Dual Logging is for when you have a secondary file designed for debug logic and one that is simplified for everything that was displayed to the screen.
Write-Verbose "Dual Logging $(if(-not ($Script:DualLoggingEnabled)){ "NOT "})Enabled."
if ($Script:DualLoggingEnabled) {
    $params = @{
        LogName                  = ([System.IO.Path]::GetFileNameWithoutExtension($Script:DebugLogger.FullPath).Replace("-Debug", ""))
        AppendDateTime           = $false
        AppendDateTimeToFileName = $false
    }
    $Script:Logger = Get-NewLoggerInstance @params
    SetWriteHostAction ${Function:Write-HostLogAndDebugLog}
} else {
    SetWriteHostAction ${Function:Write-DebugLog}
}



function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}
function Get-ExchangeDiagnosticInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$Process,

        [Parameter(Mandatory = $true)]
        [string]$Component,

        [string]$Argument,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    process {
        try {
            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $params = @{
                Process     = $Process
                Component   = $Component
                Server      = $Server
                ErrorAction = "Stop"
            }

            if (-not ([string]::IsNullOrEmpty($Argument))) {
                $params.Add("Argument", $Argument)
            }

            return (Get-ExchangeDiagnosticInfo @params)
        } catch {
            Write-Verbose "Failed to execute $($MyInvocation.MyCommand). Inner Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
}

function Get-ExchangeSettingOverride {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $updatedTime = [DateTime]::MinValue
        $settingOverrides = $null
        $simpleSettingOverrides = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        try {
            $params = @{
                Process             = "Microsoft.Exchange.Directory.TopologyService"
                Component           = "VariantConfiguration"
                Argument            = "Overrides"
                Server              = $Server
                CatchActionFunction = $CatchActionFunction
            }
            $diagnosticInfo = Get-ExchangeDiagnosticInformation @params

            if ($null -ne $diagnosticInfo) {
                Write-Verbose "Successfully got the Exchange Diagnostic Information"
                $xml = [xml]$diagnosticInfo.Result
                $overrides = $xml.Diagnostics.Components.VariantConfiguration.Overrides
                $updatedTime = $overrides.Updated
                $settingOverrides = $overrides.SettingOverride

                foreach ($override in $settingOverrides) {
                    Write-Verbose "Working on $($override.Name)"
                    $simpleSettingOverrides.Add([PSCustomObject]@{
                            Name          = $override.Name
                            ModifiedBy    = $override.ModifiedBy
                            Reason        = $override.Reason
                            ComponentName = $override.ComponentName
                            SectionName   = $override.SectionName
                            Status        = $override.Status
                            Parameters    = $override.Parameters.Parameter
                        })
                }
            } else {
                Write-Verbose "Failed to get Exchange Diagnostic Information"
            }
        } catch {
            Write-Verbose "Failed to get the Exchange setting override. Inner Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        return [PSCustomObject]@{
            Server                 = $Server
            LastUpdated            = $updatedTime
            SettingOverrides       = $settingOverrides
            SimpleSettingOverrides = $simpleSettingOverrides
        }
    }
}

function Get-PSSessionDetails {
    [CmdletBinding()]
    param()

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    # cSpell:disable
    Write-Verbose "============= PowerShell Information ==========="
    Write-Verbose "Version: $($PSVersionTable.PSVersion)"

    try {
        $modulesLoaded = Get-Module -ErrorAction Stop

        Write-Verbose "Module(s) Loaded:"
        foreach ($m in $modulesLoaded) {
            Write-Verbose "Name: $($m.Name) - Type: $($m.ModuleType)"
        }
    } catch {
        Write-Verbose "Exception: $_"
    }

    try {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        Write-Verbose "Is Elevated? $($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    } catch {
        Write-Verbose "Exception: $_"
    }

    Write-Verbose "Language Mode: $($ExecutionContext.SessionState.LanguageMode)"

    Write-Verbose "============= User Information ================="
    Write-Verbose "User: $env:USERNAME"
    Write-Verbose "Domain Name: $env:USERDNSDOMAIN"

    Write-Verbose "============= Computer Information ============="
    Write-Verbose "NetBIOS Name: $env:COMPUTERNAME"
    Write-Verbose "FQDN: $([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)"

    try {
        $osLanguageInformation = Get-WinSystemLocale -ErrorAction Stop
        Write-Verbose "OS Language:"
        Write-Verbose "Name: $($osLanguageInformation.Name) - Display Name: $($osLanguageInformation.DisplayName) - LCID: $($osLanguageInformation.LCID)"
    } catch {
        Write-Verbose "Exception: $_"
    }

    try {
        $timeZoneInformation = Get-TimeZone -ErrorAction Stop
        Write-Verbose "Time Zone:"
        Write-Verbose "Id: $($timeZoneInformation.Id) - Display Name: $($timeZoneInformation.DisplayName) - DST supported? $($timeZoneInformation.SupportsDaylightSavingTime)"
    } catch {
        Write-Verbose "Exception: $_"
    }

    Write-Verbose "================================================"
    # cSpell:enable
}



function Confirm-ProxyServer {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TargetUri
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    try {
        $proxyObject = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($TargetUri)
        if ($TargetUri -ne $proxyObject.OriginalString) {
            Write-Verbose "Proxy server configuration detected"
            Write-Verbose $proxyObject.OriginalString
            return $true
        } else {
            Write-Verbose "No proxy server configuration detected"
            return $false
        }
    } catch {
        Write-Verbose "Unable to check for proxy server configuration"
        return $false
    }
}

function WriteErrorInformationBase {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0],
        [ValidateSet("Write-Host", "Write-Verbose")]
        [string]$Cmdlet
    )

    if ($null -ne $CurrentError.OriginInfo) {
        & $Cmdlet "Error Origin Info: $($CurrentError.OriginInfo.ToString())"
    }

    & $Cmdlet "$($CurrentError.CategoryInfo.Activity) : $($CurrentError.ToString())"

    if ($null -ne $CurrentError.Exception -and
        $null -ne $CurrentError.Exception.StackTrace) {
        & $Cmdlet "Inner Exception: $($CurrentError.Exception.StackTrace)"
    } elseif ($null -ne $CurrentError.Exception) {
        & $Cmdlet "Inner Exception: $($CurrentError.Exception)"
    }

    if ($null -ne $CurrentError.InvocationInfo.PositionMessage) {
        & $Cmdlet "Position Message: $($CurrentError.InvocationInfo.PositionMessage)"
    }

    if ($null -ne $CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage) {
        & $Cmdlet "Remote Position Message: $($CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage)"
    }

    if ($null -ne $CurrentError.ScriptStackTrace) {
        & $Cmdlet "Script Stack: $($CurrentError.ScriptStackTrace)"
    }
}

function Write-VerboseErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Verbose"
}

function Write-HostErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    WriteErrorInformationBase $CurrentError "Write-Host"
}

function Invoke-WebRequestWithProxyDetection {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [string]
        $Uri,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [switch]
        $UseBasicParsing,

        [Parameter(Mandatory = $true, ParameterSetName = "ParametersObject")]
        [hashtable]
        $ParametersObject,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [string]
        $OutFile
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    if ([System.String]::IsNullOrEmpty($Uri)) {
        $Uri = $ParametersObject.Uri
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Confirm-ProxyServer -TargetUri $Uri) {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }

    if ($null -eq $ParametersObject) {
        $params = @{
            Uri     = $Uri
            OutFile = $OutFile
        }

        if ($UseBasicParsing) {
            $params.UseBasicParsing = $true
        }
    } else {
        $params = $ParametersObject
    }

    try {
        Invoke-WebRequest @params
    } catch {
        if($Error[0].exception.message -like "*403*") {
            Write-Host "403 Forbidden indicates that you do not have enough permissions" -ForegroundColor Yellow
        }
        Write-VerboseErrorInformation
    }
}

function Get-ProtocolEndpointViaAutoDv2 {
    [CmdletBinding(DefaultParameterSetName = "EXO")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "OnPrem")]
        [Parameter(Mandatory = $true, ParameterSetName = "EXO")]
        [ValidatePattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")]
        [string]$SmtpAddress,

        [Parameter(Mandatory = $true, ParameterSetName = "OnPrem")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^(?!http:\/\/|https:\/\/).*(?<!\/)$")]
        [string]$Url,

        [Parameter(Mandatory = $true, ParameterSetName = "OnPrem")]
        [Parameter(Mandatory = $true, ParameterSetName = "EXO")]
        [ValidateSet("EWS", "REST", "ActiveSync", "AutodiscoverV1")]
        [string]$Protocol
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        # AutoDiscover v2 automatically redirect calls to the right cloud - this URL works therefore for all clouds
        $baseUrl = "outlook.office365.com"

        if ($PSCmdlet.ParameterSetName -eq "OnPrem") {
            $baseUrl = $Url
        }

        # The 'ServerLocation' parameter doesn't exist in Exchange Server - it will be ignored by the server and no location will be returned
        $autoDiscoverV2Endpoint = "https://{0}/autodiscover/autodiscover.json/v1.0/{1}?Protocol={2}&ServerLocation=true" -f $baseUrl, $SmtpAddress, $Protocol

        Write-Verbose "Final AutoDiscover URL is: $autoDiscoverV2Endpoint"
    } process {
        $autoDiscoverV2Response = Invoke-WebRequestWithProxyDetection -Uri $autoDiscoverV2Endpoint -UseBasicParsing
        $headers = $autoDiscoverV2Response.Headers

        Write-Verbose "Request: $($headers.'request-id') Date: $($headers.Date) Status: $($autoDiscoverV2Response.StatusCode)"

        if ($null -eq $autoDiscoverV2Response -or
            [System.String]::IsNullOrEmpty($autoDiscoverV2Response.StatusCode) -or
            $autoDiscoverV2Response.StatusCode -ne 200) {

            Write-Verbose "AutoDiscover call failed - this could be caused by using an invalid smtp address or due to network or service issues"
            return
        }

        Write-Verbose "AutoDiscover request successful"

        $content = $autoDiscoverV2Response.Content | ConvertFrom-Json
    } end {
        return [PSCustomObject]@{
            Protocol       = $content.Protocol
            Url            = $content.Url
            ServerLocation = $content.ServerLocation
        }
    }
}

function Show-Disclaimer {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [ValidateNotNullOrEmpty()]
        [string]$Target,
        [ValidateNotNullOrEmpty()]
        [string]$Operation
    )

    if ($PSCmdlet.ShouldProcess($Message, $Target, $Operation) -or
        $WhatIfPreference) {
        return
    } else {
        exit
    }
}


function Get-ExchangeContainer {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param ()

    $rootDSE = [ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
    $exchangeContainerPath = ("CN=Microsoft Exchange,CN=Services," + $rootDSE.configurationNamingContext)
    $exchangeContainer = [ADSI]("LDAP://" + $exchangeContainerPath)
    Write-Verbose "Exchange Container Path: $($exchangeContainer.path)"
    return $exchangeContainer
}

<#
    This function returns the unique id (Guid) of the organization
    It can be used when no Exchange Management Shell is used to run a script
#>
function Get-ExchangeOrganizationGuid {
    [CmdletBinding()]
    param(
        [ScriptBlock]$CatchActionFunction
    )

    if($ExchangeOrgGUID) {
        $organizationGuid = $ExchangeOrgGUID
    }
    else {
        $organizationGuid = $null
        try {
        $exchangeContainer = Get-ExchangeContainer
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($exchangeContainer, "(objectClass=msExchOrganizationContainer)", "objectGUID")
        $result = $searcher.FindOne()
        
        if ($null -ne $result.Properties["objectGuid"]) {
            
                $organizationGuid = ([System.Guid]::New($($result.Properties["objectGuid"]))).Guid
            }
        } catch {
                Write-Verbose "Unable to query Exchange Organization Guid. Exception: $_"
                Invoke-CatchActionError $CatchActionFunction
        }
    }

    return $organizationGuid
}


function Convert-JsonWebTokenToObject {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)")]
        [string]$Token
    )

    <#
        This function can be used to split a JSON web token (JWT) into its header, payload, and signature.
        The JWT is expected to be in the format of <header>.<payload>.<signature>.
        The function returns a PSCustomObject with the following properties:
            Header    - The header of the JWT
            Payload   - The payload of the JWT
            Signature - The signature of the JWT

            It returns $null if the JWT is not in the expected format or conversion fails.
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        function ConvertJwtFromBase64StringWithoutPadding {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Jwt
            )
            $Jwt = ($Jwt.Replace("-", "+")).Replace("_", "/")
            switch ($Jwt.Length % 4) {
                0 { return [System.Convert]::FromBase64String($Jwt) }
                2 { return [System.Convert]::FromBase64String($Jwt + "==") }
                3 { return [System.Convert]::FromBase64String($Jwt + "=") }
                default { throw "The JWT is not a valid Base64 string." }
            }
        }
    }
    process {
        $tokenParts = $Token.Split(".")
        $tokenHeader = $tokenParts[0]
        $tokenPayload = $tokenParts[1]
        $tokenSignature = $tokenParts[2]

        Write-Verbose "Now processing token header..."
        $tokenHeaderDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenHeader))

        Write-Verbose "Now processing token payload..."
        $tokenPayloadDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenPayload))

        Write-Verbose "Now processing token signature..."
        $tokenSignatureDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenSignature))
    }
    end {
        if (($null -ne $tokenHeaderDecoded) -and
            ($null -ne $tokenPayloadDecoded) -and
            ($null -ne $tokenSignatureDecoded)) {
            Write-Verbose "Conversion of the token was successful"
            return [PSCustomObject]@{
                Header    = ($tokenHeaderDecoded | ConvertFrom-Json)
                Payload   = ($tokenPayloadDecoded | ConvertFrom-Json)
                Signature = $tokenSignatureDecoded
            }
        }

        Write-Verbose "Conversion of the token failed"
        return $null
    }
}

function Get-NewS256CodeChallengeVerifier {
    param()

    <#
        This function can be used to generate a new SHA256 code challenge and verifier following the PKCE specification.
        The Proof Key for Code Exchange (PKCE) extension describes a technique for public clients to mitigate the threat
        of having the authorization code intercepted. The technique involves the client first creating a secret,
        and then using that secret again when exchanging the authorization code for an access token.

        The function returns a PSCustomObject with the following properties:
        Verifier: The verifier that was generated
        CodeChallenge: The code challenge that was generated

        It returns $null if the code challenge and verifier generation fails.

        More information about the auth code flow with PKCE can be found here:
        https://www.rfc-editor.org/rfc/rfc7636
    #>

    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    $bytes = [System.Byte[]]::new(64)
    ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($bytes)
    $b64String = [Convert]::ToBase64String($bytes)
    $verifier = (($b64String.TrimEnd("=")).Replace("+", "-")).Replace("/", "_")

    $newMemoryStream = [System.IO.MemoryStream]::new()
    $newStreamWriter = [System.IO.StreamWriter]::new($newMemoryStream)
    $newStreamWriter.write($verifier)
    $newStreamWriter.Flush()
    $newMemoryStream.Position = 0
    $hash = Get-FileHash -InputStream $newMemoryStream | Select-Object Hash
    $hex = $hash.Hash

    $bytesArray = [byte[]]::new($hex.Length / 2)

    for ($i = 0; $i -lt $hex.Length; $i+=2) {
        $bytesArray[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
    }

    $base64Encoded = [Convert]::ToBase64String($bytesArray)
    $base64UrlEncoded = (($base64Encoded.TrimEnd("=")).Replace("+", "-")).Replace("/", "_")

    if ((-not([System.String]::IsNullOrEmpty($verifier))) -and
        (-not([System.String]::IsNullOrEmpty(($base64UrlEncoded))))) {
        Write-Verbose "Verifier and CodeChallenge generated successfully"
        return [PSCustomObject]@{
            Verifier      = $verifier
            CodeChallenge = $base64UrlEncoded
        }
    }

    Write-Verbose "Verifier and CodeChallenge generation failed"
    return $null
}

function Start-LocalListener {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Only non-destructive operations are performed in this function.')]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Port = 8004,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 60,

        [Parameter(Mandatory = $false)]
        [string]$UrlContains = "code=",

        [Parameter(Mandatory = $false)]
        [string]$ExpectedHttpMethod = "GET",

        [Parameter(Mandatory = $false)]
        [string]$ResponseOutput = "Authentication complete. You can return to the application. Feel free to close this browser tab."
    )

    <#
        This function is used to start a local listener on the specified port (default: 8004).
        It will wait for the specified amount of seconds (default: 60) for a request to be made.
        The function will return the URL of the request that was made.
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $url = $null
        $signalled = $false
        $stopwatch = New-Object System.Diagnostics.Stopwatch
        $listener = New-Object Net.HttpListener
    }
    process {
        $listener.Prefixes.add("http://localhost:$($Port)/")
        try {
            Write-Verbose "Starting listener..."
            Write-Verbose "Listening on port: $($Port)"
            Write-Verbose "Waiting $($TimeoutSeconds) seconds for request to be made to url that contains: $($UrlContains)"
            $stopwatch.Start()
            $listener.Start()

            while ($listener.IsListening) {
                $task = $listener.GetContextAsync()

                while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
                    if ($task.AsyncWaitHandle.WaitOne(100)) {
                        $signalled = $true
                        break
                    }
                    Start-Sleep -Milliseconds 100
                }

                if ($signalled) {
                    $context = $task.GetAwaiter().GetResult()
                    $request = $context.Request
                    $response = $context.Response
                    $url = $request.RawUrl
                    $content = [byte[]]@()

                    if (($url.Contains($UrlContains)) -and
                        ($request.HttpMethod -eq $ExpectedHttpMethod)) {
                        Write-Verbose "Request made to listener and url that was called is as expected. HTTP Method: $($request.HttpMethod)"
                        $content = [System.Text.Encoding]::UTF8.GetBytes($ResponseOutput)
                        $response.StatusCode = 200 # OK
                        $response.OutputStream.Write($content, 0, $content.Length)
                        $response.Close()
                        break
                    } else {
                        Write-Verbose "Request made to listener but the url that was called is not as expected. URL: $($url)"
                        $response.StatusCode = 404 # Not Found
                        $response.OutputStream.Write($content, 0, $content.Length)
                        $response.Close()
                        break
                    }
                } else {
                    Write-Verbose "Timeout of $($TimeoutSeconds) seconds reached..."
                    break
                }
            }
        } finally {
            Write-Verbose "Stopping listener..."
            Start-Sleep -Seconds 2
            $stopwatch.Stop()
            $listener.Stop()
        }
    }
    end {
        return $url
    }
}

<#
    This function is used to get an access token for the Azure Graph API by using the OAuth 2.0 authorization code flow
    with PKCE (Proof Key for Code Exchange). The OAuth 2.0 authorization code grant type, or auth code flow,
    enables a client application to obtain authorized access to protected resources like web APIs.
    The auth code flow requires a user-agent that supports redirection from the authorization server
    (the Microsoft identity platform) back to your application.

    More information about the auth code flow with PKCE can be found here:
    https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow#protocol-details
#>
function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AzureADEndpoint = "https://login.microsoftonline.com",

        [Parameter(Mandatory = $false)]
        [string]$GraphApiUrl = "https://graph.microsoft.com",

        [Parameter(Mandatory = $false)]
        [string]$ClientId = "1950a258-227b-4e31-a9cf-717495945fc2", # Well-known Microsoft Azure PowerShell application ID

        [Parameter(Mandatory = $false)]
        [string]$Scope = "$($GraphApiUrl)//AuditLog.Read.All Directory.AccessAsUser.All email openid profile"
    )

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"

        <#
            This helper function takes a query string (such as the one returned in an OAuth 2.0 redirect URI)
            and converts it into a PowerShell hashtable for easier access to individual parameters.
            It handles query strings starting with "/?", "?", or "#" and supports multiple values for the same key.
            Special handling is included to avoid logging sensitive values like the full authorization code.

            Example query string: /?code=1.AWEBopV8FWgvEkyBGMjt_4b...&state=54889...&session_state=007cd9
        #>
        function ConvertFrom-QueryString {
            param(
                [string]$Query
            )

            $map = @{}

            if ($Query.StartsWith("/?")) {
                Write-Verbose "Query starts with '/?'"
                $Query = $Query.Substring(2)
            } elseif ($Query.StartsWith("?") -or $Query.StartsWith("#")) {
                Write-Verbose "Query starts with '?' or '#'"
                $Query = $Query.Substring(1)
            }

            # Return an empty hashtable if the query string is null or empty
            if ([System.String]::IsNullOrEmpty($Query)) {
                Write-Verbose "Empty or null string was passed to the function"
                return $map
            }

            # Split the query by "&" to get its elements (code, state, session_state...)
            foreach ($pair in ($Query -split "&")) {
                # Skip guard to skip empty strings
                if (-not $pair) {
                    Write-Verbose "Empty string will be skipped"
                    continue
                }

                # Next, split the string by "=" to separate key and value
                $keyValue = $pair -split "=", 2

                $key = $keyValue[0]
                Write-Verbose "Key '$key' was assigned"

                if ($keyValue.Count -gt 1) {
                    # Extract the value part after "="
                    $value = $keyValue[1]

                    # Make sure to not log the full authorization code
                    if ($key -eq "code") {
                        Write-Verbose "Value '$($value.Substring(0, 8))...' was assigned"
                    } else {
                        Write-Verbose "Value '$value' was assigned"
                    }
                }

                # In case the key already exists, add the new value as array to the existing key
                if ($map.ContainsKey($key)) {
                    Write-Verbose "Key '$key' already exists in the hashtable - adding new value as array"
                    $map[$key] = @($map[$key]) + $value
                } else {
                    $map[$key] = $value
                }
            }

            return $map
        }

        $responseType = "code" # Provides the code as a query string parameter on our redirect URI
        $prompt = "select_account" # We want to show the select account dialog
        $redirectUri = "http://localhost:8004" # This is the default port for the local listener
        $codeChallengeMethod = "S256" # The code challenge method is S256 (SHA256)
        $codeChallengeVerifier = Get-NewS256CodeChallengeVerifier
        $state = ([guid]::NewGuid()).Guid # State which is needed for CSRF protection
        $nonce = ([guid]::NewGuid()).Guid # Nonce to prevent replay attacks
        $connectionSuccessful = $false
    }
    process {
        $codeChallenge = $codeChallengeVerifier.CodeChallenge
        $codeVerifier = $codeChallengeVerifier.Verifier

        # Request an authorization code from the Microsoft Azure Active Directory endpoint
        $authCodeRequestUrl = "$AzureADEndpoint/organizations/oauth2/v2.0/authorize?client_id=$ClientId" +
        "&response_type=$responseType&redirect_uri=$redirectUri&scope=$scope&state=$state&nonce=$nonce&prompt=$prompt" +
        "&code_challenge_method=$codeChallengeMethod&code_challenge=$codeChallenge"

        Start-Process -FilePath $authCodeRequestUrl
        $authCodeResponse = Start-LocalListener -TimeoutSeconds 120

        if ($null -ne $authCodeResponse) {
            # Parse the authCodeResponse to get the state that was returned
            # We need the state to add CSRF and mix-up defense protection
            $queryString = ConvertFrom-QueryString -Query $authCodeResponse

            $returnedState = $queryString["state"]

            if (-not $returnedState) {
                Write-Host "No state value was returned" -ForegroundColor Red

                return
            }

            Write-Verbose "Script state: '$state' - Returned state: '$returnedState'"

            if ($returnedState -cne $state) {
                Write-Host "State mismatch detected! Expected '$state', got '$returnedState'" -ForegroundColor Red

                return
            }

            $code = $queryString["code"]

            if (-not $code) {
                Write-Host "Authorization code is missing in callback" -ForegroundColor Red

                return
            }

            # Redeem the returned code for an access token
            $redeemAuthCodeParams = @{
                Uri             = "$AzureADEndpoint/organizations/oauth2/v2.0/token"
                Method          = "POST"
                ContentType     = "application/x-www-form-urlencoded"
                Body            = @{
                    client_id     = $ClientId
                    scope         = $scope
                    code          = $code
                    redirect_uri  = $redirectUri
                    grant_type    = "authorization_code"
                    code_verifier = $codeVerifier
                }
                UseBasicParsing = $true
            }
            $redeemAuthCodeResponse = Invoke-WebRequestWithProxyDetection -ParametersObject $redeemAuthCodeParams

            if ($redeemAuthCodeResponse.StatusCode -eq 200) {
                $tokens = $redeemAuthCodeResponse.Content | ConvertFrom-Json
                $idTokenPayload = (Convert-JsonWebTokenToObject $tokens.id_token).Payload

                Write-Verbose "Script nonce: '$nonce' - Returned nonce: '$($idTokenPayload.nonce)'"

                if ($idTokenPayload.nonce -cne $nonce) {
                    Write-Host "Nonce mismatch detected" -ForegroundColor Red

                    return
                }

                $connectionSuccessful = $true
            } else {
                Write-Host "Unable to redeem the authorization code for an access token." -ForegroundColor Red
            }
        } else {
            Write-Host "Unable to acquire an authorization code from the Microsoft Azure Active Directory endpoint." -ForegroundColor Red
        }
    }
    end {
        if ($connectionSuccessful) {
            return [PSCustomObject]@{
                AccessToken = $tokens.access_token
                TenantId    = $idTokenPayload.tid
            }
        }

        return $null
    }
}

<#
    This shared function is used to get the endpoints for the Azure and Microsoft 365 services.
    It returns a PSCustomObject with the following properties:
        GraphApiEndpoint: The endpoint for the Microsoft Graph API
        ExchangeOnlineEndpoint: The endpoint for Exchange Online
        AutoDiscoverSecureName: The endpoint for Autodiscover
        AzureADEndpoint: The endpoint for Azure Active Directory
        EnvironmentName: The name of the Azure environment
#>
function Get-CloudServiceEndpoint {
    [CmdletBinding()]
    param(
        [string]$EndpointName
    )

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
    }
    process {
        # https://learn.microsoft.com/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
        switch ($EndpointName) {
            "Global" {
                $environmentName = "AzureCloud"
                $graphApiEndpoint = "https://graph.microsoft.com"
                $exchangeOnlineEndpoint = "https://outlook.office.com"
                $autodiscoverSecureName = "https://autodiscover-s.outlook.com"
                $azureADEndpoint = "https://login.microsoftonline.com"
                break
            }
            "USGovernmentL4" {
                $environmentName = "AzureUSGovernment"
                $graphApiEndpoint = "https://graph.microsoft.us"
                $exchangeOnlineEndpoint = "https://outlook.office365.us"
                $autodiscoverSecureName = "https://autodiscover-s.office365.us"
                $azureADEndpoint = "https://login.microsoftonline.us"
                break
            }
            "USGovernmentL5" {
                $environmentName = "AzureUSGovernment"
                $graphApiEndpoint = "https://dod-graph.microsoft.us"
                $exchangeOnlineEndpoint = "https://outlook-dod.office365.us"
                $autodiscoverSecureName = "https://autodiscover-s-dod.office365.us"
                $azureADEndpoint = "https://login.microsoftonline.us"
                break
            }
            "ChinaCloud" {
                $environmentName = "AzureChinaCloud"
                $graphApiEndpoint = "https://microsoftgraph.chinacloudapi.cn"
                $exchangeOnlineEndpoint = "https://partner.outlook.cn"
                $autodiscoverSecureName = "https://autodiscover-s.partner.outlook.cn"
                $azureADEndpoint = "https://login.partner.microsoftonline.cn"
                break
            }
        }
    }
    end {
        return [PSCustomObject]@{
            EnvironmentName        = $environmentName
            GraphApiEndpoint       = $graphApiEndpoint
            ExchangeOnlineEndpoint = $exchangeOnlineEndpoint
            AutoDiscoverSecureName = $autodiscoverSecureName
            AzureADEndpoint        = $azureADEndpoint
        }
    }
}

function Get-NewJsonWebToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CertificateThumbprint,

        [ValidateSet("CurrentUser", "LocalMachine")]
        [Parameter(Mandatory = $false)]
        [string]$CertificateStore = "CurrentUser",

        [Parameter(Mandatory = $false)]
        [string]$Issuer,

        [Parameter(Mandatory = $false)]
        [string]$Audience,

        [Parameter(Mandatory = $false)]
        [string]$Subject,

        [Parameter(Mandatory = $false)]
        [int]$TokenLifetimeInSeconds = 3600,

        [ValidateSet("RS256", "RS384", "RS512")]
        [Parameter(Mandatory = $false)]
        [string]$SigningAlgorithm = "RS256"
    )

    <#
        Shared function to create a signed Json Web Token (JWT) by using a certificate.
        It is also possible to use a secret key to sign the token, but that is not supported in this function.
        The function returns the token as a string if successful, otherwise it returns $null.
        https://www.rfc-editor.org/rfc/rfc7519
        https://learn.microsoft.com/azure/active-directory/develop/active-directory-certificate-credentials
        https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
    }
    process {
        try {
            $certificate = Get-ChildItem Cert:\$CertificateStore\My\$CertificateThumbprint
            if ($certificate.HasPrivateKey) {
                $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
                # Base64url-encoded SHA-1 thumbprint of the X.509 certificate's DER encoding
                $x5t = [System.Convert]::ToBase64String($certificate.GetCertHash())
                $x5t = ((($x5t).Replace("\+", "-")).Replace("/", "_")).Replace("=", "")
                Write-Verbose "x5t is: $x5t"
            } else {
                Write-Verbose "We don't have a private key for certificate: $CertificateThumbprint and so cannot sign the token"
                return
            }
        } catch {
            Write-Verbose "Unable to import the certificate - Exception: $($Error[0].Exception.Message)"
            return
        }

        $header = [ordered]@{
            alg = $SigningAlgorithm
            typ = "JWT"
            x5t = $x5t
        }

        # "iat" (issued at) and "exp" (expiration time) must be UTC and in UNIX time format
        $payload = @{
            iat = [Math]::Round((Get-Date).ToUniversalTime().Subtract((Get-Date -Date "01/01/1970")).TotalSeconds)
            exp = [Math]::Round((Get-Date).ToUniversalTime().Subtract((Get-Date -Date "01/01/1970")).TotalSeconds) + $TokenLifetimeInSeconds
        }

        # Issuer, Audience and Subject are optional as per RFC 7519
        if (-not([System.String]::IsNullOrEmpty($Issuer))) {
            Write-Verbose "Issuer: $Issuer will be added to payload"
            $payload.Add("iss", $Issuer)
        }

        if (-not([System.String]::IsNullOrEmpty($Audience))) {
            Write-Verbose "Audience: $Audience will be added to payload"
            $payload.Add("aud", $Audience)
        }

        if (-not([System.String]::IsNullOrEmpty($Subject))) {
            Write-Verbose "Subject: $Subject will be added to payload"
            $payload.Add("sub", $Subject)
        }

        $headerJson = $header | ConvertTo-Json -Compress
        $payloadJson = $payload | ConvertTo-Json -Compress

        $headerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($headerJson)).Split("=")[0].Replace("+", "-").Replace("/", "_")
        $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($payloadJson)).Split("=")[0].Replace("+", "-").Replace("/", "_")

        $signatureInput = [System.Text.Encoding]::ASCII.GetBytes("$headerBase64.$payloadBase64")

        Write-Verbose "Header (Base64) is: $headerBase64"
        Write-Verbose "Payload (Base64) is: $payloadBase64"
        Write-Verbose "Signature input is: $signatureInput"

        $signingAlgorithmToUse = switch ($SigningAlgorithm) {
            ("RS384") { [Security.Cryptography.HashAlgorithmName]::SHA384 }
            ("RS512") { [Security.Cryptography.HashAlgorithmName]::SHA512 }
            default { [Security.Cryptography.HashAlgorithmName]::SHA256 }
        }
        Write-Verbose "Signing the Json Web Token using: $SigningAlgorithm"

        $signature = $privateKey.SignData($signatureInput, $signingAlgorithmToUse, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $signature = [Convert]::ToBase64String($signature).Split("=")[0].Replace("+", "-").Replace("/", "_")
    }
    end {
        if ((-not([System.String]::IsNullOrEmpty($headerBase64))) -and
            (-not([System.String]::IsNullOrEmpty($payloadBase64))) -and
            (-not([System.String]::IsNullOrEmpty($signature)))) {
            Write-Verbose "Returning Json Web Token"
            return ("$headerBase64.$payloadBase64.$signature")
        } else {
            Write-Verbose "Unable to create Json Web Token"
            return
        }
    }
}

function Get-NewOAuthToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter(Mandatory = $true)]
        [string]$ClientID,

        [Parameter(Mandatory = $true)]
        [string]$Secret,

        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [Parameter(Mandatory = $false)]
        [string]$TokenService = "oauth2/v2.0/token",

        [Parameter(Mandatory = $false)]
        [switch]$CertificateBasedAuthentication,

        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    <#
        Shared function to create an OAuth token by using a JWT or secret.
        If you want to use a certificate, set the CertificateBasedAuthentication switch and pass a JWT token as the Secret parameter.
        You can use the Get-NewJsonWebToken function to create a JWT token.
        If you want to use a secret, pass the secret as the Secret parameter.
        This function returns a PSCustomObject with the OAuth token, status and the time the token was created.
        If the request fails, the PSCustomObject will contain the exception message.
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $oAuthTokenCallSuccess = $false
        $exceptionMessage = $null

        Write-Verbose "TenantID: $TenantID - ClientID: $ClientID - Endpoint: $Endpoint - TokenService: $TokenService - Scope: $Scope"
        $body = @{
            scope      = $Scope
            client_id  = $ClientID
            grant_type = "client_credentials"
        }

        if ($CertificateBasedAuthentication) {
            Write-Verbose "Function was called with CertificateBasedAuthentication switch"
            $body.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            $body.Add("client_assertion", $Secret)
        } else {
            Write-Verbose "Authentication is based on a secret"
            $body.Add("client_secret", $Secret)
        }

        $invokeRestMethodParams = @{
            ContentType = "application/x-www-form-urlencoded"
            Method      = "POST"
            Body        = $body # Create string by joining bodyList with '&'
            Uri         = "$Endpoint/$TenantID/$TokenService"
        }
    }
    process {
        try {
            Write-Verbose "Now calling the Invoke-RestMethod cmdlet to create an OAuth token"
            $oAuthToken = Invoke-RestMethod @invokeRestMethodParams
            Write-Verbose "Invoke-RestMethod call was successful"
            $oAuthTokenCallSuccess = $true
        } catch {
            Write-Host "We fail to create an OAuth token - Exception: $($_.Exception.Message)" -ForegroundColor Red
            $exceptionMessage = $_.Exception.Message
        }
    }
    end {
        return [PSCustomObject]@{
            OAuthToken           = $oAuthToken
            Successful           = $oAuthTokenCallSuccess
            ExceptionMessage     = $exceptionMessage
            LastTokenRefreshTime = (Get-Date)
        }
    }
}




function Invoke-GraphApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [ValidateSet("v1.0", "beta")]
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = "v1.0",

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json",

        [Parameter(Mandatory = $false)]
        $Body,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)")]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [int]$ExpectedStatusCode = 200,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetryAttempts = 3,

        [Parameter(Mandatory = $true)]
        [string]$GraphApiUrl
    )

    <#
        This shared function is used to make requests to the Microsoft Graph API.
        It returns a PSCustomObject with the following properties:
            Content: The content of the response (converted from JSON to a PSCustomObject)
            Response: The full response object
            StatusCode: The status code of the response
            Successful: A boolean indicating whether the request was successful
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        $retryIndex = 0
        $retryAfterSeconds = 0
        $successful = $false
        $content = $null
    }
    process {
        $graphApiRequestParams = @{
            Uri             = "$GraphApiUrl/$Endpoint/$($Query.TrimStart("/"))"
            Header          = @{ Authorization = "Bearer $AccessToken" }
            Method          = $Method
            ContentType     = $ContentType
            UseBasicParsing = $true
            ErrorAction     = "Stop"
        }

        if ($null -ne $Body) {
            Write-Verbose "Body: $Body"
            $graphApiRequestParams.Add("Body", $Body)
        }

        Write-Verbose "Graph API uri called: $($graphApiRequestParams.Uri)"
        Write-Verbose "Method: $($graphApiRequestParams.Method) ContentType: $($graphApiRequestParams.ContentType)"

        do {
            $retryIndex++

            if ($retryIndex -gt $MaxRetryAttempts) {
                Write-Verbose "Reached maximum retry attempts"

                break
            }

            Write-Verbose "Graph API request attempts $retryIndex of $MaxRetryAttempts"

            if ($retryAfterSeconds -ne 0) {
                Write-Verbose "Waiting for $retryAfterSeconds seconds before trying to run Graph API call again"

                # Wait as long as specified in the Retry-After header that was returned and reset retryAfterSeconds afterwards
                Start-Sleep -Seconds $retryAfterSeconds
                $retryAfterSeconds = 0
            }

            $graphApiResponse = Invoke-WebRequestWithProxyDetection -ParametersObject $graphApiRequestParams

            if ($null -eq $graphApiResponse -or
                [System.String]::IsNullOrEmpty($graphApiResponse.StatusCode)) {
                Write-Verbose "Graph API request failed - no response"

                break
            }

            # We return HTTP 429 together with the Retry-After header in case that a Graph API call gets throttled
            # https://learn.microsoft.com/graph/throttling#best-practices-to-handle-throttling
            if ($graphApiResponse.StatusCode -eq 429) {
                $retryAfterSeconds = $graphApiResponse.Headers["Retry-After"]
                Write-Verbose "Graph API throttling threshold exceeded - retry again after $retryAfterSeconds seconds"

                continue
            }

            if ($graphApiResponse.StatusCode -ne $ExpectedStatusCode) {
                Write-Verbose "Graph API status code: $($graphApiResponse.StatusCode) doesn't match the expected status code: $ExpectedStatusCode"

                break
            }

            Write-Verbose "Graph API request successful"

            $successful = $true
            $content = $graphApiResponse.Content | ConvertFrom-Json
        } while ($successful -eq $false)
    }
    end {
        return [PSCustomObject]@{
            Content    = $content
            Response   = $graphApiResponse
            StatusCode = $graphApiResponse.StatusCode
            Successful = $successful
        }
    }
}

<#
    Gets the Azure Application ID for the Azure Application name which was provided
    https://learn.microsoft.com/graph/api/application-list#request
#>
function Get-AzureApplication {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Processing Azure Application: $AzureApplicationName via Graph Api: $GraphApiUrl"

    $listAadApplicationParams = @{
        Query       = ("applications?`$filter=displayName eq '$AzureApplicationName'")
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $getAzureApplicationResponse = Invoke-GraphApiRequest @listAadApplicationParams

    if ($getAzureApplicationResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while the Azure Application was being queried"
        return
    }

    $azureApplicationExists = (-not([System.String]::IsNullOrEmpty($getAzureApplicationResponse.Content.value.appId)))

    Write-Verbose "Application: $AzureApplicationName exists? $azureApplicationExists"

    return [PSCustomObject]@{
        Id                     = $getAzureApplicationResponse.Content.value.id
        AppId                  = $getAzureApplicationResponse.Content.value.appId
        DisplayName            = $getAzureApplicationResponse.Content.value.displayName
        CreatedDateTime        = $getAzureApplicationResponse.Content.value.createdDateTime
        RequiredResourceAccess = $getAzureApplicationResponse.Content.value.requiredResourceAccess
        KeyCredentials         = $getAzureApplicationResponse.Content.value.keyCredentials
        PasswordCredentials    = $getAzureApplicationResponse.Content.value.passwordCredentials
        ApplicationExists      = $azureApplicationExists
    }
}

<#
    This function will upload a certificate to an Azure application to enable it for CBA
    https://learn.microsoft.com/graph/api/application-update?view=graph-rest-1.0&tabs=http
#>
function Add-CertificateToAzureApplication {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $DisplayName = "Added by $($script:MyInvocation.MyCommand.Name) on $(Get-Date)",

        [ValidateNotNullOrEmpty()]
        $CertificateObject,

        $RemoveExpiredCertificates = $true
    )

    Write-Verbose "Adding keyCredentials to Azure Application: $AzureApplicationName via Graph Api: $GraphApiUrl"

    $keyCredentialsList = New-Object System.Collections.Generic.List[object]
    $certificateIsAlreadyThere = $false

    # Check if Azure application exists - we need these details for the next step
    $getAzureApplicationParams = @{
        AzAccountsObject     = $AzAccountsObject
        AzureApplicationName = $AzureApplicationName
        GraphApiUrl          = $GraphApiUrl
    }
    $getAzureApplicationResponse = Get-AzureApplication @getAzureApplicationParams

    if ($null -eq $getAzureApplicationResponse -or
        [System.String]::IsNullOrEmpty($getAzureApplicationResponse.Id)) {
        Write-Verbose "Something went wrong while querying the Azure Application: $AzureApplicationName"
        Write-Verbose "It could mean that the application doesn't exist or we failed to execute the query"
        return $false
    }

    # Check for existing key credentials, retain existing ones and delete (optional) expired ones
    if ($null -ne $getAzureApplicationResponse.KeyCredentials) {
        Write-Verbose "Existing key credentials for this Azure Application have been located"

        foreach ($key in $getAzureApplicationResponse.KeyCredentials) {
            $certificateThumbprint = $key.customKeyIdentifier

            # Check if the certificate that we're processing is already there by comparing thumbprints
            if ($CertificateObject.CertificateThumbprint -eq $certificateThumbprint) {
                $certificateIsAlreadyThere = $true
            }

            if ($RemoveExpiredCertificates) {
                [DateTime]$expDate = $key.endDateTime

                if ($expDate -lt (Get-Date)) {
                    Write-Verbose "Certificate: $certificateThumbprint has expired and will be removed from the Azure Application"
                    continue
                }
            }

            Write-Verbose "Certificate: $certificateThumbprint will be retained"
            $keyCredentialsList.Add($key)
        }
    } else {
        Write-Verbose "No existing key credentials found for this Azure Application"
    }

    # Add the new certificate to the Azure Application - don't add it again if it already exists
    if ($certificateIsAlreadyThere -eq $false ) {
        $keyCredentialsList.Add([PSCustomObject]@{
                displayName = $DisplayName
                keyId       = (New-Guid).Guid
                type        = "AsymmetricX509Cert"
                usage       = "Verify"
                key         = $CertificateObject.CertificateBase64
            })
    }

    if ($keyCredentialsList.Count -ge 1) {
        $keyCredentialsObject = [PSCustomObject]@{
            keyCredentials = $keyCredentialsList
        }

        # Upload the key credentials to the Azure Application
        $addCertificateToAzureApplicationParams = @{
            Query              = "applications/$($getAzureApplicationResponse.Id)"
            AccessToken        = $AzAccountsObject.AccessToken
            Body               = $keyCredentialsObject | ConvertTo-Json
            Method             = "PATCH"
            ExpectedStatusCode = 204
            GraphApiUrl        = $GraphApiUrl
        }
        if ($PSCmdlet.ShouldProcess("PATCH applications/$($getAzureApplicationResponse.Id)", "Invoke-GraphApiRequest")) {
            $addCertificateToAzureApplicationResponse = Invoke-GraphApiRequest @addCertificateToAzureApplicationParams

            if ($addCertificateToAzureApplicationResponse.Successful -eq $false) {
                Write-Verbose "Failed to upload key credentials to this Azure Application"
                return $false
            }
        }
    } else {
        Write-Verbose "There are no valid key credential objects available for upload to this Azure Application"
        return $false
    }

    Write-Verbose "The key credentials for the Azure Application: $AzureApplicationName have been successfully updated"
    return $true
}


<#
    Retrieve the list of appRoleAssignment that have been granted to a service principal.
    https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignments
#>
function Get-AzureAppRoleAssignments {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $ServicePrincipalId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Searching for Service Principal with Id: $ServicePrincipalId via Graph Api: $GraphApiUrl"

    $assignmentsListObject = New-Object System.Collections.Generic.List[object]

    $queryAppRoleAssignmentsParams = @{
        Query       = "servicePrincipals/$ServicePrincipalId/appRoleAssignments"
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $queryAppRoleAssignmentsResponse = Invoke-GraphApiRequest @queryAppRoleAssignmentsParams

    if ($queryAppRoleAssignmentsResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while querying the appRoleAssignment"
        return
    }

    foreach ($assignment in $queryAppRoleAssignmentsResponse.Content.value) {
        $assignmentsListObject.Add([PSCustomObject]@{
                Id                   = $assignment.id
                AppRoleId            = $assignment.appRoleId
                PrincipalDisplayName = $assignment.principalDisplayName
                PrincipalId          = $assignment.principalId
                PrincipalType        = $assignment.principalType
                ResourceDisplayName  = $assignment.resourceDisplayName
                ResourceId           = $assignment.resourceId
            })
    }

    return $assignmentsListObject
}


<#
    Queries the service principal by using an app id and returns information such as the object id
    By default we query the Office 365 Exchange Online service principal
    https://learn.microsoft.com/graph/api/serviceprincipal-get
#>
function Get-AzureServicePrincipal {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        $AzureApplicationId = "00000002-0000-0ff1-ce00-000000000000",

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $AllowReturnMultipleServicePrincipals = $false
    )

    Write-Verbose "Searching for Service Principal by using App Id: $AzureApplicationId via Graph Api: $GraphApiUrl"

    $servicePrincipalList = New-Object System.Collections.Generic.List[object]

    $queryServicePrincipalParams = @{
        Query       = "servicePrincipals?`$filter=appId eq '$AzureApplicationId'&`$select=id,appDisplayName,keyCredentials"
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $queryServicePrincipalResponse = Invoke-GraphApiRequest @queryServicePrincipalParams

    if ($queryServicePrincipalResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while querying the service principal"
        return
    }

    if (($queryServicePrincipalResponse.Content.value).Count -gt 1 -and
        $AllowReturnMultipleServicePrincipals -eq $false) {
        Write-Verbose "Multiple Service Principals were returned for this application"
        Write-Verbose "Set 'AllowReturnMultipleServicePrincipals' to true if you want the function to return all of them"
        return
    }

    foreach ($value in $queryServicePrincipalResponse.Content.value) {
        Write-Verbose "Adding Service Principal - Id: $($value.id) DisplayName: $($value.appDisplayName)"

        # Add any additional property which we should return as part of the custom object
        $servicePrincipalList.Add([PSCustomObject]@{
                SpnObjectId    = $value.id
                AppDisplayName = $value.appDisplayName
                KeyCredentials = $value.keyCredentials
            })
    }

    return $servicePrincipalList
}


<#
    Gets all the domains that are registered in a tenant
    https://learn.microsoft.com/graph/api/domain-list
#>
function Get-AzureTenantDomainList {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Getting Azure Tenant Domain List via Graph Api: $GraphApiUrl"

    $domainList = New-Object System.Collections.Generic.List[object]

    $getAzureTenantDomainsParams = @{
        Query       = "domains"
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $getAzureTenantDomainsResponse = Invoke-GraphApiRequest @getAzureTenantDomainsParams

    if ($listAzureTenantDomainsResponse.Successful -eq $false) {
        Write-Verbose "Something went wrong while the domain list was being queried"
        return
    }

    foreach ($d in $getAzureTenantDomainsResponse.Content.value) {
        Write-Verbose "Now processing: $($d.id)"

        $domainList.Add([PSCustomObject]@{
                Id                = $d.id
                AdminManaged      = $d.isAdminManaged
                IsDefault         = $d.isDefault
                IsInitial         = $d.isInitial
                IsRoot            = $d.isRoot
                IsVerified        = $d.isVerified
                IsEmailDomain     = $d.supportedServices -contains "Email"
                SupportedServices = $d.supportedServices
            })
    }

    return $domainList
}



<#
    Adds a new owner to an existing Azure Application
    Get application information: https://learn.microsoft.com/graph/api/application-get
    Add owner: https://learn.microsoft.com/graph/api/application-post-owners
#>
function Add-AzureApplicationOwner {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $ApplicationId,

        [ValidateNotNullOrEmpty()]
        $NewOwnerUserId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    begin {
        Write-Verbose "Adding User with Id: $NewOwnerUserId as Owner of the Azure Application: $ApplicationId via Graph Api: $GraphApiUrl"

        $reason = $null

        $getAzureApplicationOwnerParams = @{
            AccessToken = $AzAccountsObject.AccessToken
            GraphApiUrl = $GraphApiUrl
        }
    } process {
        # Graph API call to query the existing owners of the Azure Application as we need to check if the user is already an owner
        if ($PSCmdlet.ShouldProcess("GET applications/$ApplicationId/owners", "Invoke-GraphApiRequest")) {
            $getAzureApplicationOwner = Invoke-GraphApiRequest @getAzureApplicationOwnerParams -Query "applications/$ApplicationId/owners"

            if ($getAzureApplicationOwner.Successful -eq $false) {
                Write-Verbose "Something went wrong while querying the existing Owners of this Azure Application"

                $reason = "UnableToQueryExistingOwners"
                break
            }
        }

        if ($getAzureApplicationOwner.Content.value.Length -eq 0 -or
            (-not($getAzureApplicationOwner.Content.Value.id.Contains($NewOwnerUserId)))) {

            Write-Verbose "User: $NewOwnerUserId is not yet an Owner of this Azure Application and must be added"

            # Graph API call to add the user as a new owner of the Azure Application
            $addNewOwnerToApplicationParams = $getAzureApplicationOwnerParams + @{
                Query              = "applications/$ApplicationId/owners/`$ref"
                Body               = @{ "@odata.id" = "$GraphApiUrl/v1.0/directoryObjects/$NewOwnerUserId" } | ConvertTo-Json
                Method             = "POST"
                ExpectedStatusCode = 204
            }
            if ($PSCmdlet.ShouldProcess("POST $NewOwnerUserId", "Invoke-GraphApiRequest")) {
                $addNewOwnerToApplicationResponse = Invoke-GraphApiRequest @addNewOwnerToApplicationParams

                if ($addNewOwnerToApplicationResponse.Successful -eq $false) {
                    Write-Verbose "Something went wrong while adding the User: $NewOwnerUserId as Owner to this Azure Application"

                    $reason = "AddFailed"
                    break
                }

                $reason = "Successful"
            }
        } else {
            Write-Verbose "User: $NewOwnerUserId is already an Owner of this Azure Application"

            $reason = "AlreadyAnOwner"
        }
    } end {
        return [PSCustomObject]@{
            IsOwner = ($reason -eq "Successful" -or $reason -eq "AlreadyAnOwner")
            Reason  = $reason
        }
    }
}


<#
    Assigns permission to an Azure Application

    The resourceAccessObject which is passed in the body of the Graph API call
    It specifies the resources that the application needs to access
    resourceAppId specifies the resources that the application needs to access and also the set of delegated permissions and application roles that it needs for each of those resources
    resourceAccess id is the unique identifier of an app role or delegated permission exposed by the resource application
    resourceAccess type specifies  whether the id property references a delegated permission or an app role (application permission)

    See:
    https://learn.microsoft.com/graph/api/application-update
    https://learn.microsoft.com/graph/api/resources/requiredresourceaccess
    https://learn.microsoft.com/graph/api/resources/resourceaccess
#>
function Add-AzureApplicationRole {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $ApplicationId,

        [ValidateNotNullOrEmpty()]
        $ResourceId,

        [ValidateNotNullOrEmpty()]
        $AppRoleId,

        [ValidateSet("Scope", "Role")]
        $Type = "Role",

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Adding permission to Azure Application: $ApplicationId via Graph Api: $GraphApiUrl"
    Write-Verbose "ResourceId: $ResourceId - AppRoleId: $AppRoleId - Type: $Type"

    $resourceAccessObject = [PSCustomObject]@{
        requiredResourceAccess = @(
            [PSCustomObject]@{
                resourceAppId  = $ResourceId
                resourceAccess = @(
                    [PSCustomObject]@{
                        id   = $AppRoleId
                        type = $Type
                    }
                )
            }
        )
    }

    $updateApplicationParams = @{
        Query              = "applications/$ApplicationId"
        AccessToken        = $AzAccountsObject.AccessToken
        Body               = $resourceAccessObject | ConvertTo-Json -Depth 4
        Method             = "PATCH"
        ExpectedStatusCode = 204
        GraphApiUrl        = $GraphApiUrl
    }

    # Graph API call to add permissions to the Azure Application
    if ($PSCmdlet.ShouldProcess("PATCH $ResourceId", "Invoke-GraphApiRequest")) {
        $updateApplicationResponse = Invoke-GraphApiRequest @updateApplicationParams

        if ($updateApplicationResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while adding permissions this Azure Application"
            return $false
        }

        return $true
    }

    return $false
}


<#
    Grant an appRoleAssignment to a service principal also known as Admin Consent
    App roles that are assigned to service principals are also known as application permissions
    Application permissions can be granted directly with app role assignments, or through a consent experience
    https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments
#>
function Grant-AzureApplicationAdminConsent {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        $ServicePrincipalId,

        [ValidateNotNullOrEmpty()]
        $ResourceId,

        [ValidateNotNullOrEmpty()]
        $AppRoleId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Granting Admin Consent to Service Principal: $ServicePrincipalId via Graph Api: $GraphApiUrl"

    $grantAdminConsentParams = @{
        Query              = "servicePrincipals/$ServicePrincipalId/appRoleAssignments"
        AccessToken        = $AzAccountsObject.AccessToken
        Body               = @{ "principalId" = $ServicePrincipalId; "resourceId" = $ResourceId; "appRoleId" = $AppRoleId } | ConvertTo-Json
        Method             = "POST"
        ExpectedStatusCode = 201
        GraphApiUrl        = $GraphApiUrl
    }

    # Graph API call to grant admin consent to an Azure Application
    if ($PSCmdlet.ShouldProcess("POST servicePrincipals/$ServicePrincipalId/appRoleAssignments", "Invoke-GraphApiRequest")) {
        $adminConsentResponse = Invoke-GraphApiRequest @grantAdminConsentParams

        if ($adminConsentResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while granting Admin Consent"
            return $false
        }

        return $true
    }

    return $false
}


<#
    Queries the properties and relationship of the signed-in user
    https://learn.microsoft.com/graph/api/user-get
#>
function Get-AzureSignedInUserInformation {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Getting information for the signed-in user via Graph Api: $GraphApiUrl"

    # Groups with permission to grant admin consent
    # Build-in roles: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
    # Admin consent overview: https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview
    $groupsEligibleToGrantAdminConsent = @(
        "62e90394-69f5-4237-9190-012177145e10",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    )

    $memberOfListObject = New-Object System.Collections.Generic.List[object]

    $getAzureSignedInUserBasicParams = @{
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    # Gets the properties and relationship of the signed-in user
    $getAzureSignedInUserResponse = Invoke-GraphApiRequest @getAzureSignedInUserBasicParams -Query "me"

    if ($getAzureSignedInUserResponse.Successful -eq $false) {
        Write-Verbose "Unable to query signed-in user information - please try again"
        return
    }

    # Gets the group membership of the signed-in user
    $getAzureSignedInUserMemberOfResponse = Invoke-GraphApiRequest @getAzureSignedInUserBasicParams -Query "me/memberOf"

    if ($getAzureSignedInUserMemberOfResponse.Successful -eq $false) {
        Write-Verbose "Unable to query signed-in user memberOf information - please try again"
        return
    }

    foreach ($group in $getAzureSignedInUserMemberOfResponse.Content.value) {
        Write-Verbose "Adding group: '$($group.displayName)' to list"
        $memberOfListObject.Add($group)
    }

    return [PSCustomObject]@{
        UserInformation             = $getAzureSignedInUserResponse.Content
        MemberOfInformation         = $memberOfListObject
        EligibleToGrantAdminConsent = ($groupsEligibleToGrantAdminConsent | Where-Object { $_ -in $memberOfListObject.roleTemplateId }).Count -ge 1
    }
}


<#
    Creates a new Azure Application with a specified Display Name, SignInAudience and when provided, logo.
    The logo must be a PNG provided as byte array.
    signInAudience information: https://learn.microsoft.com/graph/api/resources/application#signinaudience-values
    Create application method: https://learn.microsoft.com/graph/api/application-post-applications
    Upload logo: https://learn.microsoft.com/graph/api/application-update?view=graph-rest-1.0&tabs=http#http-request
#>
function New-AzureApplication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $DisplayName,

        [ValidateSet("AzureADMyOrg", "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount")]
        $SignInAudience = "AzureADMyOrg",

        $Description = "Added by $($script:MyInvocation.MyCommand.Name)",

        $PngByteArray,

        $Notes,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Creating a new Azure Application: $DisplayName with Sign-in Audience: $SignInAudience via Graph Api: $GraphApiUrl"

    if ([System.String]::IsNullOrWhiteSpace($Notes)) {
        Write-Verbose "No notes were provided when calling the function - default placeholder will be used"
        $scriptName = $($script:MyInvocation.MyCommand.Name)
        $Notes = "This Enterprise Application was automatically created by the $scriptName script. The script can be downloaded here: https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName"
    }

    $azureApplicationBasicParams = @{
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    $newAzureApplicationParams = $azureApplicationBasicParams + @{
        Query              = "applications"
        Body               = @{ "displayName" = $DisplayName; "signInAudience" = $SignInAudience; "description" = $Description; "notes" = $Notes } | ConvertTo-Json
        Method             = "POST"
        ExpectedStatusCode = 201
    }

    if ($PSCmdlet.ShouldProcess("POST $AzureApplicationName", "Invoke-GraphApiRequest")) {
        $newAzureApplicationResponse = Invoke-GraphApiRequest @newAzureApplicationParams

        if ($newAzureApplicationResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while creating the Azure Application: $AzureApplicationName"
            return
        }

        # We check if the binary data starts with the PNG signature (magic number)
        if ($null -ne $PngByteArray -and
            ($PngByteArray.Length -ge 8) -and
            ([System.BitConverter]::ToString(@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)) -ceq [System.BitConverter]::ToString($PngByteArray[0..7]))) {
            Write-Verbose "Logo was provided and will be uploaded to the Azure Application"

            try {
                $memoryStream = New-Object System.IO.MemoryStream
                $memoryStream.Write($PngByteArray, 0, $PngByteArray.Length)
                $memoryStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

                $uploadLogoParams = $azureApplicationBasicParams + @{
                    ContentType        = "image/png"
                    Query              = "applications(appId='{$($newAzureApplicationResponse.Content.appId)}')/logo"
                    Body               = $memoryStream
                    Method             = "PUT"
                    ExpectedStatusCode = "204"
                }

                # Uploading the logo is optional, we continue processing even if this call fails
                if ($PSCmdlet.ShouldProcess("PUT $AzureApplicationName", "Invoke-GraphApiRequest")) {
                    $uploadLogoResponse = Invoke-GraphApiRequest @uploadLogoParams

                    Write-Verbose "Logo upload was successful? $($uploadLogoResponse.Successful)"
                }
            } catch {
                Write-Verbose "Something went wrong while adding the logo to the Azure Application. Inner Exception: $_"
            } finally {
                $memoryStream.Dispose()
            }
        }

        # Add any additional property which we should return as part of the custom object
        return [PSCustomObject]@{
            DisplayName = $newAzureApplicationResponse.Content.displayName
            Id          = $newAzureApplicationResponse.Content.id
            AppId       = $newAzureApplicationResponse.Content.appId
        }
    }

    return
}


<#
    Create a new servicePrincipal object which is assigned to the specified Azure Application
    https://learn.microsoft.com/graph/api/serviceprincipal-post-serviceprincipals
    https://learn.microsoft.com/graph/api/serviceprincipal-update
#>
function New-AzureServicePrincipal {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AppId,

        $Description = "Added by $($script:MyInvocation.MyCommand.Name)",

        $Notes,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Creating a new Service Principal for Azure Application with AppId: $AppId via Graph Api: $GraphApiUrl"

    if ([System.String]::IsNullOrWhiteSpace($Notes)) {
        Write-Verbose "No notes were provided when calling the function - default placeholder will be used"
        $scriptName = $($script:MyInvocation.MyCommand.Name)
        $Notes = "This Service Principal was automatically created by the $scriptName script. The script can be downloaded here: https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName"
    }

    $servicePrincipalBaseParams = @{
        AccessToken = $AzAccountsObject.AccessToken
        GraphApiUrl = $GraphApiUrl
    }

    # Graph API call to create a service principal object
    if ($PSCmdlet.ShouldProcess("POST $AppId", "Invoke-GraphApiRequest")) {

        $newServicePrincipalParams = $servicePrincipalBaseParams + @{
            Query              = "servicePrincipals"
            Body               = @{ "appId" = $AppId; "description" = $Description; "notes" = $Notes; "accountEnabled" = $true } | ConvertTo-Json
            Method             = "POST"
            ExpectedStatusCode = 201
        }

        $newServicePrincipalResponse = Invoke-GraphApiRequest @newServicePrincipalParams

        if ($newServicePrincipalResponse.Successful -eq $false) {
            Write-Verbose "Something went wrong while creating the service principal"
            return
        }

        $updateServicePrincipalParams = $servicePrincipalBaseParams + @{
            Query              = "servicePrincipals/$($newServicePrincipalResponse.Content.id)"
            Body               = @{ "tags" = @("WindowsAzureActiveDirectoryIntegratedApp", "HideApp") } | ConvertTo-Json
            Method             = "PATCH"
            ExpectedStatusCode = 204
        }

        # Graph API call to update the service principal and add the required tags that can be used to categorize and identify the application
        if ($PSCmdlet.ShouldProcess("PATCH WindowsAzureActiveDirectoryIntegratedApp", "Invoke-GraphApiRequest")) {
            $updateServicePrincipalResponse = Invoke-GraphApiRequest @updateServicePrincipalParams

            if ($updateServicePrincipalResponse.Successful -eq $false) {
                Write-Verbose "Something went wrong while adding the required tags to the service principal"
                return
            }
        }

        return [PSCustomObject]@{
            Id             = $newServicePrincipalResponse.Content.id
            Enabled        = $newServicePrincipalResponse.Content.accountEnabled
            AppDisplayName = $newServicePrincipalResponse.appDisplayName
        }
    }
}

function Get-Consent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('CustomRules\AvoidUsingReadHost', '', Justification = 'Script needs to continue even if N was provided')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [ValidateSet("Gray", "Green", "Cyan", "Yellow", "Red")]
        [string]$Color = "Gray",

        [int]$MaxIterations = 3
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $iterationCount = 0
        $returnValue = $false
    } process {
        do {
            $iterationCount++

            Write-Host "$Message`r`n[Y] Yes [N] No: " -ForegroundColor $Color -NoNewline
            $response = Read-Host

            Write-Verbose "[$iterationCount/$MaxIterations] Input: $response"

            if ($response.Equals("y", [StringComparison]::OrdinalIgnoreCase)) {
                $returnValue = $true
                break
            } elseif ($response.Equals("n", [StringComparison]::OrdinalIgnoreCase)) {
                break
            }
        } until ($iterationCount -ge $MaxIterations)
    } end {
        return $returnValue
    }
}

<#
    This function creates an Azure Application (3P app) with full_access_as_app permission that allows you to run EWS calls against all mailboxes in the organization

    See:
    https://learn.microsoft.com/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth#configure-for-delegated-authentication
    https://learn.microsoft.com/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications
#>
function New-EwsAzureApplication {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is used by the sub-functions which are used in this function')]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        $PngByteArray,

        $Notes,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $AskForConsent = $false,

        $AllowCreationWithoutConsentPermission = $false
    )

    begin {
        Write-Verbose "New application to be created: $AzureApplicationName via Graph Api: $GraphApiUrl"

        # Base parameters which we need to run any of the following Graph API calls
        $azureApplicationBaseParams = @{
            AzAccountsObject = $AzAccountsObject
            GraphApiUrl      = $GraphApiUrl
        }

        # Well-known ids of the Office 365 application and EWS resource
        $o365ExchangeOnlineApplicationId = "00000002-0000-0ff1-ce00-000000000000"
        $o365EwsResource = "dc890d15-9560-4a4c-9b7f-a736ec74ec40"

        $sufficientPermissionToGrantAdminConsent = $false
    } end {
        # Graph API call to check if an Azure Application with the name that was specified, already exists
        $getAzureApplication = Get-AzureApplication @azureApplicationBaseParams -AzureApplicationName $AzureApplicationName

        if ($null -eq $getAzureApplication) {
            Write-Verbose "We were not able to check if an Azure Application with the same name already exists"
            return
        }

        if (-not([System.String]::IsNullOrEmpty($getAzureApplication.Id))) {
            Write-Verbose "Azure Application: $AzureApplicationName with ClientId: $($getAzureApplication.AppId) already exists and can't be created again"
            return
        }

        # Graph API call to get the current logged in user - we need this information to run the following Graph API calls
        $loggedInUserResponse = Get-AzureSignedInUserInformation @azureApplicationBaseParams

        if ($null -eq $loggedInUserResponse) {
            Write-Verbose "We were not able to query the signed-in user information"
            return
        }

        $sufficientPermissionToGrantAdminConsent = $loggedInUserResponse.EligibleToGrantAdminConsent

        if ($sufficientPermissionToGrantAdminConsent -eq $false -and
            $AllowCreationWithoutConsentPermission -eq $false) {
            Write-Verbose "The account which was used has insufficient permission to grant Admin Consent"
            return
        }

        $currentUser = $loggedInUserResponse.UserInformation

        $createNewAzureApplicationParams = $azureApplicationBaseParams + @{
            DisplayName = $AzureApplicationName
            Notes       = $Notes
        }

        if ($null -ne $PngByteArray) {
            Write-Verbose "Logo as png byte array was provided"
            $createNewAzureApplicationParams.Add("PngByteArray", $PngByteArray)
        }

        # Graph API call to create a new Azure Application
        $azureApplication = New-AzureApplication @createNewAzureApplicationParams

        if ($null -eq $azureApplication) {
            Write-Verbose "We were not able to create a new Azure Application named: $AzureApplicationName"
            return
        }

        # Graph API call to add the user as new Azure Application owner
        $azureApplicationOwner = Add-AzureApplicationOwner @azureApplicationBaseParams -ApplicationId $azureApplication.Id -NewOwnerUserId $currentUser.id

        if ($azureApplicationOwner.IsOwner -eq $false) {
            Write-Verbose "We were not able to add the new Owner"
            return
        }

        Write-Verbose "User is an Owner of the Azure Application - Status: $($azureApplicationOwner.Reason)"

        # Graph API call to update the Azure AD Application and add the required permissions
        $azureApplicationRoleParams = $azureApplicationBaseParams + @{
            ApplicationId = $azureApplication.Id
            ResourceId    = $o365ExchangeOnlineApplicationId
            AppRoleId     = $o365EwsResource
        }
        $azureApplicationRole = Add-AzureApplicationRole @azureApplicationRoleParams

        if ($azureApplicationRole -eq $false) {
            Write-Verbose "We were not able to add the new permissions to the Azure Application: $AzureApplicationName"
            return
        }

        # Graph API call to create a new service principal for the Azure Application
        $servicePrincipal = New-AzureServicePrincipal @azureApplicationBaseParams -AppId $azureApplication.AppId -Notes $Notes

        if ($null -eq $servicePrincipal) {
            Write-Verbose "We were not able to create a new Service Principal"
            return
        }

        # Graph API call to query the Office 365 Exchange Online service principal (as we need the object id)
        $querySpnResponse = Get-AzureServicePrincipal @azureApplicationBaseParams -AzureApplicationId $o365ExchangeOnlineApplicationId

        if ($null -eq $querySpnResponse) {
            Write-Verbose "We were not able to query the Office 365 Exchange Online Service Principal"
            return
        }

        if ($sufficientPermissionToGrantAdminConsent -eq $false -and
            $AllowCreationWithoutConsentPermission) {
            Write-Verbose "User has no sufficient permission to grant Admin Consent - skipping Admin Consent call"
        } else {
            if ($AskForConsent) {
                $consentGiven = Get-Consent -Message "Do you want to grant EWS - full_access_as_app permission to all accounts in your tenant?`r`nThis action will update any existing admin consent records for this application."
            }

            if ($consentGiven -or
                $AskForConsent -eq $false) {
                # Graph API call to provide admin consent to the application
                $adminConsent = Grant-AzureApplicationAdminConsent @azureApplicationBaseParams -ServicePrincipalId $servicePrincipal.Id -ResourceId $querySpnResponse.SpnObjectId -AppRoleId $o365EwsResource

                if ($adminConsent -eq $false) {
                    Write-Verbose "We were not able to grant Admin Consent to Azure Application $($azureApplication.AppId)"
                    return
                }
            } else {
                Write-Verbose "Ask for consent: $AskForConsent - Consent given: $consentGiven"
            }
        }

        Write-Verbose "Application: $AzureApplicationName created with required permissions - Client Id: $($azureApplication.AppId)"

        return [PSCustomObject]@{
            ApplicationId          = $azureApplication.Id
            AppId                  = $azureApplication.AppId
            AdminConsent           = if ($null -eq $adminConsent) { $false } else { $adminConsent }
            AdminConsentPermission = $sufficientPermissionToGrantAdminConsent
        }
    }
}


<#
    This function will delete the specified Azure AD application
    https://docs.microsoft.com/graph/api/application-delete?view=graph-rest-1.0&tabs=http
#>
function Remove-AzureApplication {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $AzureApplicationName,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    Write-Verbose "Processing Azure Application: $AzureApplicationName via Graph Api: $GraphApiUrl"

    $getAzureApplicationParams = @{
        AzAccountsObject     = $AzAccountsObject
        AzureApplicationName = $AzureApplicationName
        GraphApiUrl          = $GraphApiUrl
    }
    $getAzureApplicationResponse = Get-AzureApplication @getAzureApplicationParams

    if ($null -eq $getAzureApplicationResponse -or
        [System.String]::IsNullOrEmpty($getAzureApplicationResponse.Id)) {
        Write-Verbose "Something went wrong while querying the Azure Application: $AzureApplicationName"
        Write-Verbose "It could mean that the application doesn't exist or we failed to execute the query"
        return $false
    }

    $deleteAadApplicationParams = @{
        Query              = "applications/$($getAzureApplicationResponse.Id)"
        AccessToken        = $AzAccountsObject.AccessToken
        Method             = "DELETE"
        ExpectedStatusCode = 204
        GraphApiUrl        = $GraphApiUrl
    }
    if ($PSCmdlet.ShouldProcess("DELETE $AzureApplicationName", "Invoke-GraphApiRequest")) {
        $deleteAzureApplicationResponse = Invoke-GraphApiRequest @deleteAadApplicationParams

        if ($deleteAzureApplicationResponse.Successful -eq $false) {
            Write-Verbose "Unable to delete the Azure Application"
            return $false
        }

        Write-Verbose "Deleted the Azure application: $AzureApplicationName successfully"
        return $true
    }

    return $false
}


<#
    This function removes a certificate from a Service Principal in Microsoft Entra ID.
    It will also remove any certificate that has expired. This functionality is enabled by default but can be disabled if needed.
    https://learn.microsoft.com/graph/api/serviceprincipal-update
#>
function Remove-CertificateFromAzureServicePrincipal {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Boolean])]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        $AzureApplicationName,

        [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
        $WellKnownApplicationId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[a-fA-F0-9]{40}$")]
        $CertificateThumbprint,

        $RemoveAllCertificates = $false,

        $RemoveExpiredCertificates = $true
    )

    begin {
        Write-Verbose "Removing keyCredentials from Service Principal of Azure Application: $AzureApplicationName via Graph Api: $GraphApiUrl"

        $returnObject = [PSCustomObject]@{
            Successful = $false
            Message    = $null
        }

        $keyCredentialsList = New-Object System.Collections.Generic.List[object]

        $graphApiBasicParams = @{
            AzAccountsObject = $AzAccountsObject
            GraphApiUrl      = $GraphApiUrl
        }
    } process {
        # If the name of an Azure Application was provided, we need to check first if it exists as we need additional information to continue
        if (-not([System.String]::IsNullOrWhiteSpace($AzureApplicationName))) {
            $getAzureApplicationResponse = Get-AzureApplication @graphApiBasicParams -AzureApplicationName $AzureApplicationName

            if ($null -eq $getAzureApplicationResponse -or
                [System.String]::IsNullOrEmpty($getAzureApplicationResponse.Id)) {
                $returnObject.Message = "Azure Application: $AzureApplicationName doesn't exist"

                return
            }

            $appId = $getAzureApplicationResponse.AppId
        } elseif (-not([System.String]::IsNullOrWhiteSpace($WellKnownApplicationId))) {
            $appId = $WellKnownApplicationId
        } else {
            $returnObject.Message = "No Application Name or WellKnown ApplicationId was provided"

            return
        }

        Write-Verbose "Searching for Service Principal which is assigned to Azure Application: $appId"

        # Next we need to query the service principal of the application, we need the appId to do so
        $getAzureServicePrincipalResponse = Get-AzureServicePrincipal @graphApiBasicParams -AzureApplicationId $appId

        if ($null -eq $getAzureServicePrincipalResponse -or
            [System.String]::IsNullOrEmpty($getAzureServicePrincipalResponse.SpnObjectId)) {
            $returnObject.Message = "Something went wrong while querying the Service Principal"

            return
        }

        # Check for existing key credentials, retain existing ones which don't match the thumbprint that was passed
        if (($getAzureServicePrincipalResponse.KeyCredentials).Count -ge 1) {
            Write-Verbose "Existing key credentials for this Service Principal have been located"

            if ($RemoveAllCertificates) {
                Write-Verbose "RemoveAllCertificates was set to true - all key credentials will be removed"
            } else {
                foreach ($key in $getAzureServicePrincipalResponse.KeyCredentials) {

                    # If the certificate matches the thumbprint, do not retain it
                    if ($CertificateThumbprint -eq $key.customKeyIdentifier) {
                        Write-Verbose "Certificate: $CertificateThumbprint was detected and will be removed from the Service Principal"
                        continue
                    }

                    # If the certificate has expired and RemoveExpiredCertificates is true, do not retain it
                    if ($RemoveExpiredCertificates) {
                        # Date and time information type is DateTimeOffset (using ISO 8601 format and is always in UTC time)
                        # see https://learn.microsoft.com/graph/api/resources/keycredential?view=graph-rest-1.0#properties
                        [DateTime]$expDate = $key.endDateTime

                        if ($expDate -lt (Get-Date).ToUniversalTime()) {
                            Write-Verbose "Certificate: $CertificateThumbprint has expired and will be removed from the Service Principal"
                            continue
                        }
                    }

                    Write-Verbose "Certificate: $($key.customKeyIdentifier) will be retained"
                    # Make sure to only pass these three values, otherwise the PATCH call will fail
                    $keyCredentialsList.Add([PSCustomObject]@{
                            key   = $key.key
                            type  = $key.type
                            usage = $key.usage
                        })
                }
            }
        } else {
            $returnObject.Successful = $true
            $returnObject.Message = "No existing key credentials were found for this Service Principal"

            return
        }

        # If there are keyCredentials that should be retained, provide them, otherwise, pass an empty array to clean up all keyCredentials
        if ($keyCredentialsList.Count -ge 1) {
            $keyCredentialsObject = [PSCustomObject]@{
                keyCredentials = $keyCredentialsList
            }
        } else {
            $keyCredentialsObject = @{
                "keyCredentials" = @()
            }
        }

        # Update the keyCredentials of the Service Principal with all the certificates that should be retained
        $addCertificateToAzureApplicationParams = @{
            Query              = "servicePrincipals/$($getAzureServicePrincipalResponse.SpnObjectId)"
            AccessToken        = $AzAccountsObject.AccessToken
            Body               = $keyCredentialsObject | ConvertTo-Json
            Method             = "PATCH"
            ExpectedStatusCode = 204
            GraphApiUrl        = $GraphApiUrl
        }

        if ($PSCmdlet.ShouldProcess("PATCH applications/$($getAzureServicePrincipalResponse.SpnObjectId)", "Invoke-GraphApiRequest")) {
            $updateServicePrincipalKeyCredentialsResponse = Invoke-GraphApiRequest @addCertificateToAzureApplicationParams

            if ($updateServicePrincipalKeyCredentialsResponse.Successful -eq $false) {
                $returnObject.Message = "Failed to update the key credentials of Service Principal: $($getAzureServicePrincipalResponse.SpnObjectId)"

                return
            }

            $returnObject.Successful = $true
            $returnObject.Message = "The key of Service Principal: $($getAzureServicePrincipalResponse.SpnObjectId) have been successfully updated"
        }
    } end {
        Write-Verbose $returnObject.Message

        return $returnObject
    }
}


<#
    Validates whether an Azure application has the expected API permissions
    The function also checks if tenant-wide admin consent has been granted
#>
function Test-AzureApplicationPermission {
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl,

        $AzureApplicationObject,

        $AzureApplicationName,

        [ValidateNotNullOrEmpty()]
        $ResourceAppId,

        [ValidateNotNullOrEmpty()]
        $ResourceAccessId,

        [ValidateNotNullOrEmpty()]
        $Type
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $graphApiBaseParams = @{
            GraphApiUrl      = $GraphApiUrl
            AzAccountsObject = $AzAccountsObject
        }

        $apiPermissionsSetAsExpected = $false
        $adminConsentGranted = $false
    } process {
        if ([System.String]::IsNullOrWhiteSpace($AzureApplicationName) -and
            $null -eq $AzureApplicationObject) {
            Write-Verbose "No Application name or Azure Application object was provided - validation can't be performed"
            return
        }

        if (-not([System.String]::IsNullOrWhiteSpace($AzureApplicationName))) {
            $AzureApplicationObject = Get-AzureApplication @graphApiBaseParams -AzureApplicationName $azureApplicationName

            if ($null -eq $AzureApplicationObject.AppId) {
                Write-Verbose "We were unable to query the Azure application: $AzureApplicationName - this could be due to the application not existing or a failure in the Graph API call"
                return
            }
        }

        # If the application exists, we're checking if resourceAppId and resourceAccess is configured as expected, otherwise the app needs to be re-created
        $requiredResourceAccessInformation = $AzureApplicationObject.RequiredResourceAccess
        $azureApplicationId = $AzureApplicationObject.AppId

        $apiPermissionsSetAsExpected = (($requiredResourceAccessInformation.resourceAppId -eq $ResourceAppId) -and
            ($requiredResourceAccessInformation.resourceAccess.id -eq $ResourceAccessId -and
            $requiredResourceAccessInformation.resourceAccess.type -eq $Type))

        # We need to validate if admin consent has been granted - to do so, we need to query the service principal assigned to the application first
        $getAzureServicePrincipalInformation = Get-AzureServicePrincipal @graphApiBaseParams -AzureApplicationId $azureApplicationId

        # Next we need to validate the role assignments for that service principal - we must provide the servicePrincipalId here which we got by previous call
        if ($null -ne $getAzureServicePrincipalInformation) {
            $getAzureAppRoleAssignmentsInformation = Get-AzureAppRoleAssignments @graphApiBaseParams -ServicePrincipalId $getAzureServicePrincipalInformation.SpnObjectId

            if ($null -eq $getAzureAppRoleAssignmentsInformation) {
                Write-Verbose "No appRoleAssignments granted to the Service Principal: $($getAzureServicePrincipalInformation.SpnObjectId) were found"

                return
            }

            $adminConsentResult = $getAzureAppRoleAssignmentsInformation | Where-Object {
                $_.PrincipalId -eq $getAzureServicePrincipalInformation.SpnObjectId -and
                $_.AppRoleId -eq $ResourceAccessId
            }

            $adminConsentGranted = $null -ne $adminConsentResult.Id
        } else {
            Write-Verbose "Unable to query Service Principal - validation can't be performed"
        }
    } end {
        Write-Verbose "API Permissions as expected? $apiPermissionsSetAsExpected - Admin Consent granted? $adminConsentGranted"

        return [PSCustomObject]@{
            PermissionsAsExpected = $apiPermissionsSetAsExpected
            AdminConsentGranted   = $adminConsentGranted
        }
    }
}

<#
    This set of code is designed to handle updating your script as this code is basically the same everywhere, making this a common file to avoid duplication.
    Just need to dot load the file to your script and have the correct parameters, then this code does the work for you.
    These are the parameters that you should have within your script.
    This needs to be done within the main part of the script, not inside a function to work correctly.

    [Parameter(Mandatory = $false, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly,

    [switch]$SkipVersionCheck
#>




<#
    Determines if the script has an update available.
#>
function Get-ScriptUpdateAvailable {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
    )

    $BuildVersion = "25.08.21.1217"

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $result = [PSCustomObject]@{
        ScriptName     = $scriptName
        CurrentVersion = $BuildVersion
        LatestVersion  = ""
        UpdateFound    = $false
        Error          = $null
    }

    if ((Get-AuthenticodeSignature -FilePath $scriptFullName).Status -eq "NotSigned") {
        Write-Warning "This script appears to be an unsigned test build. Skipping version check."
    } else {
        try {
            $versionData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequestWithProxyDetection -Uri $VersionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
            $latestVersion = ($versionData | Where-Object { $_.File -eq $scriptName }).Version
            $result.LatestVersion = $latestVersion
            if ($null -ne $latestVersion) {
                $result.UpdateFound = ($latestVersion -ne $BuildVersion)
            } else {
                Write-Warning ("Unable to check for a script update as no script with the same name was found." +
                    "`r`nThis can happen if the script has been renamed. Please check manually if there is a newer version of the script.")
            }

            Write-Verbose "Current version: $($result.CurrentVersion) Latest version: $($result.LatestVersion) Update found: $($result.UpdateFound)"
        } catch {
            Write-Verbose "Unable to check for updates: $($_.Exception)"
            $result.Error = $_
        }
    }

    return $result
}


function Confirm-Signature {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $File
    )

    $IsValid = $false
    $MicrosoftSigningRoot2010 = 'CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    $MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    try {
        $sig = Get-AuthenticodeSignature -FilePath $File

        if ($sig.Status -ne 'Valid') {
            Write-Warning "Signature is not trusted by machine as Valid, status: $($sig.Status)."
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        if (-not $chain.Build($sig.SignerCertificate)) {
            Write-Warning "Signer certificate doesn't chain correctly."
            throw
        }

        if ($chain.ChainElements.Count -le 1) {
            Write-Warning "Certificate Chain shorter than expected."
            throw
        }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            Write-Warning "Top-level certificate in chain is not a root certificate."
            throw
        }

        if ($rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2010 -and $rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2011) {
            Write-Warning "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)."
            throw
        }

        Write-Host "File signed by $($sig.SignerCertificate.Subject)"

        $IsValid = $true
    } catch {
        $IsValid = $false
    }

    $IsValid
}

<#
.SYNOPSIS
    Overwrites the current running script file with the latest version from the repository.
.NOTES
    This function always overwrites the current file with the latest file, which might be
    the same. Get-ScriptUpdateAvailable should be called first to determine if an update is
    needed.

    In many situations, updates are expected to fail, because the server running the script
    does not have internet access. This function writes out failures as warnings, because we
    expect that Get-ScriptUpdateAvailable was already called and it successfully reached out
    to the internet.
#>
function Invoke-ScriptUpdate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([boolean])]
    param ()

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)
    $tempFullName = (Join-Path ((Get-Item $env:TEMP).FullName) $scriptName)

    if ($PSCmdlet.ShouldProcess("$scriptName", "Update script to latest version")) {
        try {
            Invoke-WebRequestWithProxyDetection -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName" -OutFile $tempFullName
        } catch {
            Write-Warning "AutoUpdate: Failed to download update: $($_.Exception.Message)"
            return $false
        }

        try {
            if (Confirm-Signature -File $tempFullName) {
                Write-Host "AutoUpdate: Signature validated."
                if (Test-Path $oldFullName) {
                    Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                }
                Move-Item $scriptFullName $oldFullName
                Move-Item $tempFullName $scriptFullName
                Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                Write-Host "AutoUpdate: Succeeded."
                return $true
            } else {
                Write-Warning "AutoUpdate: Signature could not be verified: $tempFullName."
                Write-Warning "AutoUpdate: Update was not applied."
            }
        } catch {
            Write-Warning "AutoUpdate: Failed to apply update: $($_.Exception.Message)"
        }
    }

    return $false
}

<#
    Determines if the script has an update available. Use the optional
    -AutoUpdate switch to make it update itself. Pass -Confirm:$false
    to update without prompting the user. Pass -Verbose for additional
    diagnostic output.

    Returns $true if an update was downloaded, $false otherwise. The
    result will always be $false if the -AutoUpdate switch is not used.
#>
function Test-ScriptVersion {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Need to pass through ShouldProcess settings to Invoke-ScriptUpdate')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [switch]
        $AutoUpdate,
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
    )

    $updateInfo = Get-ScriptUpdateAvailable $VersionsUrl
    if ($updateInfo.UpdateFound) {
        if ($AutoUpdate) {
            return Invoke-ScriptUpdate
        } else {
            Write-Warning "$($updateInfo.ScriptName) $BuildVersion is outdated. Please download the latest, version $($updateInfo.LatestVersion)."
        }
    }

    return $false
}

$BuildVersion = "25.08.21.1217"
Write-Host ("$($script:MyInvocation.MyCommand.Name) script version $($BuildVersion)") -ForegroundColor Green

$scriptVersionParams = @{
    AutoUpdate = $true
    Confirm    = $false
}

# This needs to be set prior to injecting this file to other scripts.
if (-not ([string]::IsNullOrEmpty($versionsUrl))) {
    $scriptVersionParams.Add("VersionsUrl", $versionsUrl)
}

if ($ScriptUpdateOnly) {
    switch (Test-ScriptVersion @scriptVersionParams) {
        ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
        ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
        default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
    }
    exit
}

if ((-not($SkipVersionCheck)) -and
    (Test-ScriptVersion @scriptVersionParams)) {
    Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
    exit
}




# This function is used to determine the version of Exchange based off a build number or
# by providing the Exchange Version and CU and/or SU. This provides one location in the entire repository
# that is required to be updated for when a new release of Exchange is dropped.
function Get-ExchangeBuildVersionInformation {
    [CmdletBinding(DefaultParameterSetName = "AdminDisplayVersion")]
    param(
        [Parameter(ParameterSetName = "AdminDisplayVersion", Position = 1)]
        [object]$AdminDisplayVersion,

        [Parameter(ParameterSetName = "ExSetup")]
        [System.Version]$FileVersion,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $true)]
        [ValidateScript( { ValidateVersionParameter $_ } )]
        [string]$Version,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $true)]
        [ValidateScript( { ValidateCUParameter $_ } )]
        [string]$CU,

        [Parameter(ParameterSetName = "VersionCU", Mandatory = $false)]
        [ValidateScript( { ValidateSUParameter $_ } )]
        [string]$SU,

        [Parameter(ParameterSetName = "FindSUBuilds", Mandatory = $true)]
        [ValidateScript( { ValidateSUParameter $_ } )]
        [string]$FindBySUName,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )
    begin {

        function GetBuildVersion {
            param(
                [Parameter(Position = 1)]
                [string]$ExchangeVersion,
                [Parameter(Position = 2)]
                [string]$CU,
                [Parameter(Position = 3)]
                [string]$SU
            )
            $cuResult = $exchangeBuildDictionary[$ExchangeVersion][$CU]

            if ((-not [string]::IsNullOrEmpty($SU)) -and
                $cuResult.SU.ContainsKey($SU)) {
                return $cuResult.SU[$SU]
            } else {
                return $cuResult.CU
            }
        }

        # Dictionary of Exchange Version/CU/SU to build number
        $exchangeBuildDictionary = GetExchangeBuildDictionary

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeMajorVersion = [string]::Empty
        $exchangeVersion = $null
        $supportedBuildNumber = $false
        $latestSUBuild = $false
        $extendedSupportDate = [string]::Empty
        $cuReleaseDate = [string]::Empty
        $friendlyName = [string]::Empty
        $cuLevel = [string]::Empty
        $suName = [string]::Empty
        $orgValue = 0
        $schemaValue = 0
        $mesoValue = 0
        $exSE = "ExchangeSE"
        $ex19 = "Exchange2019"
        $ex16 = "Exchange2016"
        $ex13 = "Exchange2013"
    }
    process {
        # Convert both input types to a [System.Version]
        try {
            if ($PSCmdlet.ParameterSetName -eq "FindSUBuilds") {
                foreach ($exchangeKey in $exchangeBuildDictionary.Keys) {
                    foreach ($cuKey in $exchangeBuildDictionary[$exchangeKey].Keys) {
                        if ($null -ne $exchangeBuildDictionary[$exchangeKey][$cuKey].SU -and
                            $exchangeBuildDictionary[$exchangeKey][$cuKey].SU.ContainsKey($FindBySUName)) {
                            Get-ExchangeBuildVersionInformation -FileVersion $exchangeBuildDictionary[$exchangeKey][$cuKey].SU[$FindBySUName]
                        }
                    }
                }
                return
            } elseif ($PSCmdlet.ParameterSetName -eq "VersionCU") {
                [System.Version]$exchangeVersion = GetBuildVersion -ExchangeVersion $Version -CU $CU -SU $SU
            } elseif ($PSCmdlet.ParameterSetName -eq "AdminDisplayVersion") {
                $AdminDisplayVersion = $AdminDisplayVersion.ToString()
                Write-Verbose "Passed AdminDisplayVersion: $AdminDisplayVersion"
                $split1 = $AdminDisplayVersion.Substring(($AdminDisplayVersion.IndexOf(" ")) + 1, 4).Split(".")
                $buildStart = $AdminDisplayVersion.LastIndexOf(" ") + 1
                $split2 = $AdminDisplayVersion.Substring($buildStart, ($AdminDisplayVersion.LastIndexOf(")") - $buildStart)).Split(".")
                [System.Version]$exchangeVersion = "$($split1[0]).$($split1[1]).$($split2[0]).$($split2[1])"
            } else {
                [System.Version]$exchangeVersion = $FileVersion
            }
        } catch {
            Write-Verbose "Failed to convert to system.version"
            Invoke-CatchActionError $CatchActionFunction
        }

        <#
            Exchange Build Numbers: https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
            Exchange 2016 & 2019 AD Changes: https://learn.microsoft.com/en-us/exchange/plan-and-deploy/prepare-ad-and-domains?view=exchserver-2019
            Exchange 2013 AD Changes: https://learn.microsoft.com/en-us/exchange/prepare-active-directory-and-domains-exchange-2013-help
        #>
        if ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 2 -and $exchangeVersion.Build -ge 2562) {
            Write-Verbose "Exchange Server SE is detected"
            $exchangeMajorVersion = "ExchangeSE"
            $extendedSupportDate = "12/31/2035"
            $friendlyName = "Exchange SE"
            #Latest Version AD Settings
            $schemaValue = 17003
            $mesoValue = 13243
            $orgValue = 16763

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $exSE "RTM") } {
                    $cuLevel = "RTM"
                    $cuReleaseDate = "07/01/2025"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $exSE "RTM" -SU "Aug25SU") { $latestSUBuild = $true }
            }
        } elseif ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 2) {
            Write-Verbose "Exchange 2019 is detected"
            $exchangeMajorVersion = "Exchange2019"
            $extendedSupportDate = "10/14/2025"
            $friendlyName = "Exchange 2019"

            #Latest Version AD Settings
            $schemaValue = 17003
            $mesoValue = 13243
            $orgValue = 16763

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex19 "CU15") } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "02/10/2025"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex19 "CU15" -SU "Aug25SU") { $latestSUBuild = $true }
                { $_ -lt (GetBuildVersion $ex19 "CU15") } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "02/13/2024"
                    $supportedBuildNumber = $true
                    $orgValue = 16762
                }
                (GetBuildVersion $ex19 "CU14" -SU "Aug25SU") { $latestSUBuild = $true }
                { $_ -lt (GetBuildVersion $ex19 "CU14") } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "05/03/2023"
                    $supportedBuildNumber = $false
                    $orgValue = 16761
                }
                { $_ -lt (GetBuildVersion $ex19 "CU13") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "04/20/2022"
                    $orgValue = 16760
                }
                { $_ -lt (GetBuildVersion $ex19 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "09/28/2021"
                    $mesoValue = 13242
                    $orgValue = 16759
                }
                (GetBuildVersion $ex19 "CU11" -SU "May22SU") { $mesoValue = 13243 }
                { $_ -lt (GetBuildVersion $ex19 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16758
                }
                { $_ -lt (GetBuildVersion $ex19 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "03/16/2021"
                    $schemaValue = 17002
                    $mesoValue = 13240
                    $orgValue = 16757
                }
                { $_ -lt (GetBuildVersion $ex19 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "12/15/2020"
                    $mesoValue = 13239
                    $orgValue = 16756
                }
                { $_ -lt (GetBuildVersion $ex19 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "09/15/2020"
                    $schemaValue = 17001
                    $mesoValue = 13238
                    $orgValue = 16755
                }
                { $_ -lt (GetBuildVersion $ex19 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "06/16/2020"
                    $mesoValue = 13237
                    $orgValue = 16754
                }
                { $_ -lt (GetBuildVersion $ex19 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "03/17/2020"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "12/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "09/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "06/18/2019"
                }
                { $_ -lt (GetBuildVersion $ex19 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "02/12/2019"
                    $schemaValue = 17000
                    $mesoValue = 13236
                    $orgValue = 16752
                }
                { $_ -lt (GetBuildVersion $ex19 "CU1") } {
                    $cuLevel = "RTM"
                    $cuReleaseDate = "10/22/2018"
                    $orgValue = 16751
                }
            }
        } elseif ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 1) {
            Write-Verbose "Exchange 2016 is detected"
            $exchangeMajorVersion = "Exchange2016"
            $extendedSupportDate = "10/14/2025"
            $friendlyName = "Exchange 2016"

            #Latest Version AD Settings
            $schemaValue = 15334
            $mesoValue = 13243
            $orgValue = 16223

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex16 "CU23") } {
                    $cuLevel = "CU23"
                    $cuReleaseDate = "04/20/2022"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex16 "CU23" -SU "Aug25SU") { $latestSUBuild = $true }
                { $_ -lt (GetBuildVersion $ex16 "CU23") } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "09/28/2021"
                    $supportedBuildNumber = $false
                    $mesoValue = 13242
                    $orgValue = 16222
                }
                (GetBuildVersion $ex16 "CU22" -SU "May22SU") { $mesoValue = 13243 }
                { $_ -lt (GetBuildVersion $ex16 "CU22") } {
                    $cuLevel = "CU21"
                    $cuReleaseDate = "06/29/2021"
                    $mesoValue = 13241
                    $orgValue = 16221
                }
                { $_ -lt (GetBuildVersion $ex16 "CU21") } {
                    $cuLevel = "CU20"
                    $cuReleaseDate = "03/16/2021"
                    $schemaValue = 15333
                    $mesoValue = 13240
                    $orgValue = 16220
                }
                { $_ -lt (GetBuildVersion $ex16 "CU20") } {
                    $cuLevel = "CU19"
                    $cuReleaseDate = "12/15/2020"
                    $mesoValue = 13239
                    $orgValue = 16219
                }
                { $_ -lt (GetBuildVersion $ex16 "CU19") } {
                    $cuLevel = "CU18"
                    $cuReleaseDate = "09/15/2020"
                    $schemaValue = 15332
                    $mesoValue = 13238
                    $orgValue = 16218
                }
                { $_ -lt (GetBuildVersion $ex16 "CU18") } {
                    $cuLevel = "CU17"
                    $cuReleaseDate = "06/16/2020"
                    $mesoValue = 13237
                    $orgValue = 16217
                }
                { $_ -lt (GetBuildVersion $ex16 "CU17") } {
                    $cuLevel = "CU16"
                    $cuReleaseDate = "03/17/2020"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU16") } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "12/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU15") } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "09/17/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU14") } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "06/18/2019"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU13") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "02/12/2019"
                    $mesoValue = 13236
                    $orgValue = 16215
                }
                { $_ -lt (GetBuildVersion $ex16 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "10/16/2018"
                    $orgValue = 16214
                }
                { $_ -lt (GetBuildVersion $ex16 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "06/19/2018"
                    $orgValue = 16213
                }
                { $_ -lt (GetBuildVersion $ex16 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "03/20/2018"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "12/19/2017"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "09/16/2017"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "06/24/2017"
                    $schemaValue = 15330
                }
                { $_ -lt (GetBuildVersion $ex16 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "03/21/2017"
                    $schemaValue = 15326
                }
                { $_ -lt (GetBuildVersion $ex16 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "12/13/2016"
                }
                { $_ -lt (GetBuildVersion $ex16 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "09/20/2016"
                    $orgValue = 16212
                }
                { $_ -lt (GetBuildVersion $ex16 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "06/21/2016"
                    $schemaValue = 15325
                }
                { $_ -lt (GetBuildVersion $ex16 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "03/15/2016"
                    $schemaValue = 15323
                    $orgValue = 16211
                }
            }
        } elseif ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -eq 0) {
            Write-Verbose "Exchange 2013 is detected"
            $exchangeMajorVersion = "Exchange2013"
            $extendedSupportDate = "04/11/2023"
            $friendlyName = "Exchange 2013"

            #Latest Version AD Settings
            $schemaValue = 15312
            $mesoValue = 13237
            $orgValue = 16133

            switch ($exchangeVersion) {
                { $_ -ge (GetBuildVersion $ex13 "CU23") } {
                    $cuLevel = "CU23"
                    $cuReleaseDate = "06/18/2019"
                    $supportedBuildNumber = $true
                }
                (GetBuildVersion $ex13 "CU23" -SU "May22SU") { $mesoValue = 13238 }
                { $_ -lt (GetBuildVersion $ex13 "CU23") } {
                    $cuLevel = "CU22"
                    $cuReleaseDate = "02/12/2019"
                    $mesoValue = 13236
                    $orgValue = 16131
                    $supportedBuildNumber = $false
                }
                { $_ -lt (GetBuildVersion $ex13 "CU22") } {
                    $cuLevel = "CU21"
                    $cuReleaseDate = "06/19/2018"
                    $orgValue = 16130
                }
                { $_ -lt (GetBuildVersion $ex13 "CU21") } {
                    $cuLevel = "CU20"
                    $cuReleaseDate = "03/20/2018"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU20") } {
                    $cuLevel = "CU19"
                    $cuReleaseDate = "12/19/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU19") } {
                    $cuLevel = "CU18"
                    $cuReleaseDate = "09/16/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU18") } {
                    $cuLevel = "CU17"
                    $cuReleaseDate = "06/24/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU17") } {
                    $cuLevel = "CU16"
                    $cuReleaseDate = "03/21/2017"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU16") } {
                    $cuLevel = "CU15"
                    $cuReleaseDate = "12/13/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU15") } {
                    $cuLevel = "CU14"
                    $cuReleaseDate = "09/20/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU14") } {
                    $cuLevel = "CU13"
                    $cuReleaseDate = "06/21/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU13") } {
                    $cuLevel = "CU12"
                    $cuReleaseDate = "03/15/2016"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU12") } {
                    $cuLevel = "CU11"
                    $cuReleaseDate = "12/15/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU11") } {
                    $cuLevel = "CU10"
                    $cuReleaseDate = "09/15/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU10") } {
                    $cuLevel = "CU9"
                    $cuReleaseDate = "06/17/2015"
                    $orgValue = 15965
                }
                { $_ -lt (GetBuildVersion $ex13 "CU9") } {
                    $cuLevel = "CU8"
                    $cuReleaseDate = "03/17/2015"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU8") } {
                    $cuLevel = "CU7"
                    $cuReleaseDate = "12/09/2014"
                }
                { $_ -lt (GetBuildVersion $ex13 "CU7") } {
                    $cuLevel = "CU6"
                    $cuReleaseDate = "08/26/2014"
                    $schemaValue = 15303
                }
                { $_ -lt (GetBuildVersion $ex13 "CU6") } {
                    $cuLevel = "CU5"
                    $cuReleaseDate = "05/27/2014"
                    $schemaValue = 15300
                    $orgValue = 15870
                }
                { $_ -lt (GetBuildVersion $ex13 "CU5") } {
                    $cuLevel = "CU4"
                    $cuReleaseDate = "02/25/2014"
                    $schemaValue = 15292
                    $orgValue = 15844
                }
                { $_ -lt (GetBuildVersion $ex13 "CU4") } {
                    $cuLevel = "CU3"
                    $cuReleaseDate = "11/25/2013"
                    $schemaValue = 15283
                    $orgValue = 15763
                }
                { $_ -lt (GetBuildVersion $ex13 "CU3") } {
                    $cuLevel = "CU2"
                    $cuReleaseDate = "07/09/2013"
                    $schemaValue = 15281
                    $orgValue = 15688
                }
                { $_ -lt (GetBuildVersion $ex13 "CU2") } {
                    $cuLevel = "CU1"
                    $cuReleaseDate = "04/02/2013"
                    $schemaValue = 15254
                    $orgValue = 15614
                }
            }
        } else {
            Write-Verbose "Unknown version of Exchange is detected."
        }

        # Now get the SU Name
        if ([string]::IsNullOrEmpty($exchangeMajorVersion) -or
            [string]::IsNullOrEmpty($cuLevel)) {
            Write-Verbose "Can't lookup when keys aren't set"
            return
        }

        $currentSUInfo = $exchangeBuildDictionary[$exchangeMajorVersion][$cuLevel].SU
        $compareValue = $exchangeVersion.ToString()
        if ($null -ne $currentSUInfo -and
            $currentSUInfo.ContainsValue($compareValue)) {
            foreach ($key in $currentSUInfo.Keys) {
                if ($compareValue -eq $currentSUInfo[$key]) {
                    $suName = $key
                }
            }
        }
    }
    end {

        if ($PSCmdlet.ParameterSetName -eq "FindSUBuilds") {
            Write-Verbose "Return nothing here, results were already returned on the pipeline"
            return
        }

        $friendlyName = "$friendlyName $cuLevel $suName".Trim()
        Write-Verbose "Determined Build Version $friendlyName"
        return [PSCustomObject]@{
            MajorVersion        = $exchangeMajorVersion
            FriendlyName        = $friendlyName
            BuildVersion        = $exchangeVersion
            CU                  = $cuLevel
            ReleaseDate         = if (-not([System.String]::IsNullOrEmpty($cuReleaseDate))) { ([System.Convert]::ToDateTime([DateTime]$cuReleaseDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) } else { $null }
            ExtendedSupportDate = if (-not([System.String]::IsNullOrEmpty($extendedSupportDate))) { ([System.Convert]::ToDateTime([DateTime]$extendedSupportDate, [System.Globalization.DateTimeFormatInfo]::InvariantInfo)) } else { $null }
            Supported           = $supportedBuildNumber
            LatestSU            = $latestSUBuild
            ADLevel             = [PSCustomObject]@{
                SchemaValue = $schemaValue
                MESOValue   = $mesoValue
                OrgValue    = $orgValue
            }
        }
    }
}

function GetExchangeBuildDictionary {

    function NewCUAndSUObject {
        param(
            [string]$CUBuildNumber,
            [Hashtable]$SUBuildNumber
        )
        return @{
            "CU" = $CUBuildNumber
            "SU" = $SUBuildNumber
        }
    }

    @{
        "Exchange2013" = @{
            "CU1"  = (NewCUAndSUObject "15.0.620.29")
            "CU2"  = (NewCUAndSUObject "15.0.712.24")
            "CU3"  = (NewCUAndSUObject "15.0.775.38")
            "CU4"  = (NewCUAndSUObject "15.0.847.32")
            "CU5"  = (NewCUAndSUObject "15.0.913.22")
            "CU6"  = (NewCUAndSUObject "15.0.995.29")
            "CU7"  = (NewCUAndSUObject "15.0.1044.25")
            "CU8"  = (NewCUAndSUObject "15.0.1076.9")
            "CU9"  = (NewCUAndSUObject "15.0.1104.5")
            "CU10" = (NewCUAndSUObject "15.0.1130.7")
            "CU11" = (NewCUAndSUObject "15.0.1156.6")
            "CU12" = (NewCUAndSUObject "15.0.1178.4")
            "CU13" = (NewCUAndSUObject "15.0.1210.3")
            "CU14" = (NewCUAndSUObject "15.0.1236.3")
            "CU15" = (NewCUAndSUObject "15.0.1263.5")
            "CU16" = (NewCUAndSUObject "15.0.1293.2")
            "CU17" = (NewCUAndSUObject "15.0.1320.4")
            "CU18" = (NewCUAndSUObject "15.0.1347.2" @{
                    "Mar18SU" = "15.0.1347.5"
                })
            "CU19" = (NewCUAndSUObject "15.0.1365.1" @{
                    "Mar18SU" = "15.0.1365.3"
                    "May18SU" = "15.0.1365.7"
                })
            "CU20" = (NewCUAndSUObject "15.0.1367.3" @{
                    "May18SU" = "15.0.1367.6"
                    "Aug18SU" = "15.0.1367.9"
                })
            "CU21" = (NewCUAndSUObject "15.0.1395.4" @{
                    "Aug18SU" = "15.0.1395.7"
                    "Oct18SU" = "15.0.1395.8"
                    "Jan19SU" = "15.0.1395.10"
                    "Mar21SU" = "15.0.1395.12"
                })
            "CU22" = (NewCUAndSUObject "15.0.1473.3" @{
                    "Feb19SU" = "15.0.1473.3"
                    "Apr19SU" = "15.0.1473.4"
                    "Jun19SU" = "15.0.1473.5"
                    "Mar21SU" = "15.0.1473.6"
                })
            "CU23" = (NewCUAndSUObject "15.0.1497.2" @{
                    "Jul19SU" = "15.0.1497.3"
                    "Nov19SU" = "15.0.1497.4"
                    "Feb20SU" = "15.0.1497.6"
                    "Oct20SU" = "15.0.1497.7"
                    "Nov20SU" = "15.0.1497.8"
                    "Dec20SU" = "15.0.1497.10"
                    "Mar21SU" = "15.0.1497.12"
                    "Apr21SU" = "15.0.1497.15"
                    "May21SU" = "15.0.1497.18"
                    "Jul21SU" = "15.0.1497.23"
                    "Oct21SU" = "15.0.1497.24"
                    "Nov21SU" = "15.0.1497.26"
                    "Jan22SU" = "15.0.1497.28"
                    "Mar22SU" = "15.0.1497.33"
                    "May22SU" = "15.0.1497.36"
                    "Aug22SU" = "15.0.1497.40"
                    "Oct22SU" = "15.0.1497.42"
                    "Nov22SU" = "15.0.1497.44"
                    "Jan23SU" = "15.0.1497.45"
                    "Feb23SU" = "15.0.1497.47"
                    "Mar23SU" = "15.0.1497.48"
                })
        }
        "Exchange2016" = @{
            "CU1"  = (NewCUAndSUObject "15.1.396.30")
            "CU2"  = (NewCUAndSUObject "15.1.466.34")
            "CU3"  = (NewCUAndSUObject "15.1.544.27")
            "CU4"  = (NewCUAndSUObject "15.1.669.32")
            "CU5"  = (NewCUAndSUObject "15.1.845.34")
            "CU6"  = (NewCUAndSUObject "15.1.1034.26")
            "CU7"  = (NewCUAndSUObject "15.1.1261.35" @{
                    "Mar18SU" = "15.1.1261.39"
                })
            "CU8"  = (NewCUAndSUObject "15.1.1415.2" @{
                    "Mar18SU" = "15.1.1415.4"
                    "May18SU" = "15.1.1415.7"
                    "Mar21SU" = "15.1.1415.8"
                })
            "CU9"  = (NewCUAndSUObject "15.1.1466.3" @{
                    "May18SU" = "15.1.1466.8"
                    "Aug18SU" = "15.1.1466.9"
                    "Mar21SU" = "15.1.1466.13"
                })
            "CU10" = (NewCUAndSUObject "15.1.1531.3" @{
                    "Aug18SU" = "15.1.1531.6"
                    "Oct18SU" = "15.1.1531.8"
                    "Jan19SU" = "15.1.1531.10"
                    "Mar21SU" = "15.1.1531.12"
                })
            "CU11" = (NewCUAndSUObject "15.1.1591.10" @{
                    "Dec18SU" = "15.1.1591.11"
                    "Jan19SU" = "15.1.1591.13"
                    "Apr19SU" = "15.1.1591.16"
                    "Jun19SU" = "15.1.1591.17"
                    "Mar21SU" = "15.1.1591.18"
                })
            "CU12" = (NewCUAndSUObject "15.1.1713.5" @{
                    "Feb19SU" = "15.1.1713.5"
                    "Apr19SU" = "15.1.1713.6"
                    "Jun19SU" = "15.1.1713.7"
                    "Jul19SU" = "15.1.1713.8"
                    "Sep19SU" = "15.1.1713.9"
                    "Mar21SU" = "15.1.1713.10"
                })
            "CU13" = (NewCUAndSUObject "15.1.1779.2" @{
                    "Jul19SU" = "15.1.1779.4"
                    "Sep19SU" = "15.1.1779.5"
                    "Nov19SU" = "15.1.1779.7"
                    "Mar21SU" = "15.1.1779.8"
                })
            "CU14" = (NewCUAndSUObject "15.1.1847.3" @{
                    "Nov19SU" = "15.1.1847.5"
                    "Feb20SU" = "15.1.1847.7"
                    "Mar20SU" = "15.1.1847.10"
                    "Mar21SU" = "15.1.1847.12"
                })
            "CU15" = (NewCUAndSUObject "15.1.1913.5" @{
                    "Feb20SU" = "15.1.1913.7"
                    "Mar20SU" = "15.1.1913.10"
                    "Mar21SU" = "15.1.1913.12"
                })
            "CU16" = (NewCUAndSUObject "15.1.1979.3" @{
                    "Sep20SU" = "15.1.1979.6"
                    "Mar21SU" = "15.1.1979.8"
                })
            "CU17" = (NewCUAndSUObject "15.1.2044.4" @{
                    "Sep20SU" = "15.1.2044.6"
                    "Oct20SU" = "15.1.2044.7"
                    "Nov20SU" = "15.1.2044.8"
                    "Dec20SU" = "15.1.2044.12"
                    "Mar21SU" = "15.1.2044.13"
                })
            "CU18" = (NewCUAndSUObject "15.1.2106.2" @{
                    "Oct20SU" = "15.1.2106.3"
                    "Nov20SU" = "15.1.2106.4"
                    "Dec20SU" = "15.1.2106.6"
                    "Feb21SU" = "15.1.2106.8"
                    "Mar21SU" = "15.1.2106.13"
                })
            "CU19" = (NewCUAndSUObject "15.1.2176.2" @{
                    "Feb21SU" = "15.1.2176.4"
                    "Mar21SU" = "15.1.2176.9"
                    "Apr21SU" = "15.1.2176.12"
                    "May21SU" = "15.1.2176.14"
                })
            "CU20" = (NewCUAndSUObject "15.1.2242.4" @{
                    "Apr21SU" = "15.1.2242.8"
                    "May21SU" = "15.1.2242.10"
                    "Jul21SU" = "15.1.2242.12"
                })
            "CU21" = (NewCUAndSUObject "15.1.2308.8" @{
                    "Jul21SU" = "15.1.2308.14"
                    "Oct21SU" = "15.1.2308.15"
                    "Nov21SU" = "15.1.2308.20"
                    "Jan22SU" = "15.1.2308.21"
                    "Mar22SU" = "15.1.2308.27"
                })
            "CU22" = (NewCUAndSUObject "15.1.2375.7" @{
                    "Oct21SU" = "15.1.2375.12"
                    "Nov21SU" = "15.1.2375.17"
                    "Jan22SU" = "15.1.2375.18"
                    "Mar22SU" = "15.1.2375.24"
                    "May22SU" = "15.1.2375.28"
                    "Aug22SU" = "15.1.2375.31"
                    "Oct22SU" = "15.1.2375.32"
                    "Nov22SU" = "15.1.2375.37"
                })
            "CU23" = (NewCUAndSUObject "15.1.2507.6" @{
                    "May22SU"   = "15.1.2507.9"
                    "Aug22SU"   = "15.1.2507.12"
                    "Oct22SU"   = "15.1.2507.13"
                    "Nov22SU"   = "15.1.2507.16"
                    "Jan23SU"   = "15.1.2507.17"
                    "Feb23SU"   = "15.1.2507.21"
                    "Mar23SU"   = "15.1.2507.23"
                    "Jun23SU"   = "15.1.2507.27"
                    "Aug23SU"   = "15.1.2507.31"
                    "Aug23SUv2" = "15.1.2507.32"
                    "Oct23SU"   = "15.1.2507.34"
                    "Nov23SU"   = "15.1.2507.35"
                    "Mar24SU"   = "15.1.2507.37"
                    "Apr24HU"   = "15.1.2507.39"
                    "Nov24SU"   = "15.1.2507.43"
                    "Nov24SUv2" = "15.1.2507.44"
                    "Apr25HU"   = "15.1.2507.55"
                    "May25HU"   = "15.1.2507.57"
                    "Aug25SU"   = "15.1.2507.58"
                })
        }
        "Exchange2019" = @{
            "CU1"  = (NewCUAndSUObject "15.2.330.5" @{
                    "Feb19SU" = "15.2.330.5"
                    "Apr19SU" = "15.2.330.7"
                    "Jun19SU" = "15.2.330.8"
                    "Jul19SU" = "15.2.330.9"
                    "Sep19SU" = "15.2.330.10"
                    "Mar21SU" = "15.2.330.11"
                })
            "CU2"  = (NewCUAndSUObject "15.2.397.3" @{
                    "Jul19SU" = "15.2.397.5"
                    "Sep19SU" = "15.2.397.6"
                    "Nov19SU" = "15.2.397.9"
                    "Mar21SU" = "15.2.397.11"
                })
            "CU3"  = (NewCUAndSUObject "15.2.464.5" @{
                    "Nov19SU" = "15.2.464.7"
                    "Feb20SU" = "15.2.464.11"
                    "Mar20SU" = "15.2.464.14"
                    "Mar21SU" = "15.2.464.15"
                })
            "CU4"  = (NewCUAndSUObject "15.2.529.5" @{
                    "Feb20SU" = "15.2.529.8"
                    "Mar20SU" = "15.2.529.11"
                    "Mar21SU" = "15.2.529.13"
                })
            "CU5"  = (NewCUAndSUObject "15.2.595.3" @{
                    "Sep20SU" = "15.2.595.6"
                    "Mar21SU" = "15.2.595.8"
                })
            "CU6"  = (NewCUAndSUObject "15.2.659.4" @{
                    "Sep20SU" = "15.2.659.6"
                    "Oct20SU" = "15.2.659.7"
                    "Nov20SU" = "15.2.659.8"
                    "Dec20SU" = "15.2.659.11"
                    "Mar21SU" = "15.2.659.12"
                })
            "CU7"  = (NewCUAndSUObject "15.2.721.2" @{
                    "Oct20SU" = "15.2.721.3"
                    "Nov20SU" = "15.2.721.4"
                    "Dec20SU" = "15.2.721.6"
                    "Feb21SU" = "15.2.721.8"
                    "Mar21SU" = "15.2.721.13"
                })
            "CU8"  = (NewCUAndSUObject "15.2.792.3" @{
                    "Feb21SU" = "15.2.792.5"
                    "Mar21SU" = "15.2.792.10"
                    "Apr21SU" = "15.2.792.13"
                    "May21SU" = "15.2.792.15"
                })
            "CU9"  = (NewCUAndSUObject "15.2.858.5" @{
                    "Apr21SU" = "15.2.858.10"
                    "May21SU" = "15.2.858.12"
                    "Jul21SU" = "15.2.858.15"
                })
            "CU10" = (NewCUAndSUObject "15.2.922.7" @{
                    "Jul21SU" = "15.2.922.13"
                    "Oct21SU" = "15.2.922.14"
                    "Nov21SU" = "15.2.922.19"
                    "Jan22SU" = "15.2.922.20"
                    "Mar22SU" = "15.2.922.27"
                })
            "CU11" = (NewCUAndSUObject "15.2.986.5" @{
                    "Oct21SU" = "15.2.986.9"
                    "Nov21SU" = "15.2.986.14"
                    "Jan22SU" = "15.2.986.15"
                    "Mar22SU" = "15.2.986.22"
                    "May22SU" = "15.2.986.26"
                    "Aug22SU" = "15.2.986.29"
                    "Oct22SU" = "15.2.986.30"
                    "Nov22SU" = "15.2.986.36"
                    "Jan23SU" = "15.2.986.37"
                    "Feb23SU" = "15.2.986.41"
                    "Mar23SU" = "15.2.986.42"
                })
            "CU12" = (NewCUAndSUObject "15.2.1118.7" @{
                    "May22SU"   = "15.2.1118.9"
                    "Aug22SU"   = "15.2.1118.12"
                    "Oct22SU"   = "15.2.1118.15"
                    "Nov22SU"   = "15.2.1118.20"
                    "Jan23SU"   = "15.2.1118.21"
                    "Feb23SU"   = "15.2.1118.25"
                    "Mar23SU"   = "15.2.1118.26"
                    "Jun23SU"   = "15.2.1118.30"
                    "Aug23SU"   = "15.2.1118.36"
                    "Aug23SUv2" = "15.2.1118.37"
                    "Oct23SU"   = "15.2.1118.39"
                    "Nov23SU"   = "15.2.1118.40"
                })
            "CU13" = (NewCUAndSUObject "15.2.1258.12" @{
                    "Jun23SU"   = "15.2.1258.16"
                    "Aug23SU"   = "15.2.1258.23"
                    "Aug23SUv2" = "15.2.1258.25"
                    "Oct23SU"   = "15.2.1258.27"
                    "Nov23SU"   = "15.2.1258.28"
                    "Mar24SU"   = "15.2.1258.32"
                    "Apr24HU"   = "15.2.1258.34"
                    "Nov24SU"   = "15.2.1258.38"
                    "Nov24SUv2" = "15.2.1258.39"
                })
            "CU14" = (NewCUAndSUObject "15.2.1544.4" @{
                    "Mar24SU"   = "15.2.1544.9"
                    "Apr24HU"   = "15.2.1544.11"
                    "Nov24SU"   = "15.2.1544.13"
                    "Nov24SUv2" = "15.2.1544.14"
                    "Apr25HU"   = "15.2.1544.25"
                    "May25HU"   = "15.2.1544.27"
                    "Aug25SU"   = "15.2.1544.33"
                })
            "CU15" = (NewCUAndSUObject "15.2.1748.10" @{
                    "Apr25HU" = "15.2.1748.24"
                    "May25HU" = "15.2.1748.26"
                    "Aug25SU" = "15.2.1748.36"
                })
        }
        "ExchangeSE"   = @{
            "RTM" = (NewCUAndSUObject "15.2.2562.17" @{
                    "Aug25SU" = "15.2.2562.20"
                })
        }
    }
}

# Must be outside function to use it as a validate script
function GetValidatePossibleParameters {
    $exchangeBuildDictionary = GetExchangeBuildDictionary
    $suNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $cuNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $versionNames = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($exchangeKey in $exchangeBuildDictionary.Keys) {
        [void]$versionNames.Add($exchangeKey)
        foreach ($cuKey in $exchangeBuildDictionary[$exchangeKey].Keys) {
            [void]$cuNames.Add($cuKey)
            if ($null -eq $exchangeBuildDictionary[$exchangeKey][$cuKey].SU) { continue }
            foreach ($suKey in $exchangeBuildDictionary[$exchangeKey][$cuKey].SU.Keys) {
                [void]$suNames.Add($suKey)
            }
        }
    }
    return [PSCustomObject]@{
        Version = $versionNames
        CU      = $cuNames
        SU      = $suNames
    }
}

function ValidateSUParameter {
    param($name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.SU.Contains($Name)
}

function ValidateCUParameter {
    param($Name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.CU.Contains($Name)
}

function ValidateVersionParameter {
    param($Name)

    $possibleParameters = GetValidatePossibleParameters
    $possibleParameters.Version.Contains($Name)
}
function Test-ExchangeBuildGreaterOrEqualThanBuild {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$CurrentExchangeBuild,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$CU,
        [Parameter(Mandatory = $false)]
        [string]$SU
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $testResult = $false
    } process {
        if ($CurrentExchangeBuild.MajorVersion -eq $Version) {
            $params = @{
                Version = $Version
                CU      = $CU
            }

            if (-not([string]::IsNullOrEmpty($SU))) {
                $params.SU = $SU
            }
            $testBuild = Get-ExchangeBuildVersionInformation @params
            $testResult = $CurrentExchangeBuild.BuildVersion -ge $testBuild.BuildVersion
        }
    } end {
        Write-Verbose "Result $testResult"
        return $testResult
    }
}

function Test-ExchangeBuildLessThanBuild {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$CurrentExchangeBuild,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$CU,
        [Parameter(Mandatory = $false)]
        [string]$SU
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $testResult = $false
    } process {
        if ($CurrentExchangeBuild.MajorVersion -eq $Version) {
            $params = @{
                Version = $Version
                CU      = $CU
            }

            if (-not([string]::IsNullOrEmpty($SU))) {
                $params.SU = $SU
            }

            $testBuild = Get-ExchangeBuildVersionInformation @params
            $testResult = $CurrentExchangeBuild.BuildVersion -lt $testBuild.BuildVersion
        }
    } end {
        Write-Verbose "Result $testResult"
        return $testResult
    }
}

function Test-ExchangeBuildEqualBuild {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$CurrentExchangeBuild,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$CU,
        [Parameter(Mandatory = $false)]
        [string]$SU
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $testResult = $false
    } process {
        if ($CurrentExchangeBuild.MajorVersion -eq $Version) {
            $params = @{
                Version = $Version
                CU      = $CU
            }

            if (-not([string]::IsNullOrEmpty($SU))) {
                $params.SU = $SU
            }
            $testBuild = Get-ExchangeBuildVersionInformation @params
            $testResult = $CurrentExchangeBuild.BuildVersion -eq $testBuild.BuildVersion
        }
    } end {
        Write-Verbose "Result $testResult"
        return $testResult
    }
}

function Test-ExchangeBuildGreaterOrEqualThanSecurityPatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [object]$CurrentExchangeBuild,
        [string]$SUName
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $testResult = $false
    } process {
        $allSecurityPatches = Get-ExchangeBuildVersionInformation -FindBySUName $SUName |
            Where-Object { $_.MajorVersion -eq $CurrentExchangeBuild.MajorVersion } |
            Sort-Object ReleaseDate -Descending

        if ($null -eq $allSecurityPatches -or
            $allSecurityPatches.Count -eq 0) {
            Write-Verbose "We didn't find a security path for this version of Exchange."
            Write-Verbose "We assume this means that this version of Exchange $($CurrentExchangeBuild.MajorVersion) isn't vulnerable for this SU $SUName"
            $testResult = $true
            return
        }

        # The first item in the list should be the latest CU for this security patch.
        # If the current exchange build is greater than the latest CU + security patch, then we are good.
        # Otherwise, we need to look at the CU that we are on to make sure we are patched.
        if ($CurrentExchangeBuild.BuildVersion -ge $allSecurityPatches[0].BuildVersion) {
            $testResult = $true
            return
        }
        Write-Verbose "Need to look at particular CU match"
        $matchCU = $allSecurityPatches | Where-Object { $_.CU -eq $CurrentExchangeBuild.CU }
        Write-Verbose "Found match CU $($null -ne $matchCU)"
        $testResult = $null -ne $matchCU -and $CurrentExchangeBuild.BuildVersion -ge $matchCU.BuildVersion
    } end {
        Write-Verbose "Result $testResult"
        return $testResult
    }
}



function Invoke-CatchActionErrorLoop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$CurrentErrors,
        [Parameter(Mandatory = $false, Position = 1)]
        [ScriptBlock]$CatchActionFunction
    )
    process {
        if ($null -ne $CatchActionFunction -and
            $Error.Count -ne $CurrentErrors) {
            $i = 0
            while ($i -lt ($Error.Count - $currentErrors)) {
                & $CatchActionFunction $Error[$i]
                $i++
            }
        }
    }
}

# Common method used to handle Invoke-Command within a script.
# Avoids using Invoke-Command when running locally on a server.
function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [string]
        $ScriptBlockDescription,

        [object]
        $ArgumentList,

        [bool]
        $IncludeNoProxyServerOption,

        [ScriptBlock]
        $CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $returnValue = $null
        $currentErrors = $null
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose "Description: $ScriptBlockDescription"
        }

        try {

            if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {

                $params = @{
                    ComputerName = $ComputerName
                    ScriptBlock  = $ScriptBlock
                    ErrorAction  = "Stop"
                }

                if ($IncludeNoProxyServerOption) {
                    Write-Verbose "Including SessionOption"
                    $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
                }

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Invoke-Command with argument list"
                    $params.Add("ArgumentList", $ArgumentList)
                } else {
                    Write-Verbose "Running Invoke-Command without argument list"
                }

                $returnValue = Invoke-Command @params
            } else {
                # Handle possible errors when executed locally.
                $currentErrors = $Error.Count

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Script Block Locally with argument list"

                    # if an object array type expect the result to be multiple parameters
                    if ($ArgumentList.GetType().Name -eq "Object[]") {
                        $returnValue = & $ScriptBlock @ArgumentList
                    } else {
                        $returnValue = & $ScriptBlock $ArgumentList
                    }
                } else {
                    Write-Verbose "Running Script Block Locally without argument list"
                    $returnValue = & $ScriptBlock
                }

                Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
            }
        } catch {
            Write-Verbose "Failed to run $($MyInvocation.MyCommand) - $ScriptBlockDescription"

            # Possible that locally we hit multiple errors prior to bailing out.
            if ($null -ne $currentErrors) {
                Invoke-CatchActionErrorLoop $currentErrors $CatchActionFunction
            } else {
                Invoke-CatchActionError $CatchActionFunction
            }
        }
    }
    end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return $returnValue
    }
}
function Get-ExSetupFileVersionInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $exSetupDetails = [string]::Empty
    function Get-ExSetupDetailsScriptBlock {
        try {
            $getCommand = Get-Command ExSetup -ErrorAction Stop | ForEach-Object { $_.FileVersionInfo }
            $getItem = Get-Item -ErrorAction SilentlyContinue $getCommand[0].FileName
            $getCommand | Add-Member -MemberType NoteProperty -Name InstallTime -Value ($getItem.LastAccessTime)
            $getCommand
        } catch {
            try {
                Write-Verbose "Failed to find ExSetup by environment path locations. Attempting manual lookup."
                $installDirectory = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction Stop).MsiInstallPath

                if ($null -ne $installDirectory) {
                    $getCommand = Get-Command ([System.IO.Path]::Combine($installDirectory, "bin\ExSetup.exe")) -ErrorAction Stop | ForEach-Object { $_.FileVersionInfo }
                    $getItem = Get-Item -ErrorAction SilentlyContinue $getCommand[0].FileName
                    $getCommand | Add-Member -MemberType NoteProperty -Name InstallTime -Value ($getItem.LastAccessTime)
                    $getCommand
                }
            } catch {
                Write-Verbose "Failed to find ExSetup, need to fallback."
            }
        }
    }

    $exSetupDetails = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock ${Function:Get-ExSetupDetailsScriptBlock} -ScriptBlockDescription "Getting ExSetup remotely" -CatchActionFunction $CatchActionFunction
    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    return $exSetupDetails
}

function Get-ProcessedServerList {
    [CmdletBinding()]
    param(
        [string[]]$ExchangeServerNames,

        [string[]]$SkipExchangeServerNames,

        [bool]$CheckOnline,

        [bool]$DisableGetExchangeServerFullList,

        [string]$MinimumSU,

        [bool]$DisplayOutdatedServers = $true
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        # The complete list of all the Exchange Servers that we ran Get-ExchangeServer against.
        $getExchangeServer = New-Object System.Collections.Generic.List[object]
        # The list of possible validExchangeServers prior to completing the list.
        $possibleValidExchangeServer = New-Object System.Collections.Generic.List[object]
        # The Get-ExchangeServer object for all the servers that are either in ExchangeServerNames or not in SkipExchangeServerNames and are within the correct SU build.
        $validExchangeServer = New-Object System.Collections.Generic.List[object]
        # The FQDN of the servers in the validExchangeServer list
        $validExchangeServerFqdn = New-Object System.Collections.Generic.List[string]
        # Servers that are online within the validExchangeServer list.
        $onlineExchangeServer = New-Object System.Collections.Generic.List[object]
        # The FQDN of the servers that are in the onlineExchangeServer list
        $onlineExchangeServerFqdn = New-Object System.Collections.Generic.List[string]
        # Servers that are not reachable and therefore classified as offline
        $offlineExchangeServer = New-Object System.Collections.Generic.List[string]
        # The FQDN of the servers that are not reachable and therefore classified as offline
        $offlineExchangeServerFqdn = New-Object System.Collections.Generic.List[string]
        # The list of servers that are outside min required SU
        $outdatedBuildExchangeServerFqdn = New-Object System.Collections.Generic.List[string]
    }
    process {
        if ($DisableGetExchangeServerFullList) {
            # If we don't want to get all the Exchange Servers, then we need to make sure the list of Servers are Exchange Server
            if ($null -eq $ExchangeServerNames -or
                $ExchangeServerNames.Count -eq 0) {
                throw "Must provide servers to process when DisableGetExchangeServerFullList is set."
            }

            Write-Verbose "Getting the result of the Exchange Servers individually"
            foreach ($server in $ExchangeServerNames) {
                try {
                    $result = Get-ExchangeServer $server -ErrorAction Stop
                    $getExchangeServer.Add($result)
                } catch {
                    Write-Verbose "Failed to run Get-ExchangeServer for server '$server'. Inner Exception $_"
                    throw
                }
            }
        } else {
            Write-Verbose "Getting all the Exchange Servers in the organization"
            $result = @(Get-ExchangeServer)
            $getExchangeServer.AddRange($result)
        }

        if ($null -ne $ExchangeServerNames -and $ExchangeServerNames.Count -gt 0) {
            $getExchangeServer |
                Where-Object { ($_.Name -in $ExchangeServerNames) -or ($_.FQDN -in $ExchangeServerNames) } |
                ForEach-Object {
                    if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
                        if (($_.Name -notin $SkipExchangeServerNames) -and ($_.FQDN -notin $SkipExchangeServerNames)) {
                            Write-Verbose "Adding Server $($_.Name) to the valid server list"
                            $possibleValidExchangeServer.Add($_)
                        }
                    } else {
                        Write-Verbose "Adding Server $($_.Name) to the valid server list"
                        $possibleValidExchangeServer.Add($_)
                    }
                }
        } else {
            if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
                $getExchangeServer |
                    Where-Object { ($_.Name -notin $SkipExchangeServerNames) -and ($_.FQDN -notin $SkipExchangeServerNames) } |
                    ForEach-Object {
                        Write-Verbose "Adding Server $($_.Name) to the valid server list"
                        $possibleValidExchangeServer.Add($_)
                    }
            } else {
                Write-Verbose "Adding Server $($_.Name) to the valid server list"
                $possibleValidExchangeServer.AddRange($getExchangeServer)
            }
        }

        if ($CheckOnline -or (-not ([string]::IsNullOrEmpty($MinimumSU)))) {
            Write-Verbose "Will check to see if the servers are online"
            $serverCount = 0
            $paramWriteProgress = @{
                Activity        = "Retrieving Exchange Server Build Information"
                Status          = "Progress:"
                PercentComplete = $serverCount
            }
            Write-Progress @paramWriteProgress

            foreach ($server in $possibleValidExchangeServer) {
                $serverCount++
                $paramWriteProgress.Activity = "Processing Server: $server"
                $paramWriteProgress.PercentComplete = (($serverCount / $possibleValidExchangeServer.Count) * 100)
                Write-Progress @paramWriteProgress

                $exSetupDetails = Get-ExSetupFileVersionInfo -Server $server.FQDN

                if ($null -ne $exSetupDetails -and
                    (-not ([string]::IsNullOrEmpty($exSetupDetails)))) {
                    # Got some results back, they are online.
                    $onlineExchangeServer.Add($server)
                    $onlineExchangeServerFqdn.Add($server.FQDN)

                    if (-not ([string]::IsNullOrEmpty($MinimumSU))) {
                        $params = @{
                            CurrentExchangeBuild = (Get-ExchangeBuildVersionInformation -FileVersion $exSetupDetails.FileVersion)
                            SU                   = $MinimumSU
                        }
                        if ((Test-ExchangeBuildGreaterOrEqualThanSecurityPatch @params)) {
                            $validExchangeServer.Add($server)
                        } else {
                            Write-Verbose "Server $($server.Name) build is older than our expected min SU build. Build Number: $($exSetupDetails.FileVersion)"
                            $outdatedBuildExchangeServerFqdn.Add($server.FQDN)
                        }
                    } else {
                        $validExchangeServer.Add($server)
                    }
                } else {
                    Write-Verbose "Server $($server.Name) not online"
                    $offlineExchangeServer.Add($server)
                    $offlineExchangeServerFqdn.Add($server.FQDN)
                }
            }

            Write-Progress @paramWriteProgress -Completed
        } else {
            $validExchangeServer.AddRange($possibleValidExchangeServer)
        }

        $validExchangeServer | ForEach-Object { $validExchangeServerFqdn.Add($_.FQDN) }

        # If we have servers in the outdatedBuildExchangeServerFqdn list, the default response should be to display that we are removing them from the list.
        if ($outdatedBuildExchangeServerFqdn.Count -gt 0) {
            if ($DisplayOutdatedServers) {
                Write-Host ""
                Write-Host "Excluded the following server(s) because the build is older than what is required to make a change: $([string]::Join(", ", $outdatedBuildExchangeServerFqdn))"
                Write-Host ""
            }
        }
    }
    end {
        return [PSCustomObject]@{
            ValidExchangeServer             = $validExchangeServer
            ValidExchangeServerFqdn         = $validExchangeServerFqdn
            GetExchangeServer               = $getExchangeServer
            OnlineExchangeServer            = $onlineExchangeServer
            OnlineExchangeServerFqdn        = $onlineExchangeServerFqdn
            OfflineExchangeServer           = $offlineExchangeServer
            OfflineExchangeServerFqdn       = $offlineExchangeServerFqdn
            OutdatedBuildExchangeServerFqdn = $outdatedBuildExchangeServerFqdn
        }
    }
}

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
$logoBase64 = @'
iVBORw0KGgoAAAANSUhEUgAAAIIAAACCCAYAAACKAxD9AAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAJcEhZcwAAFiUAABYlAUlSJPAAAAAZdEVYdFNvZnR3YXJlAEFkb2JlIEltYWdlUmVh
ZHlxyWU8AAABh2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSfvu78n
IGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4NCjx4OnhtcG1ldGEgeG1sbnM6eD0iYWRv
YmU6bnM6bWV0YS8iPjxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8w
Mi8yMi1yZGYtc3ludGF4LW5zIyI+PHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9InV1aWQ6ZmFm
NWJkZDUtYmEzZC0xMWRhLWFkMzEtZDMzZDc1MTgyZjFiIiB4bWxuczp0aWZmPSJodHRwOi8vbnMu
YWRvYmUuY29tL3RpZmYvMS4wLyI+PHRpZmY6T3JpZW50YXRpb24+MTwvdGlmZjpPcmllbnRhdGlv
bj48L3JkZjpEZXNjcmlwdGlvbj48L3JkZjpSREY+PC94OnhtcG1ldGE+DQo8P3hwYWNrZXQgZW5k
PSd3Jz8+LJSYCwAAFR9JREFUeF7tXX2MXNV1/9333szsV/GGxHaAuHwWQpVgcFopQFANTqJEfEgo
qlSpbTBVKSRFkPSPEkVqbKdRRNIYnIo0hLRgFJo/GhwwSqtEKmbzB6LFDt7FJODF2FvHscHrXa/t
2a+ZefP6x7v3vvPOu/fN7Mzs7pvZ+Ulv991zzj3v3nN+cz/e250HdNFFF1100UUXXXTRRRdddNFF
F13UB8EFLcRi+k5DwAUZQybj0upGiTverGyGwF2OcP+EK5cC1Wp1RMDZsftqsZPrlhHiqn8/sVkI
PAjHXc+VS4FqUP2lqAZPH/zzC3aaSNEyItw+PHupyOeec9zl6ShHtVodEX5l8+6PFIa5bilxxY+P
XecF7lPISFxQ9UeqFdw5+vkLjlBxS4jw6ZeOXtHzwQv3OY67iuuWFdXqVKU0u+ln6wde46qlwOVP
jm3wenteFMIZ5LrlRBBUp4Ly3IbRz1+iyeDETRqC07v2wl2ZIwEAOM6gl+998baR4gauWmxc/uTY
hlxPz56skQAAhHAGHbfwHM1/s0QQtw/P3i1c9xquyAyWgQyKBHCc7H04FFx3/VU/OrpZFZslgoO8
dxcXZg6SDHcMF6/jqlajLUig4OQ2A3DRJBEEgJzrejdxRSbhOINOoXfPHb+eXzQytBUJAAjXvakl
RLj11lt7uTDTcJxBx/EWhQxXPH3sOq+358V2IQFBHoBohgjOyZMnC1yYeUgy3La3dWuGy58c2+Dl
vJeyuDCsA14zRBAAnL179zZaf3nhOIPeQGsWkO02HRjgAXCaSaRQ80tbogW7iQ4gAeTyoKkRQR3t
iyZ2Ex1CAqgcNkoEhfYmAhrbTXQQCTSaJUJnYAG7iTbeHdjQkhGhc1DHbqLNdwep6BKBImU30YnT
AUWXCByG3USnkwBdIlhAyPDhnYc+1ukkQJcIKXCcQSffvwf5gU5aGFrRJUIKHAerVgIJ0BIiBEH7
Hl1oNE2EoFrN/hEExqNLigjNEyGoZv+o+giqPlD1gaAqjyBGkpVOiEZvETvyOfba2/YXx7gyKxC6
d6SbQgACEMIBHAdCyEcm0jgsR5Xf2j8e1e1AvPVnay4AMJEkwjcObgawBQ4uSf71u+kv4hWIwmZj
kytFoJrThK9A/zDII/T2ubjq6kH8/mXnAa4bIwQlw0ohQnxq+OZbT8HBUxALIUFAEmmzSZEjCAkQ
iPp82eSAHNqZ0iACgNkZH8P7JvDa/7yHoFJB4PsI1JShpogVNFVERPjGwc2A2GwKmjmYdSQNaTo1
L7eIAKakGUSA8hU6PHZ0Gv93cBxBpQL4ci0RhGuHlYSICAG2JAJnDD4TJvQSxroIhZoAskxURqTJ
TQmzXlvZx6/59sFp+KU5uaAMdxqaDCb/HYiICA4u0efWQLKkmWxscqUI5FzcjK8AyYRqeVykwZNK
bGfnAviz0+H0oMjA7Tscye2jse8kaqnB5gKFRV4HwCwClC+mNNhWZmdQrZTlljJcK+iG8PodCDo1
GAJEhEa9hFXXynUAzAmx1dH2RJliWy2V5KKxAlSr4WG7ZgciOSIAyYjZYmELLBZjHcAMDCINbm+z
JfLALyPw5e5BjgpBzIfJQefAQIQ6AgibXFZYtnWAqkPL1MAur1bKqGoi+EA1iNYK3LgDQYhAOpzW
d6sukLpWTAMWpUEEKF+sTpotLwfQ00J4O1quE1YQkiMCD5SCJTdhFBcwDVj90ISa5FxI7dk1rbYG
mVQEvo/AV1vHsE8rZTRA7cViilwpFjoNmBAgmVAtj4s0uL3N1iQ3XC98UqluJpHto7btWAQwjggU
1v4v8nbQINIwJcZka/Kh6xrq6yeSarvIK3ceqjPTr6qOmolgjUMrt4Mq4FzOBRKBrEMNbP65TNsx
Bamv7iYCahSIm3Yi5o+PPg/AR+z57D++FdstxSGDw6cAqTJh48V92HhJHxfbYfETIlIOHZnB0OHp
mFbD5MNGAIYbrvwdetZcBK+3D25PL5x8AU6+gNEDpyEcN/zvwOi5dtujMjM9euivLr0dwDiAYtSz
r79lCI/6uNS5EEQk37rxA9iy8QNc2zS27RnH1j3s0bCpLSYCmESyfMOVx9Cz9iJ4vf1wCr1w8wU4
hc4kgl8uFc/+4of3vPfMtlcAnAFQNE8NQBihVq0DFhP8mgGSU4iWx0URWWjfiBG37wD45VJxcvdj
X3zvmW0jACpyaggMRGjhOmAxwa+ry6wx3E7LWN8SBgaY1jRtBL9cKk7tfvSBiWcfHgEwD6AkyUCJ
sMD7AWhA3ipw/5oABhLwMicAt+lQ+OVSceqnjz4w/uz2/QBmCRHYiLDQ+wFWuU25CLBdj4t0WQq5
ntfvMPjlUvH08488OP7c9mFJgjn5WxMhWv1sezOKhi0uNjlUQiJsvXm1dbE4NlXG0/un4sI03wRD
h9WuwVDBIIoRgJ0CajcE3PDh43rX4PT0ws33wIeHI6Nno8UiYn8R2xbwy6XixAv/fP/kT749AmBG
EmBaksFCBFMgwYPHwAMtsXXjamy52UyEoSMzuPlJ8sfPyeohuFyXmYLbaVltAiiYiHCuGOC947Nt
SwRCAjUSTEsyKBLIGyf8FrMJafJ6huU02GxNcp1Yw/V4WdvyKrJgqmPA7HSZi9oGfrlUnHhek0BN
BYoEZUoCWO8sggeQyw1KgygVJluTj3qvp8vyhOtNMl4m8P0AZybnubgtoNYEk7u+PSITP8NI4POe
J4mQEhxjQmAWLRjcRyyxJjmTUUVMr3ZDcVHCB8PUqVkuagsoEpza9YjaHSgSzNpIgMTUkFBLBEgs
BiM5F9LE1AGTD12fKGx21u2gLNA6Rh/JZx6VUhVTE+1HBEYCRQBFAr0w5PVgHBEoeKBj8rhIw2Rv
gsks7Xq8HBBFrIoscDcJH0kCKJw4eg6+b9ZlFWpheGrXI6+RRWFdJEAqEWwJsbkKVB1Srhe6bh3X
C4gioTfIeBmsnYjrTx6fxvxchWozD7Y7mJFEKMrzmiSAkQi2T4pBBKhAs2jbbDl0NUNiuA9+nZi+
znUA7xu7/viJaZybaq8FYh27g5okQOwx9NfeNOyrarjghCHFrbesxpZbVlNt0xg6PI2bf0BfRWQi
halsb2dIIuCyVYcQ9K+BU+iFyPdA5AoQXgHCdTN7H4GsCV5jC8OZhZAAyT9eJdCfFgOsn6ylRB3T
QGo746NIueRHdm2ARncHNiSnBqRUD2RwuWxJsYBpIFamJ4b6bYRmdgc2kKnhNzVuMdsCyyDlWzct
0tTw+OFIYGpDKgEMdWTf1vWNwnvfBQ1NDWcm5zBTLGGmWF6akaVSLmLvM/fgl9vplNAwCZC4j2CC
aSFosuVyk00rwf3XnAYM7eN9WwCqfoBT707j7QPjOHH0LM5Mzi0NCQDAyw3g43/5BO7cftlCdwc2
RPT+h9/EHQT6BykbYJIHckTYZB4RpuZ8DB+f4+KaGP7dLL78wom40DoCyAJvHyUH+bWuv/4RYX62
gmNHzixd4m2o+mdx+vBn8cM7X22GBDASgRPAUNTgchLkrZvWWIkwdHgaNz8xFndQdwKpzNbOeJI1
aN+Yrl4inDk9jxNHz8YrLyuCMyhPb8L2j/+KaxYCdos5SCaHB9Mk12WuSANJiK6ygIVgM9OAyV8d
ODM5lzESAIBYBW/gv/F3wzVfMZAG8/aRBzJNHtgUNRCrIgvcRaJciwAmEhEj3kzuLwXzs2Wc+G3W
SCAhMIict6cZMiS3j6a48ABqmUFhEKXD9gkmZahrqXOqtxFAnXB76Yv7S4HvV3Fs7AwXZwuKDF/a
m3jFQD2o/fSRy3iQE3JSTkVaAqnMljRpnLAnOl1WOoMvbW/H6fFZlEtt8N/RAoMo9L7YCBmSI4KC
MSkGRapdCmIJMphbkyYLvE4g6yhhQs8uoIqcjAxVP8DkeBs9km6QDEki8ABqmUFhtDMpUsBNaxLA
NIoQI95Mqz8mt+DcmXlUq7XtMgVFhgWsGdKnBh7kmDwu0sFF+icMIPW5HU+MLtoIQIy4v1oE4L4s
KJ5tr6eRGgtcQEb3Eb766ygcNAEUpoDRZJDTrZ9agy2fXBPJCcZOl/D0PvLn7JwAFAbV0KEihg6d
iwTchhNAnSTsopN1q94x3kc4MjqFciX6rmYasrZAgCmUK7fgkWv3cxVFkgg8sQpcxO1i+gBbP7kW
Wz5lJkKz2PaLd7H15+8a2sQEqmiTq5MAWDdoJsLoG5OA47YvESDJMD+7CTv++DWuUki/oaTlpnIU
RE4C7qLl4NesNQ1Q6LbLdi52W7OAOhaQ5htKqsiDRIOoy0TJ597FRi0C0LbEdLztKwA1yNDYriFm
Ywn6YsP2STe1xaaL6VcAUnYTcSLwgNQiACyBXUqoNvEk67amtFPX48oOhtpNPBQnQ7Ty+cobUTRi
yTYl1xJYgo2X9WPj5f1xoQKvC8SFRn2EobfPYejtoiyltSVFx5K/7vzDnbtYNMIfwcPrr1MRSRIh
0D9CxOKVEtiYjAlpYmJlKrbpUnwlbMkJ10lx+Dvpc937VxoRAJRLf43tG/4NqbsGchoG1jb0Uhkb
ZhM+WB3TNSkMCdPyhB95wnVUz9undIkKKwSuuAuAC+OugeRFF3icEuVaBDAljhjF7FP82eRp7TTV
0zpLvZUCJ3cTAA/JEYFa2T7BpAwVTHVO9TYCqBNuL30Z/VkSqU64HylO+KNyW72VhxyiP8SjSEsg
lRmSpk8Mn7KA6HRZ6Qy+lL21LQYd1RsJoE7Y9U3llQOPEUFGyhh0KrMlTRZ4HZ0UkoCYnl1AFXmS
db06CGD0KQ1M1+f2KwsuAMc+NfDY8IDF7A3JUUlRwoR/m78UORoggGoDvz69Dve5suCap4ZEwFQw
aZmcGAlAjLg/njBqb/KlTrgfKQ5/G9pXiwC6LtWtSAjoxeJDb4Yv/ORBSUuaCjIF1eky1Vt8mQhg
01F9avss11cybWuws94rsMnbHyERvnV1/P3O1gDLQqxMkkITENMb/Gl5JI7qyROqo3ruT+lovZia
2FOd8oWADI5Rsg3/3daJICMCAAQYSwQ4FlDDp1PrDUGGDLLRny2RSsf9qMNSTyWT11PX0fWpKhK4
ogTheWHmdfJXBgsUCBGCbTENTYwKMhPFdDzIaQSw+eI6pYf0yeW6Dez63FfieqROAJyXPwnh5fWL
woUQkgaUGJ2NiAiPrN8JBDvjATYlmeh0meqZQNnzJNPrcB3Vp5EKpvYxAsTOiUD66HXGMXBeBSKX
l4knB7BiRob4rmH7tXcDuBsIxpIBNgQykQAiUHqeZF1PnlAd1XN/SkfrxdTEnusS7Q7gBjNYJUZx
/u+dhNPTDwgXcBw9KqyUBYJCo711AOQBrF39pw/FF5pZAJ/n5SdcOC7guBBuDqLQC7d/FZy+VXB6
B+Dke+EUeiBy6sljHsLL4eCBCfLSjkbDlWE8/JELAEw02jNNhA/e853sEUFDzfECEI7+z2bh5iBy
efm4uQdOTz+cfI8uKxIIVxFBjRCNhivDaBURLvzb72WYCGoPKEcE1wUcD8L1QiJ4+ZAIhT6IfAEi
V4CTKwCSBML1cPD1LhHSoIlw0Zfp16xnBLFeSRIIEU4Ljgu4XviJ9woQuXw4GuRCIggvr0kA142I
0IkkQAuJsO6r/zGWXPEtFwzdIVtCOI5cI8hRwc2Fic9HawLh5kKiyPXEwddPdYmQAk2Ei7/+n9kb
ESgoEYQT7gzUqKDIkAtHAXgehKNI4KAa+NNvv34KcPP9XSKYoYlw6bdeagsiRDsHOSroHUQ4Tei1
gySBXykXJ5979EuT780KfOILj8LLD3DXHYFWEeHyHf+bXSII/SNa8AkHgo4MkgxQ58KB75eLk8/v
eHDy+e8eACBw470fxfX37uhIMrSKCFd8fyS7RKDDuWGKgHCiEUKEZUKCEfkNpgKAh+vvW48b/+a7
HUeGVhHhD/71YIaJQKF2DwiJALl4hJwuhAing5AE++Xr8CqaCEAB1993bceRoVVEuHLnkWwTQcS7
GL+FLG84CQfVSjn8qvtd20fkt5iqbzcXsq89AHpw433X4Pp7H4OX6wwySCLEnzU0gGgrlsHDC+8H
0ANOeH8g3EqG64SqXylOvPC9+yd3bVfvOygCOCePs/J3+Iq8lx9/HS8/8QAqJfWvVh2BpomgFlmZ
POS8Lxx1uOFvEZ37lXJxYvdj90/uSrzvQI0K8wnZK98fwStPPNhJZGiaCFGQs3soQsQOCPjlcvH0
7h213oZWkd9zTMkwi5cfH+4kMjRNBDnJtskBvY30K+Xi6d2P1nrfQVUeviQDtekoMjRPBL0/b5Oj
sfcdpJPh5fYnQ/NEaDM08Ta0KpkmZmJ1X3l8P1554n5Uym1LhmaJsMzfU78wtOBtaIoM86xuO+8m
ArSACEFl9tw+LswiWvU2NDJNlNt+N1EqvtoqIvilo2/u5sKsoZF3JdeAjQzttYCcOPKcGtVdrqsT
QtbNnRn68dH33fqFTzu5/Pu5URbQ6rehEag69E9lw9Xob/dNQIhhXHTtJjhuXtfIEuZmRvGDz3xN
TnGlRokARQQAOf/s+Bt962+51XGz1ekGdgcLBSWD+vr2iAyBGMaHMkiGSrmIl7bfi3ffOKFGxUaJ
oDbmHgBvfuzAtD95/OX+qz/xMZEvnM+NlwPV2XOHJn72L1+ZePY7amFIh/BWkEBBjQiKDJHPY/tO
QYhfYe0ffhRePhNxwVzxHbz4zS9i+Cejem0DlORdlobgygcxA+To/9Df/+iOnss2fNYbXH0Nr7AU
qEyNvz73zv7/OvZPf7Fbz9vRVq/RNUE9cMgo2QugXx4FAAP43GO35y/+o8+U8gPLEhfMTIzg+IGf
49n7d8vdDj3mmyGCQzo9AKBPEqMgn9Z56n/vecVFglrAqb3+PHlOUFxkEihQMvTJuNCYqLg4LVio
1wtTXObkh2NarZWaSZJaMOYlGfrkb9VZITvbzDUWAjU00xs/qsPNLgwXAkWGvIyJ+oDkMhQXNUrq
uDTbGLVOUCMDZb/qbLPXqBdqnlbbOjUaqCeI8fl7caHIUNB/xxCe55Y5LmpEUHHRH45WNEYNczlJ
AEUEOi204jppUAlWrC/LTpeWcCTgoNOEmhZy6juLpM1ixoX2lz4rUWSo0Li0qiFquHPVTmKZma86
6S/xSMAhSOLVmkl9QJYiLqrfNePS6saoDi7lHEihyECPLGC54wKSeGNcFqtRi+W3XiQ6mhF049JF
F120Af4fj655QIFsSH0AAAAASUVORK5CYII=
'@

$logo = [Convert]::FromBase64String($logoBase64)
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

    try {
        if ((Get-Module -ErrorAction Stop).Name -contains "ExchangeOnlineManagement") {
            Write-Warning "We've detected that the ExchangeOnlineManagement module is loaded in this session"
            Write-Warning "Please open a new Exchange Management Shell and don't connect to Exchange Online"

            return
        }
    } catch {
        Write-Warning "Unable to query the modules which are loaded in this PowerShell session - Exception: $_"

        return
    }

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
            # Make sure that PowerShell runs in elevated mode - if it doesn't we don't need to proceed further - stop the script run
        if (-not (Confirm-Administrator)) {
            Write-Warning "This script must be executed in elevated mode - start the PowerShell as an Administrator and try again"

            return
        }
    
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

        # Do a basic check to find out if OAuth is configured in the environment - if it's not, we should not create the SO as this could break workflows
        try {
            # Check for the 'Exchange Online' partner application - we expect it to be there and that it's enabled
            $exchangeOnlinePartnerApplication = Get-PartnerApplication -ErrorAction Stop | Where-Object {
                $_.ApplicationIdentifier -eq $resourceAppId -and
                [System.String]::IsNullOrEmpty($_.Realm) -and
                $_.Enabled -eq $true
            }

            # Check for IntraOrganizationConnector (IOC) - we expect at least one to be found
            $ioc = Get-IntraOrganizationConnector -ErrorAction Stop

            $exchangePartnerApplicationFound = ($exchangeOnlinePartnerApplication.Count -ge 1)
            $iocFound = ($ioc.Count -ge 1)
            $enabledIoc = @($ioc | Where-Object { $_.Enabled })
            $disabledIoc = @($ioc | Where-Object { -not $_.Enabled })
            $basicOAuthConfigCheckPassed = ($exchangePartnerApplicationFound -and $enabledIoc)

            if (-not $exchangePartnerApplicationFound) {
                Write-Warning "We did not find the 'Exchange Online' partner application in your on-premises environment"
            } elseif ($exchangeOnlinePartnerApplication.Count -gt 1) {
                Write-Warning "Multiple enabled 'Exchange Online' partner applications found - this may indicate a misconfiguration"
            }

            if (-not $iocFound) {
                Write-Warning "We did not find an IntraOrganizationConnector in your on-premises environment"
            }

            if ($enabledIoc.Count -eq 0) {
                Write-Warning "We did not find any enabled IntraOrganizationConnector in your on-premises environment"
            }

            foreach ($c in $enabledIoc) {
                Write-Verbose "We found the following enabled IntraOrganizationConnector: '$($c.Name)'"
                Write-Verbose "TargetAddressDomain: $($c.TargetAddressDomains) - DiscoveryEndpoint: $($c.DiscoveryEndpoint)"
            }

            foreach ($c in $disabledIoc) {
                Write-Warning "The following IntraOrganizationConnector is disabled:"
                Write-Warning "Name: $($c.Name) - TargetAddressDomain: $($c.TargetAddressDomains)"
            }

            if (-not $exchangePartnerApplicationFound -or
                -not $iocFound -or
                $enabledIoc.Count -eq 0) {
                Write-Warning "It seems like your OAuth configuration is invalid - are you using DAuth instead of OAuth?"
                Write-Host ""
            }
        } catch {
            Write-Warning "Unable to query OAuth related settings - Exception: $_"

            return
        }

        # Check if the setting override already exists and if it doesn't, create the setting override to enable the feature run Get-ExchangeDiagnosticInfo first to avoid caching issues
        Get-ExchangeDiagnosticInfo -Process "Microsoft.Exchange.Directory.TopologyService" -Component "VariantConfiguration" -Argument "Refresh" | Out-Null
        $settingOverrides = Get-ExchangeSettingOverride -Server $env:COMPUTERNAME

        # Check if we have at least one setting override
        if (($null -ne $settingOverrides) -and
            ($settingOverrides.SimpleSettingOverrides.Count -gt 0)) {
            # Filter out the overrides which enable or disable the ExchangeOnpremAsThirdPartyAppId feature
            $featureSettingOverrides = $settingOverrides.SimpleSettingOverrides | Where-Object {
                ($_.SectionName -eq "ExchangeOnpremAsThirdPartyAppId") -and
                ($_.ComponentName -eq "Global")
            }

            if ($null -ne $featureSettingOverrides) {
                Write-Warning "The following Setting Override(s) already exist:"
                Write-Host ""

                # If we find some, check whether they enable or disable the feature explicitly
                $featureEnabledCount = 0
                foreach ($o in $featureSettingOverrides) {
                    $match = [regex]::Match($o.Parameters, "^\s*Enabled\s*=\s*(true|false)\s*$", "IgnoreCase")
                    $featureIsEnabled = ($match.Success -and $match.Groups[1].Value)
                    $featureSettingOverrideValue = if (-not $match.Success) { "Unknown" } else { $match.Groups[1].Value }

                    if ($featureIsEnabled) {
                        $featureEnabledCount++
                    }

                    Write-Host ("[Setting Override] Name: '{0}' Feature enabled? '{1}'" -f $o.Name, $featureSettingOverrideValue)

                    $3pSettingOverridesObject.Add($o)
                }

                Write-Host ""
                Write-Warning "Run the following command if you want to remove the existing Setting Override(s):"
                Write-Warning "Get-SettingOverride | Where-Object {`$_.ComponentName -eq `"Global`" -and `$_.SectionName -eq `"ExchangeOnpremAsThirdPartyAppId`"} | Remove-SettingOverride -Confirm:`$false"

                if ($featureEnabledCount -gt 0 -and
                    -not $basicOAuthConfigCheckPassed) {
                    Write-Host ""
                    Write-Warning "The dedicated hybrid application feature is enabled, but your OAuth configuration appears to be incomplete"
                    Write-Warning "Please review your OAuth configuration and either fix it manually or run the Hybrid Configuration Wizard (HCW)"
                }

                return
            }
        }

        # If no setting overrides, which control the dedicated Exchange hybrid application feature, exists we'll create a new global override, otherwise, do nothing and display the name of the existing overrides
        # We only do this if the basic OAuth configuration check has passed
        if (-not $basicOAuthConfigCheckPassed) {
            Write-Warning "The feature cannot be enabled because the configuration is incomplete"
            Write-Warning "Please review your OAuth configuration and either fix it manually or run the Hybrid Configuration Wizard (HCW)"

            return
        } elseif ($3pSettingOverridesObject.Count -eq 0) {
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
