# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Users
#Requires -Modules Microsoft.Graph.Groups
#Requires -Modules ExchangeOnlineManagement -Version 3.0.0

<#
.SYNOPSIS
Evaluates user coverage and potential redundancies in Microsoft Defender for Office 365 and Exchange Online Protection threat policies, including anti-malware, anti-phishing, and anti-spam policies, as well as Safe Attachments and Safe Links policies if licensed.

.DESCRIPTION
This script checks which Microsoft Defender for Office 365 and Exchange Online Protection threat policies cover a particular user, including anti-malware, anti-phishing, inbound and outbound anti-spam, as well as Safe Attachments and Safe Links policies in case these are licensed for your tenant. In addition, the script can check for threat policies that have inclusion and/or exclusion settings that may be redundant or confusing and lead to missed coverage of users or coverage by an unexpected threat policy. It also includes an option to show all the actions and settings of the policies that apply to a user.

.PARAMETER CsvFilePath
    Allows you to specify a CSV file with a list of email addresses to check.
.PARAMETER EmailAddress
    Allows you to specify email address or multiple addresses separated by commas.
.PARAMETER IncludeMDOPolicies
    Checks both EOP and MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddress parameter.
.PARAMETER OnlyMDOPolicies
    Checks only MDO (Safe Attachment and Safe Links) policies for user(s) specified in the CSV file or EmailAddress parameter.
.PARAMETER ShowDetailedPolicies
    In addition to the policy applied, show any policy details that are set to True, On, or not blank.
.PARAMETER ShowDetailedExplanation
    Show specific explanation about why a policy is matched or not.
.PARAMETER SkipConnectionCheck
    Skips connection check for Graph and Exchange Online.
.PARAMETER SkipVersionCheck
    Skips the version check of the script.
.PARAMETER ScriptUpdateOnly
    Just updates script version to latest one.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1
	To check all threat policies for potentially confusing user inclusion and/or exclusion conditions and print them out for review.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv]
	To provide a CSV input file with email addresses and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddress user1@contoso.com,user2@fabrikam.com
	To provide multiple email addresses by command line and see only EOP policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -CsvFilePath [Path\filename.csv] -IncludeMDOPolicies
	To provide a CSV input file with email addresses and see both EOP and MDO policies.

.EXAMPLE
	.\MDOThreatPolicyChecker.ps1 -EmailAddress user1@contoso.com -OnlyMDOPolicies
	To provide an email address and see only MDO (Safe Attachment and Safe Links) policies.
#>

[CmdletBinding(DefaultParameterSetName = 'AppliedTenant')]
param(
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOCsv')]
    [string]$CsvFilePath,

    [Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = 'AppliedEmail')]
    [Parameter(ValueFromPipeline = $true, Mandatory = $true, ParameterSetName = 'AppliedMDOEmail')]
    [string[]]$EmailAddress,

    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedEmail')]
    [switch]$IncludeMDOPolicies,

    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$OnlyMDOPolicies,

    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedEmail')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$ShowDetailedPolicies,

    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedEmail')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOCsv')]
    [Parameter(Mandatory = $false, ParameterSetName = 'AppliedMDOEmail')]
    [switch]$ShowDetailedExplanation,

    [Parameter(Mandatory = $false)]
    [switch]$SkipConnectionCheck,

    [Parameter(Mandatory = $false)]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly
)

begin {





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

    [string]$errorInformation = [System.Environment]::NewLine + [System.Environment]::NewLine +
    "----------------Error Information----------------" + [System.Environment]::NewLine

    if ($null -ne $CurrentError.OriginInfo) {
        $errorInformation += "Error Origin Info: $($CurrentError.OriginInfo.ToString())$([System.Environment]::NewLine)"
    }

    $errorInformation += "$($CurrentError.CategoryInfo.Activity) : $($CurrentError.ToString())$([System.Environment]::NewLine)"

    if ($null -ne $CurrentError.Exception -and
        $null -ne $CurrentError.Exception.StackTrace) {
        $errorInformation += "Inner Exception: $($CurrentError.Exception.StackTrace)$([System.Environment]::NewLine)"
    } elseif ($null -ne $CurrentError.Exception) {
        $errorInformation += "Inner Exception: $($CurrentError.Exception)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.InvocationInfo.PositionMessage) {
        $errorInformation += "Position Message: $($CurrentError.InvocationInfo.PositionMessage)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage) {
        $errorInformation += "Remote Position Message: $($CurrentError.Exception.SerializedRemoteInvocationInfo.PositionMessage)$([System.Environment]::NewLine)"
    }

    if ($null -ne $CurrentError.ScriptStackTrace) {
        $errorInformation += "Script Stack: $($CurrentError.ScriptStackTrace)$([System.Environment]::NewLine)"
    }

    $errorInformation += "-------------------------------------------------$([System.Environment]::NewLine)$([System.Environment]::NewLine)"

    & $Cmdlet $errorInformation
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
        Write-VerboseErrorInformation
    }
}

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

    $BuildVersion = "26.04.29.1054"

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

        if ($PSSenderInfo -and
            $null -ne $Script:WriteWarningRemoteManipulateMessageAction) {
            $Message = & $Script:WriteWarningRemoteManipulateMessageAction $Message
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

function SetWriteWarningRemoteManipulateMessageAction ($DebugAction) {
    $Script:WriteWarningRemoteManipulateMessageAction = $DebugAction
}

<#
.DESCRIPTION
    An override for Write-Host to allow logging to occur and color format changes to match with what the user as default set for Warning and Error.
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

    # Cache to reduce calls to Get-MgGroup
    $groupCache = @{}
    # Cache of members to reduce number of calls to Get-MgGroupMember
    $memberCache = @{}

    function Write-DetailedExplanationOption {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Message,
            [Parameter(Mandatory = $true)]
            [switch]$ShowDetailedExplanation
        )
        if ($ShowDetailedExplanation) {
            Write-Host "`t`t$message"
        } else {
            Write-Verbose $message
        }
    }

    function Get-GroupObjectId {
        [OutputType([string])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [MailAddress]$GroupEmail
        )

        $stGroupEmail = $GroupEmail.ToString()
        # Check the cache first
        Write-Verbose "Searching cache for Group $stGroupEmail"
        if ($groupCache.ContainsKey($stGroupEmail)) {
            Write-Verbose "Group $stGroupEmail found in cache"
            return $groupCache[$stGroupEmail]
        }

        # Get the group
        $group = $null
        Write-Verbose "Getting Group $stGroupEmail"
        try {
            $group = Get-MgGroup -Filter "mail eq '$stGroupEmail'" -ErrorAction Stop
        } catch {
            Write-Host "Error getting group $stGroupEmail`:`n$_" -ForegroundColor Red
            return $null
        }

        if ($group -and $group.id) {
            if ($group.Id.GetType() -eq [string]) {
                # Cache the result
                Write-Verbose "Added to cache Group $stGroupEmail with Id $($group.Id)"
                $groupCache[$stGroupEmail] = $group.Id

                # Return the Object ID of the group
                return $group.Id
            } else {
                Write-Host "Wrong type for $($group.ToString()): $($group.Id.GetType().Name)" -ForegroundColor Red
                return $null
            }
        } else {
            Write-Host "The EmailAddress of group $stGroupEmail was not found." -ForegroundColor Red
            return $null
        }
    }

    # Function to check if an email is in a group
    function Test-IsInGroup {
        [OutputType([bool])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [MailAddress]$Email,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$GroupObjectId
        )

        # Check the cache first
        $stEmail = $Email.ToString()
        $cacheKey = "$stEmail|$GroupObjectId"
        Write-Verbose "Searching cache for value of User in Group: $stEmail | $GroupObjectId"
        if ($memberCache.ContainsKey($cacheKey)) {
            Write-Verbose "Found $stEmail|$GroupObjectId in cache"
            return $memberCache[$cacheKey]
        }

        # Get the group members
        $groupMembers = $null
        Write-Verbose "Getting $GroupObjectId"
        try {
            $groupMembers = Get-MgGroupMember -GroupId $GroupObjectId -All -ErrorAction Stop
        } catch {
            Write-Host "Error getting group members for $GroupObjectId`:`n$_" -ForegroundColor Red
            $memberCache[$cacheKey] = $false
            return $false
        }

        # Check if the email address is in the group
        if ($null -ne $groupMembers) {
            foreach ($member in $groupMembers) {
                # Check if the member is a user
                if ($member['@odata.type'] -eq '#microsoft.graph.user') {
                    if ($member.Id) {
                        # Get the user object by Id
                        Write-Verbose "Getting user with Id $($member.Id)"
                        try {
                            $user = Get-MgUser -UserId $member.Id -ErrorAction Stop
                        } catch {
                            Write-Host "Error getting user with Id $($member.Id):`n$_" -ForegroundColor Red
                            $memberCache[$cacheKey] = $false
                            return $false
                        }
                        # Compare the user's email address with the $email parameter
                        if ($user.Mail -eq $Email.ToString()) {
                            # Cache the result
                            $memberCache[$cacheKey] = $true
                            return $true
                        }
                    } else {
                        Write-Host "The user with Id $($member.Id) does not have an email address." -ForegroundColor Red
                    }
                }
                # Check if the member is a group
                elseif ($member['@odata.type'] -eq '#microsoft.graph.group') {
                    Write-Verbose "Nested group $($member.Id)"
                    # Recursive call to check nested groups
                    $isInNestedGroup = Test-IsInGroup -Email $Email -GroupObjectId $member.Id
                    if ($isInNestedGroup) {
                        # Cache the result
                        Write-Verbose "Cache group $cacheKey"
                        $memberCache[$cacheKey] = $true
                        return $true
                    }
                }
            }
        } else {
            Write-Verbose "The group with Object ID $GroupObjectId does not have any members."
        }

        # Cache the result
        $memberCache[$cacheKey] = $false
        return $false
    }

    function Test-EmailAddress {
        [OutputType([MailAddress])]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$EmailAddress,
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string[]]$AcceptedDomains
        )

        try {
            $tempAddress = $null
            Write-Verbose "Casting $EmailAddress"
            $tempAddress = [MailAddress]$EmailAddress
        } catch {
            Write-Host "The EmailAddress $EmailAddress cannot be validated. Please provide a valid email address." -ForegroundColor Red
            Write-Host "Error details:`n$_" -ForegroundColor Red
            return $null
        }

        $domain = $tempAddress.Host
        Write-Verbose "Checking domain $domain"
        if ($AcceptedDomains -contains $domain) {
            Write-Verbose "Verified domain $domain for $tempAddress"
            $recipient = $null
            Write-Verbose "Getting $EmailAddress"
            try {
                $recipient = Get-EXORecipient $EmailAddress -ErrorAction Stop
                if ($null -eq $recipient) {
                    Write-Host "$EmailAddress is not a recipient in this tenant." -ForegroundColor Red
                } else {
                    return $tempAddress
                }
            } catch {
                Write-Host "Error getting recipient $EmailAddress $tempAddress" -ForegroundColor Red
                Write-Verbose "$_"
            }
        } else {
            Write-Host "The domain $domain is not an accepted domain in your organization. Please provide a valid email address: $tempAddress " -ForegroundColor Red
        }
        return $null
    }

    # Function to check rules
    function Test-Rules {
        param(
            [Parameter(Mandatory = $true)]
            $Rules,
            [Parameter(Mandatory = $true)]
            [MailAddress]$Email,
            [Parameter(Mandatory = $false)]
            [switch]$Outbound
        )

        foreach ($rule in $Rules) {
            $senderOrReceiver = $exceptSenderOrReceiver = $memberOf = $exceptMemberOf = $domainsIs = $exceptIfDomainsIs = $null
            $emailInRule = $emailExceptionInRule = $groupInRule = $groupExceptionInRule = $domainInRule = $domainExceptionInRule = $false
            Write-Host " "
            if ($Outbound) {
                Write-DetailedExplanationOption -Message "Checking outbound spam rule: `"$($rule.Name)`"" -ShowDetailedExplanation:$ShowDetailedExplanation
                $requestedProperties = 'From', 'ExceptIfFrom', 'FromMemberOf', 'ExceptIfFromMemberOf', 'SenderDomainIs', 'ExceptIfSenderDomainIs'
                $senderOrReceiver = $rule.From
                $exceptSenderOrReceiver = $rule.ExceptIfFrom
                $memberOf = $rule.FromMemberOf
                $exceptMemberOf = $rule.ExceptIfFromMemberOf
                $domainsIs = $rule.SenderDomainIs
                $exceptIfDomainsIs = $rule.ExceptIfSenderDomainIs
            } else {
                Write-DetailedExplanationOption -Message "Checking rule: `"$($rule.Name)`"" -ShowDetailedExplanation:$ShowDetailedExplanation
                $requestedProperties = 'SentTo', 'ExceptIfSentTo', 'SentToMemberOf', 'ExceptIfSentToMemberOf', 'RecipientDomainIs', 'ExceptIfRecipientDomainIs'
                $senderOrReceiver = $rule.SentTo
                $exceptSenderOrReceiver = $rule.ExceptIfSentTo
                $memberOf = $rule.SentToMemberOf
                $exceptMemberOf = $rule.ExceptIfSentToMemberOf
                $domainsIs = $rule.RecipientDomainIs
                $exceptIfDomainsIs = $rule.ExceptIfRecipientDomainIs
            }

            $Policy.PSObject.Properties | ForEach-Object {
                if ($requestedProperties -contains $_.Name) {
                    Write-Host "`t`t$($_.Name): $($_.Value)"
                }
            }
            Write-Verbose " "

            if ($senderOrReceiver -and $Email -in $senderOrReceiver) {
                Write-DetailedExplanationOption -Message "Included in rule as User." -ShowDetailedExplanation:$ShowDetailedExplanation
                $emailInRule = $true
            }
            if ($exceptSenderOrReceiver -and $Email -in $exceptSenderOrReceiver) {
                Write-DetailedExplanationOption -Message "Excluded from rule as User." -ShowDetailedExplanation:$ShowDetailedExplanation
                $emailExceptionInRule = $true
            }

            if ($memberOf) {
                foreach ($groupEmail in $memberOf) {
                    Write-DetailedExplanationOption -Message "Checking if recipient is in Group $groupEmail" -ShowDetailedExplanation:$ShowDetailedExplanation
                    $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $groupInRule = Test-IsInGroup -Email $Email -GroupObjectId $groupObjectId
                        if ($groupInRule) {
                            Write-DetailedExplanationOption -Message "Group membership match: $($Email.ToString()) is a member of Group $($groupObjectId)" -ShowDetailedExplanation:$ShowDetailedExplanation
                            break
                        } else {
                            Write-DetailedExplanationOption -Message "No Group match because $($Email.ToString()) is not a member of Group $($groupObjectId)" -ShowDetailedExplanation:$ShowDetailedExplanation
                        }
                    }
                }
            }

            if ($exceptMemberOf) {
                foreach ($groupEmail in $exceptMemberOf) {
                    Write-DetailedExplanationOption -Message "Checking if recipient is in excluded Group $groupEmail" -ShowDetailedExplanation:$ShowDetailedExplanation
                    $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                    if ([string]::IsNullOrEmpty($groupObjectId)) {
                        Write-Host "The group in $($rule.Name) with email address $groupEmail does not exist." -ForegroundColor Yellow
                    } else {
                        $groupExceptionInRule = Test-IsInGroup -Email $Email -GroupObjectId $groupObjectId
                        if ($groupExceptionInRule) {
                            Write-DetailedExplanationOption -Message "Excluded from rule by group membership. $($Email.ToString()) is in excluded Group $($groupObjectId)" -ShowDetailedExplanation:$ShowDetailedExplanation
                            break
                        } else {
                            Write-DetailedExplanationOption -Message "$($Email.ToString()) is not excluded from rule by membership in Group $($groupObjectId)" -ShowDetailedExplanation:$ShowDetailedExplanation
                        }
                    }
                }
            }

            $temp = $Email.Host
            while ($temp.IndexOf(".") -gt 0) {
                if ($temp -in $domainsIs) {
                    Write-DetailedExplanationOption -Message "Domain is in rule: $temp." -ShowDetailedExplanation:$ShowDetailedExplanation
                    $domainInRule = $true
                }
                if ($temp -in $exceptIfDomainsIs) {
                    Write-DetailedExplanationOption -Message "Excluded from rule by domain: $temp" -ShowDetailedExplanation:$ShowDetailedExplanation
                    $domainExceptionInRule = $true
                }
                $temp = $temp.Substring($temp.IndexOf(".") + 1)
            }

            # Check for explicit inclusion based on selected logic (AND or OR)
            # Exclusions are always OR: any exclusion match removes the user
            if ($Script:IncludeLogic -eq '1') {
                # AND logic: user must match ALL populated inclusion properties
                $isIncluded = ((($emailInRule -or (-not $senderOrReceiver)) -and ($domainInRule -or (-not $domainsIs)) -and ($groupInRule -or (-not $memberOf))) -and
                    ($emailInRule -or $domainInRule -or $groupInRule))
            } else {
                # OR logic: user must match ANY populated inclusion property
                $isIncluded = ($emailInRule -or $groupInRule -or $domainInRule)
            }

            if ($isIncluded -and
                ((-not $emailExceptionInRule) -and (-not $groupExceptionInRule) -and (-not $domainExceptionInRule))) {
                Write-DetailedExplanationOption -Message "Policy match found: `"$($rule.Name)`"" -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Included in rule as User: $emailInRule. Included in rule by Group membership: $groupInRule. Included in rule by Domain: $domainInRule." -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Excluded from rule as User: $emailExceptionInRule. Excluded from rule by group membership: $groupExceptionInRule. Excluded from rule by domain: $domainExceptionInRule." -ShowDetailedExplanation:$ShowDetailedExplanation
                return $rule
            } else {
                if ($Script:IncludeLogic -eq '1') {
                    Write-DetailedExplanationOption -Message "The rule/policy does not explicitly include the recipient because not all User, Group, and Domain properties which have values include the recipient. `n`t`tDue to the AND operator between the User, Group, and Domain inclusion properties, if any of those properties have non-null values (they are not empty), the recipient must be included in that property." -ShowDetailedExplanation:$ShowDetailedExplanation
                } else {
                    Write-DetailedExplanationOption -Message "The rule/policy does not explicitly include the recipient. The recipient does not match any of the User, Group, or Domain inclusion properties (OR condition)." -ShowDetailedExplanation:$ShowDetailedExplanation
                }
                Write-DetailedExplanationOption -Message "Included in rule as User: $emailInRule. Included in rule by Group membership: $groupInRule. Included in rule by Domain: $domainInRule." -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Excluded from rule as User: $emailExceptionInRule. Excluded from rule by group membership: $groupExceptionInRule. Excluded from rule by domain: $domainExceptionInRule." -ShowDetailedExplanation:$ShowDetailedExplanation
            }

            # Check for implicit inclusion (no mailboxes included at all), which is possible for Presets and SA/SL. They are included if not explicitly excluded. Only inbound
            if ((-not $Outbound) -and
                (((-not $senderOrReceiver) -and (-not $domainsIs) -and (-not $memberOf)) -and
                ((-not $emailExceptionInRule) -and (-not $groupExceptionInRule) -and (-not $domainExceptionInRule)))) {
                Write-DetailedExplanationOption -Message "The recipient is IMPLICITLY included. There are no recipients explicitly included in the policy, and the user is not explicitly excluded either in the User, Group, or Domain exclusion properties. `n`t`tImplicit inclusion is possible for Preset policies and Safe Attachments and Safe Links in which no explicit inclusions have been made." -ShowDetailedExplanation:$ShowDetailedExplanation
                Write-DetailedExplanationOption -Message "Rule of matching policy: `"$($rule.Name)`"" -ShowDetailedExplanation:$ShowDetailedExplanation
                return $rule
            }
        }
        return $null
    }

    function Show-DetailedPolicy {
        param (
            [Parameter(Mandatory = $true)]
            $Policy
        )
        Write-Host "`n`tProperties of the policy that are True, On, or not blank:"
        $excludedProperties = 'Identity', 'Id', 'Name', 'ExchangeVersion', 'DistinguishedName', 'ObjectCategory', 'ObjectClass', 'WhenChanged', 'WhenCreated',
        'WhenChangedUTC', 'WhenCreatedUTC', 'ExchangeObjectId', 'OrganizationalUnitRoot', 'OrganizationId', 'OriginatingServer', 'ObjectState', 'Priority', 'ImmutableId',
        'Description', 'HostedContentFilterPolicy', 'AntiPhishPolicy', 'MalwareFilterPolicy', 'SafeAttachmentPolicy', 'SafeLinksPolicy', 'HostedOutboundSpamFilterPolicy'

        $Policy.PSObject.Properties | ForEach-Object {
            if ($null -ne $_.Value -and
                (($_.Value.GetType() -eq [Boolean] -and $_.Value -eq $true) -or
                ($_.Value -ne '{}' -and $_.Value -ne 'Off' -and $_.Value -ne $true -and $_.Value -ne '' -and $excludedProperties -notcontains $_.Name))) {
                Write-Host "`t`t$($_.Name): $($_.Value)"
            } else {
                Write-Verbose "`t`tExcluded property:$($_.Name): $($_.Value)"
            }
        }
        Write-Host " "
    }

    function Test-GraphContext {
        [OutputType([bool])]
        param (
            [Parameter(Mandatory = $true)]
            [string[]]$Scopes,
            [Parameter(Mandatory = $true)]
            [string[]]$ExpectedScopes
        )

        $validScope = $true
        foreach ($expectedScope in $ExpectedScopes) {
            if ($Scopes -contains $expectedScope) {
                Write-Verbose "Scopes $expectedScope is present."
            } else {
                Write-Host "The following scope is missing: $expectedScope" -ForegroundColor Red
                $validScope = $false
            }
        }
        return $validScope
    }

    function Write-DebugLog ($message) {
        if (![string]::IsNullOrEmpty($message)) {
            $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
        }
    }

    function Write-HostLog ($message) {
        if (![string]::IsNullOrEmpty($message)) {
            $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
        }
        # all write-host should be logged in the debug log as well.
        Write-DebugLog $message
    }

    $LogFileName = "MDOThreatPolicyChecker"
    $StartDate = Get-Date
    $StartDateFormatted = ($StartDate).ToString("yyyyMMddhhmmss")
    $Script:DebugLogger = Get-NewLoggerInstance -LogName "$LogFileName-Debug-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
    $Script:HostLogger = Get-NewLoggerInstance -LogName "$LogFileName-Results-$StartDateFormatted" -LogDirectory $PSScriptRoot -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue
    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteVerboseAction ${Function:Write-DebugLog}
    SetWriteWarningAction ${Function:Write-HostLog}

    $BuildVersion = "26.04.29.1054"

    Write-Host ("MDOThreatPolicyChecker.ps1 script version $($BuildVersion)") -ForegroundColor Green
    Write-Host " "
    Write-Host "============================================================================================================" -ForegroundColor Cyan
    Write-Host "In mid-2026, Include conditions (Users/Groups/Domains) in threat policies are moving from AND" -ForegroundColor Yellow
    Write-Host "logic to OR logic. After that, a policy will apply if a user matches any included User, Group, or Domain." -ForegroundColor Yellow
    Write-Host "Check a policy in your tenant to confirm if it is already using OR logic as this script will prompt you to" -ForegroundColor Yellow
    Write-Host "specify which logic is being used. A message center post will also inform you of the change for your tenant." -ForegroundColor Yellow
    Write-Host "============================================================================================================" -ForegroundColor Cyan

    if ($ScriptUpdateOnly) {
        switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false) {
            ($true) { Write-Host ("Script was successfully updated.") -ForegroundColor Green }
            ($false) { Write-Host ("No update of the script performed.") -ForegroundColor Yellow }
            default { Write-Host ("Unable to perform ScriptUpdateOnly operation.") -ForegroundColor Red }
        }
        return
    }

    if ((-not($SkipVersionCheck)) -and (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/MDOThreatPolicyChecker-VersionsURL" -Confirm:$false)) {
        Write-Host ("Script was updated. Please re-run the command.") -ForegroundColor Yellow
        return
    }
}

process {
    if (-not $SkipConnectionCheck) {
        #Validate EXO PS Connection
        $exoConnection = $null
        try {
            $exoConnection = Get-ConnectionInformation -ErrorAction Stop
        } catch {
            Write-Host "Error checking EXO connection:`n$_" -ForegroundColor Red
            Write-Host "Verify that you have ExchangeOnlineManagement module installed." -ForegroundColor Yellow
            Write-Host "You need a connection to Exchange Online; you can use:" -ForegroundColor Yellow
            Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
            Write-Host "Exchange Online Powershell Module is required." -ForegroundColor Red
            exit
        }
        if ($null -eq $exoConnection) {
            Write-Host "Not connected to EXO" -ForegroundColor Red
            Write-Host "You need a connection to Exchange Online; you can use:" -ForegroundColor Yellow
            Write-Host "Connect-ExchangeOnline" -ForegroundColor Yellow
            Write-Host "Exchange Online Powershell Module is required." -ForegroundColor Red
            exit
        } elseif ($exoConnection.count -eq 1) {
            Write-Host " "
            Write-Host "Connected to EXO"
            Write-Host "Session details"
            Write-Host "Tenant Id: $($exoConnection.TenantId)"
            Write-Host "User: $($exoConnection.UserPrincipalName)"
        } else {
            Write-Host "You have more than one EXO session. Please use just one session." -ForegroundColor Red
            exit
        }

        if ($PSCmdlet.ParameterSetName -ne "AppliedTenant") {
            #Validate Graph is connected
            $graphConnection = $null
            Write-Host " "
            try {
                $graphConnection = Get-MgContext -ErrorAction Stop
            } catch {
                Write-Host "Error checking Graph connection:`n$_" -ForegroundColor Red
                Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                Write-Host "You could use:" -ForegroundColor Yellow
                Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
                exit
            }
            if ($null -eq $graphConnection) {
                Write-Host "Not connected to Graph" -ForegroundColor Red
                Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                Write-Host "You could use:" -ForegroundColor Yellow
                Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
                exit
            } elseif ($graphConnection.count -eq 1) {
                $expectedScopes = "Group.Read.All", 'User.Read.All'
                if (Test-GraphContext -Scopes $graphConnection.Scopes -ExpectedScopes $expectedScopes) {
                    Write-Host "Connected to Graph"
                    Write-Host "Session details"
                    Write-Host "TenantID: $(($graphConnection).TenantId)"
                    Write-Host "Account: $(($graphConnection).Account)"
                } else {
                    Write-Host "We cannot continue without Graph Powershell session without Expected Scopes." -ForegroundColor Red
                    Write-Host "Verify that you have Microsoft.Graph.Users and Microsoft.Graph.Groups modules installed and loaded." -ForegroundColor Yellow
                    Write-Host "You could use:" -ForegroundColor Yellow
                    Write-Host "`tConnect-MgGraph -Scopes 'Group.Read.All','User.Read.All' -TenantId $($exoConnection.TenantId)" -ForegroundColor Yellow
                    exit
                }
            } else {
                Write-Host "You have more than one Graph sessions. Please use just one session." -ForegroundColor Red
                exit
            }
            if (($graphConnection.TenantId) -ne ($exoConnection.TenantId) ) {
                Write-Host "`nThe Tenant Id from Graph and EXO are different. Please use the same tenant." -ForegroundColor Red
                exit
            }
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "AppliedTenant") {
        # Define the cmdlets to retrieve policies from and their corresponding policy types
        $cmdlets = @{
            "Get-HostedContentFilterRule"                                                                        = "Anti-spam Policy"
            "Get-HostedOutboundSpamFilterRule"                                                                   = "Outbound Spam Policy"
            "Get-MalwareFilterRule"                                                                              = "Malware Policy"
            "Get-AntiPhishRule"                                                                                  = "Anti-phishing Policy"
            "Get-SafeLinksRule"                                                                                  = "Safe Links Policy"
            "Get-SafeAttachmentRule"                                                                             = "Safe Attachment Policy"
            "Get-ATPBuiltInProtectionRule"                                                                       = "Built-in protection preset security Policy"
            { Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } }   = "EOP"
            { Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } } = "EOP"
            { Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } }   = "MDO (Safe Links / Safe Attachments)"
            { Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } } = "MDO (Safe Links / Safe Attachments)"
        }

        $foundIssues = $false

        Write-Host " "
        # Loop through each cmdlet
        foreach ($cmdlet in $cmdlets.Keys) {
            # Retrieve the policies
            $policies = & $cmdlet

            # Loop through each policy
            foreach ($policy in $policies) {
                # Initialize an empty list to store issues
                $multiInclude = New-Object System.Collections.Generic.List[string]

                # Check for multiple Include conditions
                if ($policy.SentTo -and $policy.SentToMemberOf) {
                    $multiInclude.Add("`t`tUsers and Groups")
                }
                if ($policy.SentTo -and $policy.RecipientDomainIs) {
                    $multiInclude.Add("`t`tUsers and Domains")
                }
                if ($policy.SentToMemberOf -and $policy.RecipientDomainIs) {
                    $multiInclude.Add("`t`tGroups and Domains")
                }

                # Check for multiple Include conditions (Outbound)
                if ($policy.From -and $policy.FromMemberOf) {
                    $multiInclude.Add("`t`tUsers and Groups")
                }
                if ($policy.From -and $policy.SenderDomainIs) {
                    $multiInclude.Add("`t`tUsers and Domains")
                }
                if ($policy.FromMemberOf -and $policy.SenderDomainIs) {
                    $multiInclude.Add("`t`tGroups and Domains")
                }

                # If there are multiple include conditions, print the policy details and list them
                if ($multiInclude.Count -gt 0) {
                    if ($policy.State -eq "Enabled") {
                        $color = [console]::ForegroundColor
                    } else {
                        $color = "Yellow"
                    }
                    Write-Host ("Policy `"$($policy.Name)`":")
                    Write-Host ("`tType: $($cmdlets[$cmdlet]).")
                    Write-Host ("`tState: $($policy.State).") -ForegroundColor $color
                    Write-Host ("`tMultiple Include conditions:") -ForegroundColor Red
                    foreach ($item in $multiInclude) {
                        Write-Host $item
                    }
                    $foundIssues = $true
                }
            }
        }
        if (-not $foundIssues) {
            Write-Host ("No policies with multiple Include conditions found!") -ForegroundColor DarkGreen
        }
    } else {
        # Prompt for AND or OR logic when evaluating policies for specific users
        Write-Host " "
        Write-Host "Please select how to evaluate Include conditions:" -ForegroundColor Cyan
        Write-Host "  1) AND logic (original) - A user must match ALL populated Include conditions (Users AND Groups AND Domains)"
        Write-Host "  2) OR logic (new)       - A user must match ANY populated Include condition (Users OR Groups OR Domains)"
        Write-Host " "

        $Script:IncludeLogic = $null
        while ($Script:IncludeLogic -notin @('1', '2')) {
            $Script:IncludeLogic = Read-Host "Enter your choice (1 or 2)"
        }

        switch ($Script:IncludeLogic) {
            '1' { Write-Host "`nUsing AND logic for Include conditions.`n" -ForegroundColor Green }
            '2' { Write-Host "`nUsing OR logic for Include conditions.`n" -ForegroundColor Green }
        }

        if ($CsvFilePath) {
            try {
                # Import CSV file
                $csvFile = Import-Csv -Path $CsvFilePath
                # checking 'email' header
                if ($csvFile[0].PSObject.Properties.Name -contains 'Email') {
                    $EmailAddress = $csvFile | Select-Object -ExpandProperty Email
                } else {
                    Write-Host "CSV does not contain 'Email' header." -ForegroundColor Red
                    exit
                }
            } catch {
                Write-Host "Error importing CSV file:`n$_" -ForegroundColor Red
                exit
            }
        }

        $acceptedDomains = $null
        try {
            $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        } catch {
            Write-Host "Error getting Accepted Domains:`n$_" -ForegroundColor Red
            exit
        }

        if ($null -eq $acceptedDomains) {
            Write-Host "We do not get accepted domains." -ForegroundColor Red
            exit
        }

        if ($acceptedDomains.count -eq 0) {
            Write-Host "No accepted domains found." -ForegroundColor Red
            exit
        } else {
            $acceptedDomainList = New-Object System.Collections.Generic.List[string]
            $acceptedDomains | ForEach-Object { $acceptedDomainList.Add($_.DomainName.ToString()) }
        }

        $foundError = $false
        $validEmailAddress = New-Object System.Collections.Generic.List[MailAddress]
        foreach ($email in $EmailAddress) {
            $tempAddress = $null
            $tempAddress = Test-EmailAddress -EmailAddress $email -AcceptedDomains $acceptedDomainList
            if ($null -eq $tempAddress) {
                $foundError = $true
            } else {
                $validEmailAddress.Add($tempAddress)
            }
        }
        if ($foundError) {
            exit
        }

        $malwareFilterRules = $null
        $antiPhishRules = $null
        $hostedContentFilterRules = $null
        $hostedOutboundSpamFilterRules = $null
        $eopStrictPresetRules = $null
        $eopStandardPresetRules = $null

        if ( -not $OnlyMDOPolicies) {
            $malwareFilterRules = Get-MalwareFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $antiPhishRules = Get-AntiPhishRule | Where-Object { $_.State -ne 'Disabled' }
            $hostedContentFilterRules = Get-HostedContentFilterRule | Where-Object { $_.State -ne 'Disabled' }
            $hostedOutboundSpamFilterRules = Get-HostedOutboundSpamFilterRule | Where-Object { $_.State -ne 'Disabled' -and $_.Name -ne 'Strict Preset Security Policy' -and $_.Name -ne 'Standard Preset Security Policy' }
            $eopStrictPresetRules = Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
            $eopStandardPresetRules = Get-EOPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
        }

        $safeAttachmentRules = $null
        $safeLinksRules = $null
        $mdoStrictPresetRules = $null
        $mdoStandardPresetRules = $null

        if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
            # Get the custom and preset rules for Safe Attachments/Links
            $safeAttachmentRules = Get-SafeAttachmentRule | Where-Object { $_.State -ne 'Disabled' }
            $safeLinksRules = Get-SafeLinksRule | Where-Object { $_.State -ne 'Disabled' }
            $mdoStrictPresetRules = Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Strict Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
            $mdoStandardPresetRules = Get-ATPProtectionPolicyRule | Where-Object { $_.Identity -eq 'Standard Preset Security Policy' } | Where-Object { $_.State -ne 'Disabled' }
        }

        foreach ($email in $validEmailAddress) {
            $stEmailAddress = $email.ToString()
            # Initialize a variable to capture all policy details
            $allPolicyDetails = ""
            Write-Host "`n`nPolicies applied to $stEmailAddress..." -ForegroundColor Yellow

            if ( -not $OnlyMDOPolicies) {
                # Check the Strict EOP rules first as they have higher precedence
                $matchedRule = $null
                if ($eopStrictPresetRules) {
                    $matchedRule = Test-Rules -Rules $eopStrictPresetRules -email $stEmailAddress
                }
                if ($eopStrictPresetRules -contains $matchedRule) {
                    $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority
                    if ($ShowDetailedPolicies) {
                        $allPolicyDetails += "`n`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
                    }
                    Write-Host $allPolicyDetails -ForegroundColor Green
                } else {
                    # Check the Standard EOP rules secondly
                    $matchedRule = $null
                    if ($eopStandardPresetRules) {
                        $matchedRule = Test-Rules -Rules $eopStandardPresetRules -email $stEmailAddress
                    }
                    if ($eopStandardPresetRules -contains $matchedRule) {
                        $allPolicyDetails += "`nFor malware, spam, and phishing:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority
                        if ($ShowDetailedPolicies) {
                            $allPolicyDetails += "`n`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-anti-malware-and-anti-phishing-protection-in-eop"
                        }
                        Write-Host $allPolicyDetails -ForegroundColor Green
                    } else {
                        # If no match in EOPProtectionPolicyRules, check MalwareFilterRules, AntiPhishRules, outboundSpam, and HostedContentFilterRules
                        $allPolicyDetails = " "
                        $malwareMatchedRule = $malwareFilterPolicy = $null
                        if ($malwareFilterRules) {
                            $malwareMatchedRule = Test-Rules -Rules $malwareFilterRules -Email $stEmailAddress
                        }
                        if ($null -eq $malwareMatchedRule) {
                            Write-Host "`nMalware policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                            $malwareFilterPolicy = Get-MalwareFilterPolicy "Default"
                        } else {
                            $malwareFilterPolicy = Get-MalwareFilterPolicy $malwareMatchedRule.MalwareFilterPolicy
                            Write-Host "`nMalware policy applied:`n`tName: $($malwareMatchedRule.MalwareFilterPolicy)`n`tPriority: $($malwareMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($malwareFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $malwareFilterPolicy
                        }

                        $antiPhishMatchedRule = $antiPhishPolicy = $null
                        if ($antiPhishRules) {
                            $antiPhishMatchedRule = Test-Rules -Rules $antiPhishRules -Email $stEmailAddress
                        }
                        if ($null -eq $antiPhishMatchedRule) {
                            Write-Host "`nAnti-phish policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                            $antiPhishPolicy = Get-AntiPhishPolicy "Office365 AntiPhish Default"
                        } else {
                            $antiPhishPolicy = Get-AntiPhishPolicy $antiPhishMatchedRule.AntiPhishPolicy
                            Write-Host "`nAnti-phish policy applied:`n`tName: $($antiPhishMatchedRule.AntiPhishPolicy)`n`tPriority: $($antiPhishMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($antiPhishPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $antiPhishPolicy
                        }

                        $spamMatchedRule = $hostedContentFilterPolicy = $null
                        if ($hostedContentFilterRules) {
                            $spamMatchedRule = Test-Rules -Rules $hostedContentFilterRules -Email $stEmailAddress
                        }
                        if ($null -eq $spamMatchedRule) {
                            Write-Host "`nAnti-spam policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                            $hostedContentFilterPolicy = Get-HostedContentFilterPolicy "Default"
                        } else {
                            $hostedContentFilterPolicy = Get-HostedContentFilterPolicy $spamMatchedRule.HostedContentFilterPolicy
                            Write-Host "`nAnti-spam policy applied:`n`tName: $($spamMatchedRule.HostedContentFilterPolicy)`n`tPriority: $($spamMatchedRule.Priority)"  -ForegroundColor Yellow
                        }
                        if ($hostedContentFilterPolicy -and $ShowDetailedPolicies) {
                            Show-DetailedPolicy -Policy $hostedContentFilterPolicy
                        }

                        $allPolicyDetails = $userDetails + "`n" + $allPolicyDetails
                        Write-Host $allPolicyDetails -ForegroundColor Yellow
                    }
                }

                # Outbound spam is not covered by Preset policies; always check custom outbound spam rules
                $outboundSpamMatchedRule = $hostedOutboundSpamFilterPolicy = $null
                if ($hostedOutboundSpamFilterRules) {
                    $outboundSpamMatchedRule = Test-Rules -Rules $hostedOutboundSpamFilterRules -email $stEmailAddress -Outbound
                }
                if ($null -eq $outboundSpamMatchedRule) {
                    Write-Host "`nOutbound Spam policy applied:`n`tDefault policy"  -ForegroundColor Yellow
                    $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy "Default"
                } else {
                    $hostedOutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy $outboundSpamMatchedRule.HostedOutboundSpamFilterPolicy
                    Write-Host "`nOutbound Spam policy applied:`n`tName: $($outboundSpamMatchedRule.HostedOutboundSpamFilterPolicy)`n`tPriority: $($outboundSpamMatchedRule.Priority)"  -ForegroundColor Yellow
                }
                if ($hostedOutboundSpamFilterPolicy -and $ShowDetailedPolicies) {
                    Show-DetailedPolicy -Policy $hostedOutboundSpamFilterPolicy
                }
            }

            if ($IncludeMDOPolicies -or $OnlyMDOPolicies) {
                $domain = $email.Host
                $matchedRule = $null

                # Check the MDO Strict Preset rules first as they have higher precedence
                if ($mdoStrictPresetRules) {
                    $matchedRule = Test-Rules -Rules $mdoStrictPresetRules -Email $stEmailAddress
                }
                if ($mdoStrictPresetRules -contains $matchedRule) {
                    Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                    if ($ShowDetailedPolicies) {
                        Write-Host ("`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#microsoft-defender-for-office-365-security") -ForegroundColor Green
                    }
                } else {
                    # Check the Standard MDO rules secondly
                    $matchedRule = $null
                    if ($mdoStandardPresetRules) {
                        $matchedRule = Test-Rules -Rules $mdoStandardPresetRules -Email $stEmailAddress
                    }
                    if ($mdoStandardPresetRules -contains $matchedRule) {
                        Write-Host ("`nFor both Safe Attachments and Safe Links:`n`tName: {0}`n`tPriority: {1}" -f $matchedRule.Name, $matchedRule.Priority) -ForegroundColor Green
                        if ($ShowDetailedPolicies) {
                            Write-Host ("`tPreset policy settings are not configurable but documented here:`n`t`thttps://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#microsoft-defender-for-office-365-security") -ForegroundColor Green
                        }
                    } else {
                        # No match in preset ATPProtectionPolicyRules, check custom SA/SL rules
                        $SAmatchedRule = $null
                        if ($safeAttachmentRules) {
                            $SAmatchedRule = Test-Rules -Rules $safeAttachmentRules -Email $stEmailAddress
                        }
                        $SLmatchedRule = $null
                        if ($safeLinksRules) {
                            $SLmatchedRule = Test-Rules -Rules $safeLinksRules -Email $stEmailAddress
                        }
                        if ($null -eq $SAmatchedRule) {
                            # Get the Built-in Protection Rule
                            $builtInProtectionRule = Get-ATPBuiltInProtectionRule
                            # Initialize a variable to track if the user is a member of any excluded group
                            $isInExcludedGroup = $false
                            # Check if the user is a member of any group in ExceptIfSentToMemberOf
                            foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
                                $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                                if ((-not [string]::IsNullOrEmpty($groupObjectId)) -and (Test-IsInGroup -Email $stEmailAddress -GroupObjectId $groupObjectId)) {
                                    $isInExcludedGroup = $true
                                    break
                                }
                            }
                            # Check if the user is returned by ExceptIfSentTo, isInExcludedGroup, or ExceptIfRecipientDomainIs in the Built-in Protection Rule
                            if ($stEmailAddress -in $builtInProtectionRule.ExceptIfSentTo -or
                                $isInExcludedGroup -or
                                $domain -in $builtInProtectionRule.ExceptIfRecipientDomainIs) {
                                Write-Host "`nSafe Attachments:`n`tThe user is excluded from all Safe Attachment protection because they are excluded from Built-in Protection, and they are not explicitly included in any other policy." -ForegroundColor Red
                            } else {
                                Write-Host "`nSafe Attachments:`n`tIf your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy." -ForegroundColor Yellow
                            }
                            $policy = $null
                        } else {
                            $safeAttachmentPolicy = Get-SafeAttachmentPolicy -Identity $SAmatchedRule.Name
                            Write-Host "`nSafe Attachments:`n`tName: $($SAmatchedRule.Name)`n`tPriority: $($SAmatchedRule.Priority)"  -ForegroundColor Yellow
                            if ($SAmatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy $safeAttachmentPolicy
                            }
                        }

                        if ($null -eq $SLmatchedRule) {
                            # Get the Built-in Protection Rule
                            $builtInProtectionRule = Get-ATPBuiltInProtectionRule

                            # Initialize a variable to track if the user is a member of any excluded group
                            $isInExcludedGroup = $false

                            # Check if the user is a member of any group in ExceptIfSentToMemberOf
                            foreach ($groupEmail in $builtInProtectionRule.ExceptIfSentToMemberOf) {
                                $groupObjectId = Get-GroupObjectId -GroupEmail $groupEmail
                                if ((-not [string]::IsNullOrEmpty($groupObjectId)) -and (Test-IsInGroup -Email $stEmailAddress -GroupObjectId $groupObjectId)) {
                                    $isInExcludedGroup = $true
                                    break
                                }
                            }

                            # Check if the user is returned by ExceptIfSentTo, isInExcludedGroup, or ExceptIfRecipientDomainIs in the Built-in Protection Rule
                            if ($stEmailAddress -in $builtInProtectionRule.ExceptIfSentTo -or
                                $isInExcludedGroup -or
                                $domain -in $builtInProtectionRule.ExceptIfRecipientDomainIs) {
                                Write-Host "`nSafe Links:`n`tThe user is excluded from all Safe Links protection because they are excluded from Built-in Protection, and they are not explicitly included in any other policy." -ForegroundColor Red
                            } else {
                                Write-Host "`nSafe Links:`n`tIf your organization has at least one A5/E5, or MDO license, the user is included in the Built-in policy." -ForegroundColor Yellow
                            }
                            $policy = $null
                        } else {
                            $safeLinkPolicy = Get-SafeLinksPolicy -Identity $SLmatchedRule.Name
                            Write-Host "`nSafe Links:`n`tName: $($SLmatchedRule.Name)`n`tPriority: $($SLmatchedRule.Priority)" -ForegroundColor Yellow
                            if ($SLmatchedRule -and $ShowDetailedPolicies) {
                                Show-DetailedPolicy -Policy $safeLinkPolicy
                            }
                        }
                    }
                }
            }
        }
    }
    if (-not $ShowDetailedExplanation) {
        Write-Host ("`nFor details about why a policy applies to a recipient, use the -ShowDetailedExplanation parameter and run this script again.")
    }
    Write-Host " "
}

