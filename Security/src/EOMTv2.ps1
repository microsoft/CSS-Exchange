# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    .SYNOPSIS
        This script contains mitigations to help address the following vulnerabilities.
            CVE-2022-41040
    .DESCRIPTION
       This script has three operations it performs:
            Mitigation of CVE-2022-41040 via a URL Rewrite configuration. Note: this mitigates current known attacks.
    .PARAMETER RollbackMitigation
        If set, will only reverse the mitigations if present.
    .PARAMETER DoNotAutoUpdateEOMTv2
        If set, will not attempt to download and run latest EOMTv2 version from GitHub.
    .EXAMPLE
		PS C:\> EOMTv2.ps1
		This will run the default mode which does the following:
            1. Checks if an updated version of EOMTv2 is available, downloads and runs latest version if so
            2. Downloads and installs the IIS URL rewrite tool.
            3. Applies the URL rewrite mitigation (only if vulnerable).
    .EXAMPLE
		PS C:\> EOMTv2.ps1 -RollbackMitigation
        This will only rollback the URL rewrite mitigation.
	.Link
        https://www.iis.net/downloads/microsoft/url-rewrite
        https://aka.ms/privacy
#>

[CmdletBinding()]
param (
    [switch]$RollbackMitigation,
    [switch]$DoNotAutoUpdateEOMTv2,
    [switch]$SkipDisclaimer
)

$ProgressPreference = "SilentlyContinue"
$EOMTv2Dir = Join-Path $env:TEMP "EOMTv2"
$EOMTv2LogFile = Join-Path $EOMTv2Dir "EOMTv2.log"
$SummaryFile = "$env:SystemDrive\EOMTv2Summary.txt"
$EOMTv2DownloadUrl = 'https://github.com/microsoft/CSS-Exchange/releases/latest/download/EOMTv2.ps1'
$versionsUrl = 'https://aka.ms/EOMTv2-VersionsUri'
$MicrosoftSigningRoot2010 = 'CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
$MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

#auto populated by CSS-Exchange build
$BuildVersion = ""

# Force TLS1.2 to make sure we can download from HTTPS
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

. $PSScriptRoot\..\..\Shared\Show-Disclaimer.ps1

function Test-ExchangeMitigationRequired {
    param()

    $mitigationRequired = $true

    try {
        $exchangeBuildInformation = Get-Command ExSetup.exe | ForEach-Object { $_.FileVersionInfo }
        [System.Version]$fullBuildNumber = $exchangeBuildInformation.FileVersion

        if ($exchangeBuildInformation.FileMinorPart -eq 0) {
            $mitigationRequired = $fullBuildNumber -lt "15.00.1497.044"
        } elseif ($exchangeBuildInformation.FileMinorPart -eq 1) {
            if ($exchangeBuildInformation.ProductBuildPart -gt 2375) {
                $mitigationRequired = $fullBuildNumber -lt "15.01.2507.016"
            } else {
                $mitigationRequired = $fullBuildNumber -lt "15.01.2375.037"
            }
        } elseif ($exchangeBuildInformation.FileMinorPart -eq 2) {
            if ($exchangeBuildInformation.ProductBuildPart -gt 986) {
                $mitigationRequired = $fullBuildNumber -lt "15.02.1118.020"
            } else {
                $mitigationRequired = $fullBuildNumber -lt "15.02.0986.036"
            }
        } else {
            throw "Exchange Server version is not supported by this script. Build number returned was: {0}" -f $fullBuildNumber
        }
    } catch {
        throw "Failed to get Exchange Server build number. The error was: {0}." -f $_
    }

    return $mitigationRequired
}

function Test-ExchangeMitigationExists {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [string]$Site = "IIS:\Sites\Default Web Site",
        [string]$Filter = "*"
    )

    try {
        return ($null -ne (Get-WebConfiguration -Filter $Filter -PSPath $Site -ErrorAction Stop))
    } catch {
        return $false
    }
}

function Run-Mitigate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Invalid rule result')]
    param(
        [string]$WebSiteName = "Default Web Site",
        [string]$Stage = "MitigationProcess",
        [switch]$RollbackMitigation

    )

    function Get-MsiProductVersion {
        param (
            [string]$filename
        )

        try {
            $windowsInstaller = New-Object -com WindowsInstaller.Installer

            $database = $windowsInstaller.GetType().InvokeMember(
                "OpenDatabase", "InvokeMethod", $Null,
                $windowsInstaller, @($filename, 0)
            )

            $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"

            $View = $database.GetType().InvokeMember(
                "OpenView", "InvokeMethod", $Null, $database, ($q)
            )

            try {
                $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null) | Out-Null

                $record = $View.GetType().InvokeMember(
                    "Fetch", "InvokeMethod", $Null, $View, $Null
                )

                $productVersion = $record.GetType().InvokeMember(
                    "StringData", "GetProperty", $Null, $record, 1
                )

                return $productVersion
            } finally {
                if ($View) {
                    $View.GetType().InvokeMember("Close", "InvokeMethod", $Null, $View, $Null) | Out-Null
                }
            }
        } catch {
            throw "Failed to get MSI file version the error was: {0}." -f $_
        }
    }

    function Get-InstalledSoftwareVersion {
        param (
            [ValidateNotNullOrEmpty()]
            [string[]]$Name
        )

        try {
            $UninstallKeys = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )

            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

            $UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object {
                "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            }

            foreach ($UninstallKey in $UninstallKeys) {
                $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue
                foreach ($n in $Name) {
                    $SwKeys = $SwKeys | Where-Object { $_.GetValue('DisplayName') -like "$n" }
                }
                if ($SwKeys) {
                    foreach ($SwKey in $SwKeys) {
                        if ($SwKey.GetValueNames().Contains("DisplayVersion")) {
                            return $SwKey.GetValue("DisplayVersion")
                        }
                    }
                }
            }
        } catch {
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        }
    }

    function Test-IIS10 {
        $iisRegPath = "HKLM:\SOFTWARE\Microsoft\InetStp"

        if (Test-Path $iisRegPath) {
            $properties = Get-ItemProperty $iisRegPath
            if ($properties.MajorVersion -eq 10) {
                return $true
            }
        }

        return $false
    }

    function Get-URLRewriteLink {
        $DownloadLinks = @{
            "x86" = @{
                "de-DE" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_de-DE.msi"
                "en-US" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_en-US.msi"
                "es-ES" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_es-ES.msi"
                "fr-FR" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_fr-FR.msi"
                "it-IT" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_it-IT.msi"
                "ja-JP" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ja-JP.msi"
                "ko-KR" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ko-KR.msi"
                "ru-RU" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ru-RU.msi"
                "zh-CN" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_zh-CN.msi"
                "zh-TW" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_zh-TW.msi"
            }
            "x64" = @{
                "de-DE" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_de-DE.msi"
                "en-US" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
                "es-ES" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_es-ES.msi"
                "fr-FR" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_fr-FR.msi"
                "it-IT" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_it-IT.msi"
                "ja-JP" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ja-JP.msi"
                "ko-KR" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ko-KR.msi"
                "ru-RU" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ru-RU.msi"
                "zh-CN" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_zh-CN.msi"
                "zh-TW" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_zh-TW.msi"
            }
        }

        if ([Environment]::Is64BitOperatingSystem) {
            $Architecture = "x64"
        } else {
            $Architecture = "x86"
        }

        if ((Get-Culture).Name -in @("de-DE", "en-US", "es-ES", "fr-FR", "it-IT", "ja-JP", "ko-KR", "ru-RU", "zn-CN", "zn-TW")) {
            $Language = (Get-Culture).Name
        } else {
            $Language = "en-US"
        }

        return $DownloadLinks[$Architecture][$Language]
    }

    #Configure Rewrite Rule constants
    $HttpRequestInput = '{UrlDecode:{REQUEST_URI}}'
    $root = 'system.webServer/rewrite/rules'
    $inbound = '.*'
    $name = 'PowerShell - inbound'
    $pattern = '(?=.*autodiscover)(?=.*powershell)'
    $filter = "{0}/rule[@name='{1}']" -f $root, $name
    $site = "IIS:\Sites\$WebSiteName"
    Import-Module WebAdministration

    if ($RollbackMitigation) {
        $Message = "Starting rollback of mitigation on $env:COMPUTERNAME"
        $RegMessage = "Starting rollback of mitigation"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        $mitigationFound = $false
        if (Test-ExchangeMitigationExists -Filter $filter -Site $site) {
            $mitigationFound = $true
            Clear-WebConfiguration -Filter $filter -PSPath $site
        }

        if ($mitigationFound) {
            $Rules = Get-WebConfiguration -Filter 'system.webServer/rewrite/rules/rule' -PSPath $site -Recurse
            if ($null -eq $Rules) {
                Clear-WebConfiguration -PSPath $site -Filter 'system.webServer/rewrite/rules'
            }

            $Message = "Rollback of mitigation complete on $env:COMPUTERNAME"
            $RegMessage = "Rollback of mitigation complete"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } else {
            $Message = "Mitigation not present on $env:COMPUTERNAME"
            $RegMessage = "Mitigation not present"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        }
    } else {
        $Message = "Starting mitigation process on $env:COMPUTERNAME"
        $RegMessage = "Starting mitigation process"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"

        if ($RewriteModule) {
            $Message = "IIS URL Rewrite Module is already installed on $env:COMPUTERNAME"
            $RegMessage = "IIS URL Rewrite Module already installed"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } else {
            $DownloadLink = Get-URLRewriteLink
            $DownloadPath = Join-Path $EOMTv2Dir "\$($DownloadLink.Split("/")[-1])"
            $RewriteModuleInstallLog = Join-Path $EOMTv2Dir "\RewriteModuleInstall.log"

            $response = Invoke-WebRequest $DownloadLink -UseBasicParsing
            [IO.File]::WriteAllBytes($DownloadPath, $response.Content)

            $MSIProductVersion = Get-MsiProductVersion -filename $DownloadPath

            if ($MSIProductVersion -lt "7.2.1993") {
                $Message = "Incorrect IIS URL Rewrite Module downloaded on $env:COMPUTERNAME"
                $RegMessage = "Incorrect IIS URL Rewrite Module downloaded"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }
            #KB2999226 required for IIS Rewrite 2.1 on IIS ver under 10
            if (!(Test-IIS10) -and !(Get-HotFix -Id "KB2999226" -ErrorAction SilentlyContinue)) {
                $Message = "Did not detect the KB2999226 on $env:COMPUTERNAME. Please review the prerequisite for this KB and download from https://support.microsoft.com/en-us/topic/update-for-universal-c-runtime-in-windows-c0514201-7fe6-95a3-b0a5-287930f3560c"
                $RegMessage = "Did not detect KB299226"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }

            $Message = "Installing the IIS URL Rewrite Module on $env:COMPUTERNAME"
            $RegMessage = "Installing IIS URL Rewrite Module"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

            $arguments = "/i `"$DownloadPath`" /quiet /log `"$RewriteModuleInstallLog`""
            $msiExecPath = $env:WINDIR + "\System32\msiExec.exe"

            if (!(Confirm-Signature -filepath $DownloadPath -Stage $stage)) {
                $Message = "File present at $DownloadPath does not seem to be signed as expected, stopping execution."
                $RegMessage = "File downloaded for UrlRewrite MSI does not seem to be signed as expected, stopping execution"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                Write-Summary -NoRemediation:$DoNotRemediate
                throw
            }

            Start-Process -FilePath $msiExecPath -ArgumentList $arguments -Wait
            Start-Sleep -Seconds 15
            $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"

            if ($RewriteModule) {
                $Message = "IIS URL Rewrite Module installed on $env:COMPUTERNAME"
                $RegMessage = "IIS URL Rewrite Module installed"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
            } else {
                $Message = "Issue installing IIS URL Rewrite Module $env:COMPUTERNAME"
                $RegMessage = "Issue installing IIS URL Rewrite Module"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }
        }

        $Message = "Applying URL Rewrite configuration to $env:COMPUTERNAME :: $WebSiteName"
        $RegMessage = "Applying URL Rewrite configuration"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        try {
            if ((Get-WebConfiguration -Filter $filter -PSPath $site).name -eq $name) {
                Set-LogActivity -Stage $Stage -Message "Mitigation already exists - start cleanup to apply the latest mitigation"
                Clear-WebConfiguration -Filter $filter -PSPath $site
            }

            Add-WebConfigurationProperty -PSPath $site -Filter $root -Name '.' -Value @{name = $name; patternSyntax = 'Regular Expressions'; stopProcessing = 'True' }
            Set-WebConfigurationProperty -PSPath $site -Filter "$filter/match" -Name 'url' -Value $inbound
            Set-WebConfigurationProperty -PSPath $site -Filter "$filter/conditions" -Name '.' -Value @{input = $HttpRequestInput; matchType = '0'; pattern = $pattern; ignoreCase = 'True'; negate = 'False' }
            Set-WebConfigurationProperty -PSPath $site -Filter "$filter/action" -Name 'type' -Value 'AbortRequest'

            $Message = "Mitigation complete on $env:COMPUTERNAME :: $WebSiteName"
            $RegMessage = "Mitigation complete"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } catch {
            $Message = "Mitigation failed on $env:COMPUTERNAME :: $WebSiteName"
            $RegMessage = "Mitigation failed"
            Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
            throw
        }
    }
}

function Write-Log {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Invalid rule result')]
    param
    (
        [string]$Message,
        [string]$Path = $EOMTv2LogFile,
        [string]$Level = "Info"
    )

    $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Write log entry to $Path
    "$FormattedDate $($Level): $Message" | Out-File -FilePath $Path -Append
}

function Set-LogActivity {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'Invalid rule result')]
    [CmdletBinding(SupportsShouldProcess)]
    param (
        $Stage,
        $RegMessage,
        $Message,
        [switch]$Notice,
        [switch]$Error
    )
    if ($Notice) {
        $Level = "Notice"
    } elseif ($Error) {
        $Level = "Error"
    } else {
        $Level = "Info"
    }
    if ($Level -eq "Info") {
        Write-Verbose -Message $Message -Verbose
    } elseif ($Level -eq "Notice") {
        Write-Host -ForegroundColor Cyan -BackgroundColor black "NOTICE: $Message"
    } else {
        Write-Error -Message $Message
    }

    Write-Log -Message $Message -Level $Level
}

function Confirm-Signature {
    param(
        [string]$Filepath,
        [string]$Stage
    )

    $IsValid = $false
    $failMsg = "Signature of $Filepath not as expected. "
    try {
        if (!(Test-Path $Filepath)) {
            $IsValid = $false
            $failMsg += "Filepath does not exist"
            throw
        }

        $sig = Get-AuthenticodeSignature -FilePath $Filepath

        if ($sig.Status -ne 'Valid') {
            $IsValid = $false
            $failMsg += "Signature is not trusted by machine as Valid, status: $($sig.Status)"
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        $chainsCorrectly = $chain.Build($sig.SignerCertificate)

        if (!$chainsCorrectly) {
            $IsValid = $false
            $failMsg += "Signer certificate doesn't chain correctly"
            throw
        }

        if ($chain.ChainElements.Count -le 1) {
            $IsValid = $false
            $failMsg += "Certificate Chain shorter than expected"
            throw
        }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            $IsValid = $false
            $failMsg += "Top-level certificate in chain is not a root certificate"
            throw
        }

        if ($rootCert.Certificate.Subject -eq $MicrosoftSigningRoot2010 -or $rootCert.Certificate.Subject -eq $MicrosoftSigningRoot2011) {
            $IsValid = $true
            $Message = "$Filepath is signed by Microsoft as expected, trusted by machine as Valid, signed by: $($sig.SignerCertificate.Subject), Issued by: $($sig.SignerCertificate.Issuer), with Root certificate: $($rootCert.Certificate.Subject)"
            $RegMessage = "$Filepath is signed by Microsoft as expected"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
        } else {
            $IsValid = $false
            $failMsg += "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)"
            throw
        }
    } catch {
        $IsValid = $false
        Set-LogActivity -Stage $Stage -RegMessage $failMsg -Message $failMsg -Error
    }

    return $IsValid
}
function Write-Summary {
    param(
        [switch]$Pass,
        [switch]$NoRemediation
    )

    $RemediationText = ""
    if (!$NoRemediation) {
        $RemediationText = " and clear malicious files"
    }

    $summary = @"
EOMTv2 mitigation summary
Message: Microsoft attempted to mitigate and protect your Exchange server from CVE-2022-41040 $RemediationText.
For more information on these vulnerabilities please visit (https://aka.ms/Exchangevulns2)
Please review locations and files as soon as possible and take the recommended action.
Microsoft saved several files to your system to "$EOMTv2Dir". The only files that should be present in this directory are:
    a - EOMTv2.log
    b - RewriteModuleInstall.log
    c - one of the following IIS URL rewrite MSIs:
        rewrite_amd64_[de-DE,en-US,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_ x86_[de-DE,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_x64_[de-DE,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_2.0_rtw_x86.msi
        rewrite_2.0_rtw_x64.msi
1 - Confirm the IIS URL Rewrite Module is installed. This module is required for the mitigation of CVE-2022-41040, the module and the configuration (present or not) will not impact this system negatively.
    a - If installed, Confirm the following entry exists in the "$env:SystemDrive\inetPub\wwwRoot\web.config". If this configuration is not present, your server is not mitigated. This may have occurred if the module was not successfully installed with a supported version for your system.
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="PowerShell - inbound">
                    <match url=".*" />
                    <conditions>
                        <add input="{UrlDecode:{REQUEST_URI}}" pattern="(?=.*autodiscover)(?=.*powershell)" />
                    </conditions>
                    <action type="AbortRequest" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
"@

    if (Test-Path $SummaryFile) {
        Remove-Item $SummaryFile -Force
    }

    $summary = $summary.Replace("`r`n", "`n").Replace("`n", "`r`n")
    $summary | Out-File -FilePath $SummaryFile -Encoding ASCII -Force
}

if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Unable to launch EOMTv2.ps1: please re-run as administrator."
    exit
}

if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Error "Unsupported version of PowerShell on $env:COMPUTERNAME - The Exchange On-premises Mitigation Tool supports PowerShell 3 and later"
    exit
}

# Main
try {
    if (($SkipDisclaimer -eq $false) -and
        ($RollbackMitigation -eq $false)) {
        $params = @{
            Message   = "Display Warning about CVE-2022-41040 mitigation"
            Target    = "The CVE-2022-41040 security vulnerability has been addressed with the November 2022 and later Exchange Server Security Update." +
            "`r`nMitigations can become insufficient to protect against all variations of an attack." +
            "`r`nThus, installation of an applicable SU is the ***only way to protect your servers***." +
            "`r`nGet the latest Exchange Server update here: https://aka.ms/LatestExchangeServerUpdate" +
            "`r`nDo you really want to proceed?"
            Operation = "Applying CVE-2022-41040 mitigation"
        }

        Show-Disclaimer @params
        Write-Host ""
    }

    $Stage = "CheckEOMTv2Version"

    if (!(Test-Path $EOMTv2Dir)) {
        New-Item -ItemType Directory $EOMTv2Dir | Out-Null
    }

    try {
        $Message = "Checking if EOMTv2 is up to date with $versionsUrl"
        Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message
        $latestEOMTv2Version = $null
        $versionsData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $versionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
        $latestEOMTv2Version = ($versionsData | Where-Object -Property File -EQ "EOMTv2.ps1").Version
    } catch {
        $Message = "Cannot check version info at $versionsUrl to confirm EOMTv2.ps1 is latest version. Version currently running is $BuildVersion. Please download latest EOMTv2 from $EOMTv2DownloadUrl and re-run EOMTv2, unless you just did so. Exception: $($_.Exception)"
        $RegMessage = "Cannot check version info at $versionsUrl to confirm EOMTv2.ps1 is latest version. Version currently running is $BuildVersion. Continuing with execution"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
    }

    $DisableAutoUpdateIfNeeded = "If you are getting this error even with updated EOMTv2, re-run with -DoNotAutoUpdateEOMTv2 parameter"

    $Stage = "AutoUpdateEOMTv2"
    if ($latestEOMTv2Version -and ($BuildVersion -ne $latestEOMTv2Version)) {
        if ($DoNotAutoUpdateEOMTv2) {
            $Message = "EOMTv2.ps1 is out of date. Version currently running is $BuildVersion, latest version available is $latestEOMTv2Version. We strongly recommend downloading latest EOMTv2 from $EOMTv2DownloadUrl and re-running EOMTv2. DoNotAutoUpdateEOMTv2 is set, so continuing with execution"
            $RegMessage = "EOMTv2.ps1 is out of date. Version currently running is $BuildVersion, latest version available is $latestEOMTv2Version.  DoNotAutoUpdateEOMTv2 is set, so continuing with execution"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
        } else {
            $Stage = "DownloadLatestEOMTv2"
            $EOMTv2LatestFilepath = Join-Path $EOMTv2Dir "EOMTv2_$latestEOMTv2Version.ps1"
            try {
                $Message = "Downloading latest EOMTv2 from $EOMTv2DownloadUrl"
                Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message
                Invoke-WebRequest $EOMTv2DownloadUrl -OutFile $EOMTv2LatestFilepath -UseBasicParsing
            } catch {
                $Message = "Cannot download latest EOMTv2.  Please download latest EOMTv2 yourself from $EOMTv2DownloadUrl, copy to necessary machine(s), and re-run. $DisableAutoUpdateIfNeeded. Exception: $($_.Exception)"
                $RegMessage = "Cannot download latest EOMTv2 from $EOMTv2DownloadUrl. Stopping execution."
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                throw
            }

            $Stage = "RunLatestEOMTv2"
            if (Confirm-Signature -Filepath $EOMTv2LatestFilepath -Stage $Stage) {
                $Message = "Running latest EOMTv2 version $latestEOMTv2Version downloaded to $EOMTv2LatestFilepath"
                Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message

                try {
                    & $EOMTv2LatestFilepath @PSBoundParameters
                    exit
                } catch {
                    $Message = "Run failed for latest EOMTv2 version $latestEOMTv2Version downloaded to $EOMTv2LatestFilepath, please re-run $EOMTv2LatestFilepath manually. $DisableAutoUpdateIfNeeded. Exception: $($_.Exception)"
                    $RegMessage = "Run failed for latest EOMTv2 version $latestEOMTv2Version"
                    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                    throw
                }
            } else {
                $Message = "File downloaded to $EOMTv2LatestFilepath does not seem to be signed as expected, stopping execution."
                $RegMessage = "File downloaded for EOMTv2.ps1 does not seem to be signed as expected, stopping execution"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                Write-Summary -NoRemediation:$DoNotRemediate
                throw
            }
        }
    }

    $Stage = "EOMTv2Start"

    $Message = "Starting EOMTv2.ps1 version $BuildVersion on $env:COMPUTERNAME"
    $RegMessage = "Starting EOMTv2.ps1 version $BuildVersion"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

    $Message = "EOMTv2 preCheck complete on $env:COMPUTERNAME"
    $RegMessage = "EOMTv2 preCheck complete"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

    if ($RollbackMitigation) {
        Run-Mitigate -RollbackMitigation
    } elseif ((Test-ExchangeMitigationRequired) -eq $false) {
        if (Test-ExchangeMitigationExists -Filter "system.webServer/rewrite/rules/rule[@name='PowerShell - inbound']") {
            if ($SkipDisclaimer -eq $false) {
                $params = @{
                    Message   = "Display Warning about CVE-2022-41040 mitigation"
                    Target    = "This computer is running the November 2022 (or higher) Exchange Server build and the mitigation has been detected." +
                    "`r`nThe mitigation is no longer required on this machine." +
                    "`r`nDo you want to rollback the mitigation on this computer?"
                    Operation = "Rollback CVE-2022-41040 mitigation"
                }

                Show-Disclaimer @params
                Write-Host ""
                Run-Mitigate -RollbackMitigation
            } else {
                $Message = "CVE-2022-41040 mitigation has already been applied on this computer. However, the Exchange build running on this computer" +
                "`r`nis no longer vulnerable to this vulnerability and so, the mitigation can be removed."
                Set-LogActivity -Stage $Stage -Message $Message -Notice
            }
        } else {
            $Message = "CVE-2022-41040 vulnerability has been fixed for the Exchange build running on this computer - mitigation will not be applied"
            Set-LogActivity -Stage $Stage -Message $Message -Notice
        }
    } else {
        $Message = "Applying mitigation on $env:COMPUTERNAME"
        $RegMessage = ""
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        Run-Mitigate
    }

    $Message = "EOMTv2.ps1 complete on $env:COMPUTERNAME, please review EOMTv2 logs at $EOMTv2LogFile and the summary file at $SummaryFile"
    $RegMessage = "EOMTv2.ps1 completed successfully"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
    Write-Summary -Pass -NoRemediation:$DoNotRemediate #Pass
} catch {
    $Message = "EOMTv2.ps1 failed to complete on $env:COMPUTERNAME, please review EOMTv2 logs at $EOMTv2LogFile and the summary file at $SummaryFile - $_"
    $RegMessage = "EOMTv2.ps1 failed to complete"
    Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
    Write-Summary -NoRemediation:$DoNotRemediate #Fail
}
