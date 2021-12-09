# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Determines if the script has an update available. Use the optional
    -AutoUpdate switch to make it update itself. Returns $true if an
    update was downloaded, $false otherwise. The result will always
    be $false if the -AutoUpdate switch is not used.
#>
function Test-ScriptVersion {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter()]
        [switch]
        $AutoUpdate
    )

    function Confirm-ProxyServer {
        [CmdletBinding()]
        [OutputType([bool])]
        param (
            [Parameter(Mandatory = $true)]
            [string]
            $TargetUri
        )

        try {
            $proxyObject = ([System.Net.WebRequest]::GetSystemWebproxy()).GetProxy($TargetUri)
            if ($TargetUri -ne $proxyObject.OriginalString) {
                return $true
            } else {
                return $false
            }
        } catch {
            return $false
        }
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
                Write-Warning "Top-level certifcate in chain is not a root certificate."
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

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    if ((Get-AuthenticodeSignature -FilePath $scriptFullName).Status -eq "NotSigned") {
        Write-Warning "This script appears to be an unsigned test build. Skipping version check."
        return $false
    }

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)

    $tempFullName = (Join-Path $env:TEMP $scriptName)

    $BuildVersion = ""
    try {
        $versionsUrl = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/ScriptVersions.csv"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (Confirm-ProxyServer -TargetUri "https://github.com") {
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "PowerShell")
            $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        }
        $versionData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $versionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
        $latestVersion = ($versionData | Where-Object { $_.File -eq $scriptName }).Version
        if ($null -ne $latestVersion -and $latestVersion -ne $BuildVersion) {
            if ($AutoUpdate) {
                if (Test-Path $tempFullName) {
                    Remove-Item $tempFullName -Force -Confirm:$false -ErrorAction Stop
                }
                Write-Host "AutoUpdate: Downloading update."
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName" -OutFile $tempFullName -UseBasicParsing
                if (Confirm-Signature -File $tempFullName) {
                    Write-Host "AutoUpdate: Signature validated."
                    if (Test-Path $oldFullName) {
                        Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                    }
                    Move-Item $scriptFullName $oldFullName
                    Move-Item $tempFullName $scriptFullName
                    Write-Host "AutoUpdate: Succeeded."
                    return $true
                } else {
                    Write-Warning "AutoUpdate: Signature could not be verified: $tempFullName."
                    Write-Warning "AutoUpdate: Update was not applied."
                }
            } else {
                Write-Warning "$scriptName $BuildVersion is outdated. Please download the latest, version $latestVersion."
            }
        }
    } catch {
        # Work around empty catch block rule. The failure is intentionally silent.
        # For example, the script might be running on a computer with no internet access.
        "Version check failed" | Out-Null
    }

    return $false
}
