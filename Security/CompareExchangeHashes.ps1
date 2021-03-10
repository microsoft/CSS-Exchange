#################################################################################
#
# The sample scripts are not supported under any Microsoft standard support
# program or service. The sample scripts are provided AS IS without warranty
# of any kind. Microsoft further disclaims all implied warranties including, without
# limitation, any implied warranties of merchantability or of fitness for a particular
# purpose. The entire risk arising out of the use or performance of the sample scripts
# and documentation remains with you. In no event shall Microsoft, its authors, or
# anyone else involved in the creation, production, or delivery of the scripts be liable
# for any damages whatsoever (including, without limitation, damages for loss of business
# profits, business interruption, loss of business information, or other pecuniary loss)
# arising out of the use of or inability to use the sample scripts or documentation,
# even if Microsoft has been advised of the possibility of such damages.
#
#################################################################################
#

<#
.SYNOPSIS
    This script provides detection mechanism for exchange onprem security threats for E13, E16 and E19.
    For more information please go to https://aka.ms/exchangevulns

    .DESCRIPTION
    This script will:
        1. Examine the files in each exchange virtual directory in IIS and compares the file hashes against the baseline hashes from the exchange installation files.

    The result generated is stored in a file locally with the following format: <ExchangeVersion>_result.csv
    If there are errors during file comparision there is an error generated on the cmdline.

    How to read the output:
        Open the result csv file in excel or in powershell:
        $result = Import-Csv <Path to result file>

    Submitting files for analysis:
        Please submit the output file for analysis in the malware analysis portal
        in the link below. Please add the text "ExchangeMarchCVE" in
        "Additional Information" field on the portal submission form.
            https://www.microsoft.com/en-us/wdsi/filesubmission
        Instructions on how to use the portal can be found here:
            https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/submission-guide

    Disclaimer:
        The script currently only validates any compromised file in exchange vdirs, it does not check any files in the iis root.
        This script needs to be run as ADMINISTRATOR

    .EXAMPLE
    PS C:\> CompareExchangeHashes.ps1
#>


$ErrorActionPreference = 'Stop';

$BuildVersion = ""

# use native powershell types
$KNOWN_BAD_HASH = @{ `
        'b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0' = $true; `
        '097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e' = $true; `
        '2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1' = $true; `
        '65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5' = $true; `
        '511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1' = $true; `
        '4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea' = $true; `
        '811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d' = $true; `
        '1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944' = $true; `

}

$KNOWN_ROOT_FILES = @{ `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client"                                      = $true; `
        "$env:SystemDrive\inetpub\wwwroot\iisstart.htm"                                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\iisstart.png"                                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\web.config"                                         = $true; `
        "$env:SystemDrive\inetpub\wwwroot\web.config.bak"                                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs"                                              = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\newmantest.aspx"                      = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\newmantest2.aspx"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\newmantest3.aspx"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\poc.aspx"                             = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\system_web"                           = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\system_web\4_0_30319"                 = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\system_web\poc.aspx"                  = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin"                                        = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification"                                = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\decommission"                                 = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\groupexpansion"                               = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing"                                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\AuditReportMgr.asmx"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\ClusterInfoMgr.asmx"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\EnterpriseMgr.asmx"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\Global.asax"                            = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\RoleMgr.asmx"                           = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\TemplateMgr.asmx"                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\web.config"                             = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\certification.asmx"             = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\global.asax"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\MacCertification.asmx"          = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\MobileDeviceCertification.asmx" = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\Precertification.asmx"          = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\server.asmx"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\ServerCertification.asmx"       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\ServiceLocator.asmx"            = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\web.config"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\decommission\decommission.asmx"               = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\decommission\global.asax"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\decommission\web.config"                      = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\groupexpansion\global.asax"                   = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\groupexpansion\GroupExpansion.asmx"           = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\groupexpansion\web.config"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\editissuancelicense.asmx"           = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\global.asax"                        = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\license.asmx"                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\publish.asmx"                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\server.asmx"                        = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\ServiceLocator.asmx"                = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\TemplateDistribution.asmx"          = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\web.config"                         = $true;
}

$VALID_VERSIONS = @{ `
        # E19
        '15.2.858.5'   = $true; `
        '15.2.792.5'   = $true; `
        '15.2.792.3'   = $true; `
        '15.2.721.13'  = $true; `
        '15.2.792.10'  = $true; `
        '15.2.721.8'   = $true; `
        '15.2.721.6'   = $true; `
        '15.2.721.4'   = $true; `
        '15.2.721.3'   = $true; `
        '15.2.721.2'   = $true; `
        '15.2.659.11'  = $true; `
        '15.2.659.8'   = $true; `
        '15.2.659.7'   = $true; `
        '15.2.659.6'   = $true; `
        '15.2.659.4'   = $true; `
        '15.2.595.6'   = $true; `
        '15.2.595.3'   = $true; `
        '15.2.529.11'  = $true; `
        '15.2.529.8'   = $true; `
        '15.2.529.5'   = $true; `
        '15.2.464.5'   = $true; `
        '15.2.397.3'   = $true; `
        '15.2.330.5'   = $true; `
        '15.2.221.12'  = $true; `
        '15.2.196.0'   = $true; `

    #E16
    '15.1.2242.4'      = $true; `
        '15.1.2176.9'  = $true; `
        '15.1.2176.4'  = $true; `
        '15.1.2176.2'  = $true; `
        '15.1.2106.13' = $true; `
        '15.1.2106.8'  = $true; `
        '15.1.2106.6'  = $true; `
        '15.1.2106.4'  = $true; `
        '15.1.2106.3'  = $true; `
        '15.1.2106.2'  = $true; `
        '15.1.2044.12' = $true; `
        '15.1.2044.8'  = $true; `
        '15.1.2044.7'  = $true; `
        '15.1.2044.6'  = $true; `
        '15.1.2044.4'  = $true; `
        '15.1.1979.6'  = $true; `
        '15.1.1979.3'  = $true; `
        '15.1.1913.10' = $true; `
        '15.1.1913.7'  = $true; `
        '15.1.1913.5'  = $true; `
        '15.1.1847.10' = $true; `
        '15.1.1847.7'  = $true; `
        '15.1.1847.5'  = $true; `
        '15.1.1847.3'  = $true; `
        '15.1.1779.2'  = $true; `
        '15.1.1713.5'  = $true; `
        '15.1.1591.17' = $true; `
        '15.1.1591.16' = $true; `
        '15.1.1591.10' = $true; `
        '15.1.1591.8'  = $true; `
        '15.1.1531.10' = $true; `
        '15.1.1531.7'  = $true; `
        '15.1.1531.6'  = $true; `
        '15.1.1531.4'  = $true; `
        '15.1.1531.3'  = $true; `
        '15.1.1466.8'  = $true; `
        '15.1.1466.3'  = $true; `
        '15.1.1415.2'  = $true; `
        '15.1.1261.35' = $true; `
        '15.1.1034.33' = $true; `
        '15.1.1034.26' = $true; `
        '15.1.845.34'  = $true; `
        '15.1.669.32'  = $true; `
        '15.1.544.27'  = $true; `
        '15.1.466.34'  = $true; `
        '15.1.396.30'  = $true; `
        '15.1.225.42'  = $true; `
        '15.1.225.16'  = $true; `

    #E13
    '15.0.1497.12'     = $true; `
        '15.0.1497.10' = $true; `
        '15.0.1497.8'  = $true; `
        '15.0.1497.7'  = $true; `
        '15.0.1497.6'  = $true; `
        '15.0.1497.4'  = $true; `
        '15.0.1497.3'  = $true; `
        '15.0.1497.2'  = $true; `
        '15.0.1497.0'  = $true; `
        '15.0.1473.5'  = $true; `
        '15.0.1473.4'  = $true; `
        '15.0.1473.3'  = $true; `
        '15.0.1395.10' = $true; `
        '15.0.1395.8'  = $true; `
        '15.0.1395.7'  = $true; `
        '15.0.1395.6'  = $true; `
        '15.0.1395.4'  = $true; `
        '15.0.1367.9'  = $true; `
        '15.0.1367.6'  = $true; `
        '15.0.1367.3'  = $true; `
        '15.0.1365.7'  = $true; `
        '15.0.1365.1'  = $true; `
        '15.0.1347.5'  = $true; `
        '15.0.1347.4'  = $true; `
        '15.0.1347.3'  = $true; `
        '15.0.1347.2'  = $true; `
        '15.0.1347.0'  = $true; `
        '15.0.1320.4'  = $true; `
        '15.0.1293.2'  = $true; `
        '15.0.1263.5'  = $true; `
        '15.0.1236.6'  = $true; `
        '15.0.1236.3'  = $true; `
        '15.0.1210.3'  = $true; `
        '15.0.1178.4'  = $true; `
        '15.0.1156.6'  = $true; `
        '15.0.1130.10' = $true; `
        '15.0.1130.7'  = $true; `
        '15.0.1104.5'  = $true; `
        '15.0.1076.9'  = $true; `
        '15.0.1044.25' = $true; `
        '15.0.995.32'  = $true; `
        '15.0.995.29'  = $true; `
        '15.0.995.28'  = $true; `
        '15.0.913.22'  = $true; `
        '15.0.847.32'  = $true; `
        '15.0.775.38'  = $true; `
        '15.0.712.24'  = $true; `
        '15.0.712.23'  = $true; `
        '15.0.620.29'  = $true; `
        '15.0.516.32'  = $true; `
        '15.0.516.30'  = $true; `

    #E10
    '14.3.513.0'       = $true; `
        '14.3.509.0'   = $true; `
        '14.3.496.0'   = $true; `
        '14.3.468.0'   = $true; `
        '14.3.461.1'   = $true; `
        '14.3.452.0'   = $true; `
        '14.3.442.0'   = $true; `
        '14.3.435.0'   = $true; `
        '14.3.419.0'   = $true; `
        '14.3.417.1'   = $true; `
        '14.3.411.0'   = $true; `
        '14.3.399.2'   = $true; `
        '14.3.389.1'   = $true; `
        '14.3.382.0'   = $true; `
        '14.3.361.1'   = $true; `
        '14.3.352.0'   = $true; `
        '14.3.336.0'   = $true; `
        '14.3.319.2'   = $true; `
        '14.3.301.0'   = $true; `
        '14.3.294.0'   = $true; `
        '14.3.279.2'   = $true; `
        '14.3.266.2'   = $true; `
        '14.3.248.2'   = $true; `
        '14.3.235.1'   = $true; `
        '14.3.224.2'   = $true; `
        '14.3.224.1'   = $true; `
        '14.3.210.2'   = $true; `
        '14.3.195.1'   = $true; `
        '14.3.181.6'   = $true; `
        '14.3.174.1'   = $true; `
        '14.3.169.1'   = $true; `
        '14.3.158.1'   = $true; `
        '14.3.146.0'   = $true; `
        '14.3.123.4'   = $true; `

}

$MARK_AS_SUSPICIOUS_FROM = (Get-Date -Date "12/01/2020" -Format "MM/dd/yyyy HH:mm:ss")

function PerformComparison {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'Incorrect rule result')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Incorrect rule result')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Incorrect rule result')]
    param (
        [Parameter()]
        $baselineData,

        [Parameter()]
        $pattern,

        [Parameter()]
        $baseExoVer
    )

    Write-Host "BaselineData - $($baselineData.Keys) $baseExoVer"
    $result = @{}
    $vdirBatches = GetVdirBatches
    $errFound = $false
    $vdirBatches.Keys | Sort-Object | ForEach-Object {
        $vdirs = $vdirBatches[$_]
        $jobs = @()
        Write-Host "Processing $($vdirs.Count) directories in parallel. Batch $($_ + 1) of $($vdirBatches.Count) batches."
        $vdirs | ForEach-Object {
            $j = Start-Job -ScriptBlock {
                param ($baselines, $pattern, $l, $known_bad, $KNOWN_ROOT_FILES, $mark_as_suspicious_from)
                $vdirErrors = @()
                $pdirErrors = @()
                $fErrors = @()
                $errHappend = $false

                $l -match $pattern | Out-Null;
                $vdir = $Matches[2];
                $pdir = $Matches[3]
                $pdir = $pdir -replace "%SystemDrive%", $env:SystemDrive
                $pdir = $pdir -replace "%windir%", $env:windir

                function GetFileHash([string] $filePath) {
                    $hash = ""
                    try {
                        $sha256 = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider
                        $hash = [System.BitConverter]::ToString($sha256.ComputeHash([System.IO.File]::ReadAllBytes($filePath))).Replace('-', '')
                    } catch {
                        return ""
                    }

                    return $hash
                }

                $datetime_format = "MM/dd/yyyy HH:mm:ss"

                if ($pdir.StartsWith("$env:SystemDrive\inetpub\wwwroot")) {
                    $inetpub_files = (Get-ChildItem -Recurse -Path $pdir -File -Exclude *aspx, *asmx, *asax, *js, *css, *htm, *html)
                    foreach ($f in $inetpub_files) {

                        $hash = GetFileHash $f.FullName

                        $creation_time = Get-Date ($f.CreationTimeUtc) -Format $datetime_format
                        $lastwrite_time = Get-Date ($f.LastWriteTimeUtc) -Format $datetime_format
                        $lastaccess_time = Get-Date ($f.LastAccessTimeUtc) -Format $datetime_format

                        if ([string]::IsNullOrEmpty($hash)) {
                            $newError = New-Object PSObject -Property @{
                                VDir              = $vdir
                                PDir              = $pdir
                                FileName          = $f.Name
                                FilePath          = $f.FullName
                                FileHash          = ""
                                CreationTimeUtc   = $creation_time
                                LastWriteTimeUtc  = $lastwrite_time
                                LastAccessTimeUtc = $lastaccess_time
                                Error             = "ReadError"
                            }
                            $fErrors += $newError;
                            $errHappend = $true
                        } else {
                            if ($mark_as_suspicious_from -le $f.LastWriteTime) {
                                $newError = New-Object PSObject -Property @{
                                    VDir              = $vdir
                                    PDir              = $pdir
                                    FileName          = $f.Name
                                    FilePath          = $f.FullName
                                    FileHash          = $hash
                                    CreationTimeUtc   = $creation_time
                                    LastWriteTimeUtc  = $lastwrite_time
                                    LastAccessTimeUtc = $lastaccess_time
                                    Error             = "Suspicious"
                                }
                                $fErrors += $newError;
                                $errHappend = $true
                            }
                        }
                    }
                }

                foreach ($f in (Get-ChildItem -Recurse -Path $pdir -File -Include *aspx, *asmx, *asax, *js, *css, *htm, *html)) {
                    if ($f.Name.EndsWith(".strings.localized.js")) {
                        continue;
                    }

                    $creation_time = Get-Date ($f.CreationTimeUtc) -Format $datetime_format
                    $lastwrite_time = Get-Date ($f.LastWriteTimeUtc) -Format $datetime_format
                    $lastaccess_time = Get-Date ($f.LastAccessTimeUtc) -Format $datetime_format

                    $hash = GetFileHash $f.FullName

                    if ([string]::IsNullOrEmpty($hash)) {
                        $newError = New-Object PSObject -Property @{
                            VDir              = $vdir
                            PDir              = $pdir
                            FileName          = $f.Name
                            FilePath          = $f.FullName
                            FileHash          = ""
                            CreationTimeUtc   = $creation_time
                            LastWriteTimeUtc  = $lastwrite_time
                            LastAccessTimeUtc = $lastaccess_time
                            Error             = "ReadError"
                        }
                        $fErrors += $newError;
                        $errHappend = $true
                    }

                    if ($pdir.StartsWith("$env:SystemDrive\inetpub\wwwroot")) {
                        if ($mark_as_suspicious_from -le $f.LastWriteTime) {
                            $newError = New-Object PSObject -Property @{
                                VDir              = $vdir
                                PDir              = $pdir
                                FileName          = $f.Name
                                FilePath          = $f.FullName
                                FileHash          = $hash
                                CreationTimeUtc   = $creation_time
                                LastWriteTimeUtc  = $lastwrite_time
                                LastAccessTimeUtc = $lastaccess_time
                                Error             = "Suspicious"
                            }
                            $fErrors += $newError;
                            $errHappend = $true
                        }
                    }

                    if ($KNOWN_ROOT_FILES[$f.FullName]) {
                        continue;
                    }

                    if ($hash) {
                        if ($known_bad[$hash]) {
                            $newError = New-Object PSObject -Property @{
                                VDir              = $vdir
                                PDir              = $pdir
                                FileName          = $f.Name
                                FilePath          = $f.FullName
                                FileHash          = $hash
                                CreationTimeUtc   = $creation_time
                                LastWriteTimeUtc  = $lastwrite_time
                                LastAccessTimeUtc = $lastaccess_time
                                Error             = "KnownBadHash"
                            }
                            $fErrors += $newError;
                            $errHappend = $true
                        }

                        $found = $false
                        foreach ($key in $baselines.Keys) {
                            if ([string]::IsNullOrEmpty($key)) {
                                continue;
                            }

                            if ($baselines[$key] -and [string]::IsNullOrEmpty($baselines[$key][$hash]) -ne $true) {
                                $found = $true
                                break;
                            }
                        }

                        if ($found -eq $false) {
                            $newError = New-Object PSObject -Property @{
                                VDir              = $vdir
                                PDir              = $pdir
                                FileName          = $f.Name
                                FilePath          = $f.FullName
                                FileHash          = $hash
                                CreationTimeUtc   = $creation_time
                                LastWriteTimeUtc  = $lastwrite_time
                                LastAccessTimeUtc = $lastaccess_time
                                Error             = "NoHashMatch"
                            }
                            $fErrors += $newError;
                            $errHappend = $true
                        }
                    }
                }

                if ($errHappend -eq $false) {
                    return $null
                }

                return New-Object PSObject -Property @{
                    VDir       = $vdir
                    PDir       = $pdir
                    VDirErrors = $vdirErrors
                    PDirErrors = $pdirErrors
                    FileErrors = $fErrors
                }
            } -ArgumentList $baselineData, $pattern, $_, $KNOWN_BAD_HASH, $KNOWN_ROOT_FILES, $MARK_AS_SUSPICIOUS_FROM

            $jobs += $j
        }

        foreach ($job in $jobs) {
            $job | Wait-Job | Out-Null
            $res = Receive-Job $job.ID
            if ($res) {
                $errFound = $true
                $result[$res.VDir] = $res
            }
        }
    }

    return $result, $errFound
}

function Main() {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Just getting this working for now. Will revisit.')]
    param()

    Write-Host "[$(Get-Date)] Started..." -ForegroundColor Green
    $exchVersion, $installedVers = FindInstalledVersions # Get-ExchangeVersion

    Write-Host "Found exchange version: $exchVersion" -ForegroundColor Green
    $pattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList '(.+)\s+\"(.+)\"\s+\(physicalPath:(.+)\)'
    $baselineData = LoadBaseline $installedVers

    $result, $errFound = PerformComparison $baselineData $pattern $exchVersion
    Write-Host "Comparison complete. Writing results."
    WriteScriptResult $result $exchVersion $errFound
}

function LoadFromGitHub($url, $filename, $installed_versions) {
    Write-Host "Downloading baseline file from GitHub to $filename"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # this file is only used for network connectivity test
        Invoke-WebRequest -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/baseline_15.0.1044.25.checksum.txt" | Out-Null
    } catch {
        Write-Error "Cannot reach out to https://github.com/microsoft/CSS-Exchange/releases/latest, please download baseline files for $installed_versions from https://github.com/microsoft/CSS-Exchange/releases/latest manually to $(GetCurrDir), then rerun this script from $(GetCurrDir)."
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $filename | Out-Null
    } catch {
        Write-Error "$filename not found... please open issue on https://github.com/microsoft/CSS-Exchange/issues, we will work on it"
    }
}

function PreProcessBaseline($baselines) {
    $data = @{}
    foreach ($baseline in $baselines) {
        # each baseline contains csv data corresponding the a version
        $baseline | ForEach-Object {
            $sp = $_.Split(',');

            if (-not $data[$sp[1]]) {
                $data[$sp[1]] = @{}
            }

            # only one hash should be found for the same file in a version.
            $data[$sp[1]][$sp[0]] = $sp[2]
        }
    }

    return $data
}

function FindInstalledVersions() {
    $VDIR_PATTERN = New-Object System.Text.RegularExpressions.Regex -ArgumentList  '(.+)\s+\"(.+)\"\s+\(physicalPath:(.+)\)'

    $versions = @{}

    Add-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue
    $server = (Get-ExchangeServer) | Where-Object { $_.Identity.Name -eq (hostname) }
    if ($server.AdminDisplayVersion.Major -eq 14) {
        $exchange_version = (Get-Command ExSetup | ForEach-Object { $_.FileVersionInfo }).ProductVersion
    } else {
        $exchange_version = "$($server.AdminDisplayVersion.Major).$($server.AdminDisplayVersion.Minor).$($server.AdminDisplayVersion.Build).$($server.AdminDisplayVersion.Revision)"
    }

    Remove-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue

    $versions[$exchange_version] = $true
    $vdir_paths = @()
    $logs = & (Join-Path $env:Windir "system32\inetsrv\appcmd.exe") LIST VDIRS | Sort-Object

    foreach ($log in $logs) {
        $log -match $VDIR_PATTERN | Out-Null;
        $vdir_physical_path = $Matches[3]
        $vdir_physical_path = $vdir_physical_path -replace "%SystemDrive%", $env:SystemDrive
        $vdir_physical_path = $vdir_physical_path -replace "%windir%", $env:windir

        # note: some vdirs share same physical paths
        $vdir_paths += $vdir_physical_path
    }

    $vdir_paths | Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem -Directory -Path $_ -Recurse } | Where-Object { $VALID_VERSIONS[$_.Name] -eq $true } | ForEach-Object { $versions[$_.Name] = $true }

    return $exchange_version, $versions.Keys
}

function GetVdirBatches {
    $grps = @{}
    $i = 0
    $batchSize = 10
    $logs = & (Join-Path $env:Windir "system32\inetsrv\appcmd.exe") LIST VDIRS

    $logs | ForEach-Object {
        $bt = $i % $batchSize
        $grps[$bt] += @($_)
        $i++
    }

    return $grps
}

function LoadBaseline($installed_versions) {
    $data = @{}
    foreach ($version in $installed_versions) {
        $filename = "baseline_$version"
        $zip_file_name = "${filename}.zip"
        $filename = (Join-Path (GetCurrDir) $filename)
        $zip_file = "${filename}.zip"

        if (-not (Test-Path $zip_file)) {
            Write-Host "Can't find local baseline for $version"
            $zip_file_url = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$zip_file_name"
            LoadFromGitHub -url $zip_file_url -filename $zip_file -installed_versions $installed_versions
        }

        if (Get-Command Expand-Archive -EA SilentlyContinue) {
            Expand-Archive -Path $zip_file -DestinationPath $filename -Force | Out-Null
        } else {
            [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" ) | Out-Null
            if (Test-Path  $filename) {
                Remove-Item $filename -Confirm:$false -Force -Recurse
            }

            [System.IO.Compression.ZipFile]::ExtractToDirectory($zip_file, $filename) | Out-Null
        }

        $csv_file = Get-ChildItem $filename | Select-Object -First 1 | Select-Object FullName
        $baselines = Get-Content $csv_file.FullName
        $processed_baselines = PreProcessBaseline $baselines

        foreach ($k in $processed_baselines.Keys) {
            Write-Host "Loaded baseline for $k, hashes number $($processed_baselines[$k].Count)"
            $data[$k] = $processed_baselines[$k]
        }
    }

    return $data
}

function WriteScriptResult ($result, $exchVersion, $errFound) {
    $tmp_file = Join-Path (GetCurrDir) ($exchVersion + "_" + "result.csv")
    $resData = @(
        $result.Keys | ForEach-Object {
            $currentResult = $result[$_]
            foreach ($fileError in $currentResult.FileErrors) {
                New-Object PsObject -Property @{
                    'FileName'          = $fileError.FileName
                    'VDir'              = $fileError.VDir
                    'Error'             = [string]$fileError.Error
                    'FilePath'          = [string]$fileError.FilePath
                    'FileHash'          = [string]$fileError.FileHash
                    'CreationTimeUtc'   = [string]$fileError.CreationTimeUtc
                    'LastWriteTimeUtc'  = [string]$fileError.LastWriteTimeUtc
                    'LastAccessTimeUtc' = [string]$fileError.LastAccessTimeUtc
                    'PDir'              = [string]$fileError.PDir
                }
            }
        }
    )

    Write-Host "Exporting ${resData.Count} objects to results"
    $resData | Select-Object | Export-Csv -Path $tmp_file -NoTypeInformation;

    $fgCol = 'Green'
    $msg = "[$(Get-Date)] Done."
    if ($errFound -eq $true) {
        $fgCol = 'Red'
        $msg += ' One or more potentially malicious files found, please inspect the result file.'
        $msg += " ExchangeVersion: $exchVersion"
        $msg += " OSVersion: $([environment]::OSVersion.Version)"
        $msg += " ScriptVersion: $BuildVersion"
        $report_msg = @"
        Submitting files for analysis:
        Please submit the output file for analysis in the malware analysis portal
        in the link below. Please add the text 'ExchangeMarchCVE' in
        'Additional Information' field on the portal submission form.
        https://www.microsoft.com/en-us/wdsi/filesubmission
        Instructions on how to use the portal can be found here:
        https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/submission-guide
"@

        Write-Host $report_msg
    }

    Write-Host "Exported results to $tmp_file"
    Write-Host $msg -ForegroundColor $fgCol
}

function GetCurrDir {
    if ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
        return $MyInvocation.MyCommand.Path
    }

    return Get-Location
}

Main
