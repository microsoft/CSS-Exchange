# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1
. $PSScriptRoot\..\Invoke-ScriptBlockHandler.ps1

function Get-IISModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$ApplicationHostConfig,

        [Parameter(Mandatory = $false)]
        [bool]$SkipLegacyOSModulesCheck = $false,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $modulesToCheckList = New-Object 'System.Collections.Generic.List[object]'

        function GetModulePath {
            [CmdletBinding()]
            [OutputType([System.String])]
            param(
                [string]$Path
            )

            if (-not([String]::IsNullOrEmpty($Path))) {
                $returnPath = $Path

                if ($Path -match "\%.+\%") {
                    Write-Verbose "Environment variable found in path: $Path"
                    # Assuming that we have the env var always at the beginning of the string and no other vars within the string
                    # Example: %windir%\system32\SomeExample.dll
                    $preparedPath = ($Path.Split("%", [System.StringSplitOptions]::RemoveEmptyEntries))
                    if ($preparedPath.Count -eq 2) {
                        if ($preparedPath[0] -notmatch "\\.+\\") {
                            $varPath = [System.Environment]::GetEnvironmentVariable($preparedPath[0])
                            $returnPath = [String]::Join("", $varPath, $($preparedPath[1]))
                        }
                    }
                }
            } else {
                $returnPath = $null
            }

            return $returnPath
        }
        function GetIISModulesSignatureStatus {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$ComputerName,

                [Parameter(Mandatory = $true)]
                [object[]]$Modules,

                [Parameter(Mandatory = $false)]
                [bool]$SkipLegacyOSModules = $false,

                [Parameter(Mandatory = $false)]
                [ScriptBlock]$CatchActionFunction
            )
            begin {
                # Add all modules here which should be skipped on legacy OS (pre-Windows Server 2016)
                $modulesToSkip = @(
                    "$env:windir\system32\inetSrv\cachUri.dll",
                    "$env:windir\system32\inetSrv\cachFile.dll",
                    "$env:windir\system32\inetSrv\cachtokn.dll",
                    "$env:windir\system32\inetSrv\cachHttp.dll",
                    "$env:windir\system32\inetSrv\compStat.dll",
                    "$env:windir\system32\inetSrv\defDoc.dll",
                    "$env:windir\system32\inetSrv\dirList.dll",
                    "$env:windir\system32\inetSrv\protsUp.dll",
                    "$env:windir\system32\inetSrv\redirect.dll",
                    "$env:windir\system32\inetSrv\static.dll",
                    "$env:windir\system32\inetSrv\authAnon.dll",
                    "$env:windir\system32\inetSrv\cusTerr.dll",
                    "$env:windir\system32\inetSrv\logHttp.dll",
                    "$env:windir\system32\inetSrv\iisEtw.dll",
                    "$env:windir\system32\inetSrv\iisFreb.dll",
                    "$env:windir\system32\inetSrv\iisReQs.dll",
                    "$env:windir\system32\inetSrv\isApi.dll",
                    "$env:windir\system32\inetSrv\compDyn.dll",
                    "$env:windir\system32\inetSrv\authCert.dll",
                    "$env:windir\system32\inetSrv\authBas.dll",
                    "$env:windir\system32\inetSrv\authsspi.dll",
                    "$env:windir\system32\inetSrv\authMd5.dll",
                    "$env:windir\system32\inetSrv\modRqFlt.dll",
                    "$env:windir\system32\inetSrv\filter.dll",
                    "$env:windir\system32\rpcProxy\rpcProxy.dll",
                    "$env:windir\system32\inetSrv\validCfg.dll",
                    "$env:windir\system32\wsmSvc.dll",
                    "$env:windir\system32\inetSrv\ipReStr.dll",
                    "$env:windir\system32\inetSrv\dipReStr.dll",
                    "$env:windir\system32\inetSrv\iis_ssi.dll",
                    "$env:windir\system32\inetSrv\cgi.dll",
                    "$env:windir\system32\inetSrv\iisFcGi.dll",
                    "$env:windir\system32\inetSrv\iisWSock.dll",
                    "$env:windir\system32\inetSrv\warmup.dll")

                $iisModulesList = New-Object 'System.Collections.Generic.List[object]'
                $signerSubject = "O=Microsoft Corporation, L=Redmond, S=Washington"
            }
            process {
                try {
                    $numberOfModulesFound = $Modules.Count
                    if ($numberOfModulesFound -ge 1) {
                        Write-Verbose "$numberOfModulesFound module(s) loaded by IIS"
                        Write-Verbose "SkipLegacyOSModules enabled? $SkipLegacyOSModules"
                        Write-Verbose "Checking file signing information now..."

                        $signatureParams = @{
                            ComputerName        = $ComputerName
                            ScriptBlock         = { Get-AuthenticodeSignature -FilePath $args[0] }
                            ArgumentList        = , $Modules.image # , is used to force the array to be passed as a single object
                            CatchActionFunction = $CatchActionFunction
                        }
                        $allSignatures = Invoke-ScriptBlockHandler @signatureParams

                        foreach ($m in $Modules) {
                            Write-Verbose "Now processing module: $($m.name)"
                            $signature = $null
                            $isModuleSigned = $false
                            $signatureDetails = [PSCustomObject]@{
                                Signer            = $null
                                SignatureStatus   = -1
                                IsMicrosoftSigned = $null
                            }

                            try {
                                $signature = $allSignatures | Where-Object { $_.Path -eq $m.image } | Select-Object -First 1
                                if (($SkipLegacyOSModules) -and
                                    ($m.image -in $modulesToSkip)) {
                                    Write-Verbose "Module was found in module skip list and will be skipped"
                                    # set to $null as this will indicate that the module was on the skip list
                                    $isModuleSigned = $null
                                } elseif ($null -ne $signature) {
                                    Write-Verbose "Performing signature status validation. Status: $($signature.Status)"
                                    # Signature Status Enum Values:
                                    # <0> Valid, <1> UnknownError, <2> NotSigned, <3> HashMismatch,
                                    # <4> NotTrusted, <5> NotSupportedFileFormat, <6> Incompatible,
                                    # https://docs.microsoft.com/dotnet/api/system.management.automation.signaturestatus
                                    if (($null -ne $signature.Status) -and
                                        ($signature.Status -ne 1) -and
                                        ($signature.Status -ne 2) -and
                                        ($signature.Status -ne 5) -and
                                        ($signature.Status -ne 6)) {

                                        $signatureDetails.SignatureStatus = $signature.Status
                                        $isModuleSigned = $true

                                        if ($null -ne $signature.SignerCertificate.Subject) {
                                            Write-Verbose "Signer information found. Subject: $($signature.SignerCertificate.Subject)"
                                            $signatureDetails.Signer = $signature.SignerCertificate.Subject.ToString()
                                            $signatureDetails.IsMicrosoftSigned = $signature.SignerCertificate.Subject -cmatch $signerSubject
                                        }
                                    }
                                } else {
                                    Write-Verbose "No signature information found for module $($m.name)"
                                    $isModuleSigned = $false
                                }

                                $iisModulesList.Add([PSCustomObject]@{
                                        Name             = $m.name
                                        Path             = $m.image
                                        Signed           = $isModuleSigned
                                        SignatureDetails = $signatureDetails
                                    })
                            } catch {
                                Write-Verbose "Unable to validate file signing information"
                                Invoke-CatchActionError $CatchActionFunction
                            }
                        }
                    } else {
                        Write-Verbose "No modules are loaded by IIS"
                    }
                } catch {
                    Write-Verbose "Failed to process global module information. $_"
                    Invoke-CatchActionError $CatchActionFunction
                }
            }
            end {
                return $iisModulesList
            }
        }
    }
    process {
        $ApplicationHostConfig.configuration.'system.webServer'.globalModules.add | ForEach-Object {
            $moduleFilePath = GetModulePath -Path $_.image
            # Replace the image path with the full path without environment variables
            $_.image = $moduleFilePath
            $modulesToCheckList.Add($_)
        }

        $getIISModulesSignatureStatusParams = @{
            ComputerName        = $ComputerName
            Modules             = $modulesToCheckList
            SkipLegacyOSModules = $SkipLegacyOSModulesCheck # now handled within the function as we need to return all modules which are loaded by IIS
            CatchActionFunction = $CatchActionFunction
        }
        $modules = GetIISModulesSignatureStatus @getIISModulesSignatureStatusParams

        # Validate if all modules that are loaded are digitally signed
        $allModulesAreSigned = (-not($modules.Signed.Contains($false)))
        Write-Verbose "Are all modules loaded by IIS digitally signed? $allModulesAreSigned"

        # Validate that all modules are signed by Microsoft Corp.
        $allModulesSignedByMSFT = (-not($modules.SignatureDetails.IsMicrosoftSigned.Contains($false)))
        Write-Verbose "Are all modules signed by Microsoft Corporation? $allModulesSignedByMSFT"

        # Validate if all signatures are valid (regardless of whether signed by Microsoft Corp. or not)
        $allSignaturesValid = $null -eq ($modules | Where-Object {
                ($_.Signed) -and
                ($_.SignatureDetails.SignatureStatus -ne 0)
            })
    }
    end {
        return [PSCustomObject]@{
            AllSignedModulesSignedByMSFT = $allModulesSignedByMSFT
            AllSignaturesValid           = $allSignaturesValid
            AllModulesSigned             = $allModulesAreSigned
            ModuleList                   = $modules
        }
    }
}
