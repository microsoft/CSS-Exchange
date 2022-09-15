﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1

function Get-IISModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$ApplicationHostConfig,

        [Parameter(Mandatory = $false)]
        [scriptblock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
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
                    # Example: %windir%\system32\someexample.dll
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
                [object[]]$Modules
            )
            process {
                try {
                    $iisModulesList = New-Object 'System.Collections.Generic.List[object]'
                    if ($Modules.Count -ge 1) {
                        Write-Verbose "At least one module is loaded by IIS"
                        foreach ($m in $Modules) {
                            Write-Verbose "Now processing module: $($m.Name)"
                            $isModuleSigned = $false
                            $signatureDetails = [PSCustomObject]@{
                                Signer            = $null
                                SignatureStatus   = -1
                                IsMicrosoftSigned = $null
                            }

                            $moduleFilePath = GetModulePath -Path $m.Image

                            try {
                                Write-Verbose "Querying file signing information"
                                $signature = Get-AuthenticodeSignature -FilePath $moduleFilePath -ErrorAction Stop
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
                                        $signatureDetails.IsMicrosoftSigned = $signature.SignerCertificate.Subject -cmatch "O=Microsoft Corporation, L=Redmond, S=Washington"
                                    }
                                }

                                $iisModulesList.Add([PSCustomObject]@{
                                        Name             = $m.Name
                                        Path             = $moduleFilePath
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
        $modules = GetIISModulesSignatureStatus -Modules $ApplicationHostConfig.configuration.'system.webServer'.globalModules.add

        # Validate if all modules that are loaded are digitally signed
        $allModulesAreSigned = (-not($modules.Signed.Contains($false)))
        Write-Verbose "Are all modules loaded by IIS digitally signed? $allModulesAreSigned"

        # Validate that all modules are signed by Microsoft Corp.
        $allModulesSignedByMSFT = (-not($modules.SignatureDetails.IsMicrosoftSigned.Contains($false)))
        Write-Verbose "Are all modules signed by Microsoft Corporation? $allModulesSignedByMSFT"

        # Validate if all signatures are valid (regardless of whether signed by Microsoft Corp. or not)
        $allSignaturesValid = $null -eq ($modules |
                Where-Object { $_.Signed -and $_.SignatureDetails.SignatureStatus -ne 0 })
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
