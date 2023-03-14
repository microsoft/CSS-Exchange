# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1
. $PSScriptRoot\ScriptUpdateFunctions\Invoke-WebRequestWithProxyDetection.ps1

<#
    This function will download a NuGet package from the NuGet.org repository.

    NuGet service index request is used to get the search Service Url which will be then used to search for NuGet packages.
    We always try to download the latest version of a package.

    NuGet api documentation:
    https://learn.microsoft.com/en-us/nuget/api/service-index
    https://learn.microsoft.com/en-us/nuget/api/search-query-service-resource
#>

function Get-NuGetPackage {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageId,

        [Parameter(Mandatory = $false)]
        [string]$Author,

        [Parameter(Mandatory = $false)]
        [string]$SaveTo = $PSScriptRoot,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $SaveTo = $SaveTo.TrimEnd("\")
        $packageFound = $false
        $downloadSuccessful = $false
    }
    process {
        if ((Test-Path -Path $SaveTo) -eq $false) {
            Write-Verbose "Path: $SaveTo doesn't exist, creating it"

            try {
                New-Item -ItemType Directory -Path $SaveTo -ErrorAction Stop | Out-Null
            } catch {
                Write-Verbose "Unable to create directory: '$($SaveTo)' - Exception: $($Error[0].Exception.Message)"
                Invoke-CatchActionError $CatchActionFunction
                return
            }
        }

        try {
            $nuGetIndexResponse = Invoke-WebRequestWithProxyDetection -Uri "https://api.nuget.org/v3/index.json" -UseBasicParsing -ErrorAction Stop

            if ($nuGetIndexResponse.StatusCode -eq 200) {
                Write-Verbose "NuGet service index request successful"
                $nuGetIndex = $nuGetIndexResponse.Content | ConvertFrom-Json -ErrorAction Stop
            } else {
                Write-Verbose "NuGet service index request failed with status code: $($nuGetIndexResponse.StatusCode)"
                return
            }

            $nuGetSearchService = ($nuGetIndex.resources | Where-Object { $_.'@type' -eq "SearchQueryService" } | Select-Object -First 1).'@id'
            $nuGetSearchResponse = Invoke-WebRequestWithProxyDetection -Uri ("$($nuGetSearchService)?q={0}" -f $PackageId) -UseBasicParsing -ErrorAction Stop

            if ($nuGetSearchResponse.StatusCode -eq 200) {
                Write-Verbose "NuGet search request successful"
                $nuGetSearch = $nuGetSearchResponse.Content | ConvertFrom-Json -ErrorAction Stop
            } else {
                Write-Verbose "NuGet search request failed with status code: $($nuGetSearchResponse.StatusCode)"
                return
            }

            if ($nuGetSearch.totalHits -ge 1) {
                Write-Verbose "We found: $($nuGetSearch.totalHits) packages with the name: $PackageId"
                Write-Verbose "Applying filter for id: $PackageId"
                $nuGetPackage = $nuGetSearch.data | Where-Object { $_.id -eq $PackageId }

                if ($null -ne $Author) {
                    Write-Verbose "Applying filter for author: $Author"
                    $nuGetPackage = $nuGetPackage | Where-Object { $_.authors -eq $Author }
                }

                if (($null -ne $nuGetPackage) -and
                ($nuGetPackage.title.Count -eq 1)) {
                    Write-Verbose "NuGet package found: $($nuGetPackage.id)"
                    $packageFound = $true
                    Write-Verbose "Description: $($nuGetPackage.description)"
                    $nuGetVersionsUrl = $nuGetPackage.versions[-1].'@id'

                    $nuGetVersionsResponse = Invoke-WebRequestWithProxyDetection -Uri $nuGetVersionsUrl -UseBasicParsing -ErrorAction Stop

                    if ($nuGetVersionsResponse.StatusCode -eq 200) {
                        $nuGetDownloadUrl = ($nuGetVersionsResponse.Content | ConvertFrom-Json -ErrorAction Stop).packageContent

                        $nuGetPackageFileName = $nuGetDownloadUrl.Split("/")[-1]
                        $fullPathToDownloadedFile = "$($SaveTo)\$($nuGetPackageFileName)"
                    }
                }

                if ($null -ne $nuGetDownloadUrl) {
                    if (Test-Path -Path $fullPathToDownloadedFile) {
                        Write-Verbose "File: $fullPathToDownloadedFile already exists, deleting it"
                        Remove-Item -Path $fullPathToDownloadedFile -Force -ErrorAction Stop | Out-Null
                    }

                    Write-Verbose "Downloading package from: $nuGetDownloadUrl"
                    Invoke-WebRequestWithProxyDetection -Uri $nuGetDownloadUrl -OutFile $fullPathToDownloadedFile -UseBasicParsing -ErrorAction Stop

                    if (Test-Path -Path $fullPathToDownloadedFile) {
                        Write-Verbose "Download successful"
                        $downloadSuccessful = $true
                    }
                }
            } else {
                Write-Verbose "No package found with id: $PackageId"
            }
        } catch {
            Write-Verbose "Unable to run WebRequest - Exception: $($Error[0].Exception.Message)"
            Invoke-CatchActionError $CatchActionFunction
            return
        }
    }
    end {
        return [PSCustomObject]@{
            PackageFound         = $packageFound
            DownloadSuccessful   = $downloadSuccessful
            NuGetPackageName     = $nuGetPackageFileName
            NuGetPackageFullPath = $fullPathToDownloadedFile
        }
    }
}
