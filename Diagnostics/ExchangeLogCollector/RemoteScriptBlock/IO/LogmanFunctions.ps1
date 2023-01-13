# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function CopyLogmanData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$LogmanObject
    )

    $copyTo = "$Script:RootCopyToDirectory\$($LogmanObject.LogmanName)_Data"
    New-Item -ItemType Directory -Path $copyTo -Force | Out-Null
    $directory = $LogmanObject.RootPath
    $filterDate = $LogmanObject.StartDate
    $copyFromDate = [DateTime]::Now - $PassedInfo.TimeSpan
    $copyToDate = [DateTime]::Now - $PassedInfo.EndTimeSpan
    Write-Verbose "Copy From Date: $filterDate"
    Write-Verbose "Copy To Date: $filterToDate"

    if ([DateTime]$filterDate -lt [DateTime]$copyFromDate) {
        $filterDate = $copyFromDate
        Write-Verbose "Updating Copy From Date: $filterDate"
    }

    if ([DateTime]$filterToDate -lt [DateTime]$copyToDate) {
        $filterToDate = $copyToDate
        Write-Verbose "Updating Copy to Date: $filterToDate"
    }

    if ((Test-Path $directory)) {

        $childItems = Get-ChildItem $directory -Recurse |
            Where-Object { $_.Name -like "*$($LogmanObject.Extension)" }

        if ($null -ne $childItems) {
            $items = $childItems |
                Where-Object { $_.CreationTime -ge $filterDate -and $_.CreationTime -le $filterToDate } |
                ForEach-Object { $_.VersionInfo.FileName }

            if ($null -ne $items) {
                Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items
                Invoke-ZipFolder -Folder $copyTo
                return
            } else {
                Write-Host "Failed to find any files in the directory: $directory that was greater than or equal to this time: $filterDate and lower than $filterToDate" -ForegroundColor "Yellow"
                $filterDate = ($childItems |
                        Sort-Object CreationTime -Descending |
                        Select-Object -First 1).CreationTime.AddDays(-1)
                Write-Verbose "Updated filter time to $filterDate"
                $items = $childItems |
                    Where-Object { $_.CreationTime -ge $filterDate -and $_.CreationTime -le $filterToDate } |
                    ForEach-Object { $_.VersionInfo.FileName }

                if ($null -ne $items) {
                    Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items
                    Invoke-ZipFolder -Folder $copyTo
                    return
                }
                Write-Verbose "Something went really wrong..."
            }
        }
        Write-Host "Failed to find any files in the directory $directory" -ForegroundColor "Yellow"
        New-Item -Path "$copyTo\NoFiles.txt" -Value $directory | Out-Null
    } else {
        Write-Host "Doesn't look like this Directory is valid: $directory" -ForegroundColor "Yellow"
        New-Item -Path "$copyTo\NotValidDirectory.txt" -Value $directory | Out-Null
    }
}

function GetLogmanObject {
    [CmdletBinding()]
    param(
        [string]$LogmanName
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $status = "Stopped"
        $rootPath = [string]::Empty
        $extension = ".blg"
        $startDate = [DateTime]::MinValue
        $foundLogman = $false
    }
    process {
        try {
            $dataCollectorSetList = New-Object -ComObject Pla.DataCollectorSetCollection
            $dataCollectorSetList.GetDataCollectorSets($null, $null)
            $existingLogmanDataCollectorSetList = $dataCollectorSetList | Where-Object { $_.Name -eq $LogmanName }

            if ($null -eq $existingLogmanDataCollectorSetList) { return }

            if ($existingLogmanDataCollectorSetList.Status -eq 1) {
                $status = "Running"
            }

            $rootPath = $existingLogmanDataCollectorSetList.RootPath
            $outputLocation = $existingLogmanDataCollectorSetList.DataCollectors._NewEnum.OutputLocation
            Write-Verbose "Output Location: $outputLocation"
            $extension = $outputLocation.Substring($outputLocation.LastIndexOf("."))
            $startDate = $existingLogmanDataCollectorSetList.Schedules._NewEnum.StartDate
            Write-Verbose "Status: $status RootPath: $rootPath Extension: $extension StartDate: $startDate"
            $foundLogman = $true
        } catch {
            Write-Verbose "Failed to get the Logman information. Exception $_"
        }

        finally {
            if ($null -ne $dataCollectorSetList) {
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($dataCollectorSetList) | Out-Null
                $dataCollectorSetList = $null
                $existingLogmanDataCollectorSetList = $null
            }
        }
    }
    end {
        return [PSCustomObject]@{
            LogmanName  = $LogmanName
            Status      = $status
            RootPath    = $rootPath
            Extension   = $extension
            StartDate   = $startDate
            FoundLogman = $foundLogman
        }
    }
}

function GetLogmanData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogmanName
    )
    $logmanObject = GetLogmanObject -LogmanName $LogmanName

    if ($logmanObject.FoundLogman) {
        if ($logmanObject.Status -eq "Running") {
            Write-Host "$LogmanName is running. Going to stop to prevent corruption for collection...."
            logman stop $LogmanName | Write-Verbose

            if ($LASTEXITCODE) {
                Write-Host "Failed to stop $LogmanName. $LastExitCode" -ForegroundColor "Red"
            }

            CopyLogmanData -LogmanObject $logmanObject
            Write-Host "Going to start $LogmanName again for you...."
            logman start $LogmanName | Write-Verbose

            if ($LASTEXITCODE) {
                Write-Host "Failed to start $LogmanName. $LastExitCode" -ForegroundColor "Red"
            }
        } else {
            Write-Host "$LogmanName isn't running, therefore not going to stop it prior to collection."
            CopyLogmanData -LogmanObject $logmanObject
        }
        Write-Host "Done copying $LogmanName"
    } else {
        Write-Host "Can't find Logman '$LogmanName'. Moving on..."
    }
}

function Save-LogmanExMonData {
    GetLogmanData -LogmanName $PassedInfo.ExMonLogmanName
}

function Save-LogmanExPerfWizData {
    $PassedInfo.ExPerfWizLogmanName |
        ForEach-Object {
            GetLogmanData -LogmanName $_
        }
}
