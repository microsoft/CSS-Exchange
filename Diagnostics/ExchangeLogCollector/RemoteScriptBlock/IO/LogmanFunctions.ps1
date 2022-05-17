# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function GetLogmanExtension {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$RawLogmanData
    )
    $line = $RawLogmanData | Where-Object { $_.Trim().Contains("Output Location:") }

    if ($null -ne $line) {
        [int]$index = $line.LastIndexOf(".")

        if ($index -ne -1) {
            return $line.Substring($index)
        }
    }
    return ".blg"
}

Function GetLogmanStartDate {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$RawLogmanData
    )
    $line = $RawLogmanData | Where-Object { $_.Trim().Contains("Start Date:") }

    if ($null -ne $line) {
        [string]$dateTime = $line.Substring($line.LastIndexOf(" ") + 1)
        return [System.Convert]::ToDateTime($dateTime)
    }
    return [datetime]::MinValue
}

Function CopyLogmanData {
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
    Write-Verbose "Copy From Date: $filterDate"

    if ([DateTime]$filterDate -lt [DateTime]$copyFromDate) {
        $filterDate = $copyFromDate
        Write-Verbose "Updating Copy From Date to: $filterDate"
    }

    if ((Test-Path $directory)) {

        $childItems = Get-ChildItem $directory -Recurse |
            Where-Object { $_.Name -like "*$($LogmanObject.Extension)" }

        if ($null -ne $childItems) {
            $items = $childItems |
                Where-Object { $_.CreationTime -ge $filterDate } |
                ForEach-Object { $_.VersionInfo.FileName }

            if ($null -ne $items) {
                Copy-BulkItems -CopyToLocation $copyTo -ItemsToCopyLocation $items
                Invoke-ZipFolder -Folder $copyTo
                return
            } else {
                Write-Host "Failed to find any files in the directory: $directory that was greater than or equal to this time: $filterDate" -ForegroundColor "Yellow"
                $filterDate = ($childItems |
                        Sort-Object CreationTime -Descending |
                        Select-Object -First 1).CreationTime.AddDays(-1)
                Write-Verbose "Updated filter time to $filterDate"
                $items = $childItems |
                    Where-Object { $_.CreationTime -ge $filterDate } |
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

Function GetLogmanObject {
    [CmdletBinding()]
    param(
        [string]$LogmanName
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $status = "Stopped"
        $rootPath = [string]::Empty
        $extension = ".blg"
        $startDate = [datetime]::MinValue
        $foundLogman = $false
    }
    process {
        try {
            $dcsc = New-Object -ComObject Pla.DataCollectorSetCollection
            $dcsc.GetDataCollectorSets($null, $null)
            $existingLogmanDcsc = $dcsc | Where-Object { $_.Name -eq $LogmanName }

            if ($null -eq $existingLogmanDcsc) { return }

            if ($existingLogmanDcsc.Status -eq 1) {
                $status = "Running"
            }

            $rootPath = $existingLogmanDcsc.RootPath

            $logmanResults = logman $LogmanName

            if ($LASTEXITCODE) {
                Write-Verbose "Failed to get logman information"
                return
            }

            $logmanResults | ForEach-Object { Write-Verbose $_ }
            $extension = GetLogmanExtension $logmanResults
            $startDate = GetLogmanStartDate $logmanResults
            $foundLogman = $true
        } catch {
            Write-Verbose "Failed to get the Logman information. Exception $_"
        }

        finally {
            if ($null -ne $dcsc) {
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($dcsc) | Out-Null
                $dcsc = $null
                $existingLogmanDcsc = $null
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

Function GetLogmanData {
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

Function Save-LogmanExmonData {
    GetLogmanData -LogmanName $PassedInfo.ExmonLogmanName
}

Function Save-LogmanExperfwizData {
    $PassedInfo.ExperfwizLogmanName |
        ForEach-Object {
            GetLogmanData -LogmanName $_
        }
}
