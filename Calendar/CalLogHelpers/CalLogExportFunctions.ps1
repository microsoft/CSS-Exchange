# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# FileNames
# ===================================================================================================
function Get-FileName {
    Write-Host -ForegroundColor Cyan "Creating FileName for $Identity..."

    $ThisMeetingID = $script:GCDO.CleanGlobalObjectId | Select-Object -Unique
    $ShortMeetingID = $ThisMeetingID.Substring($ThisMeetingID.length - 6)

    if ($script:Identity -like "*@*") {
        $script:ShortId = $script:Identity.Split('@')[0]
    } else {
        $script:ShortId = $script:Identity
    }
    $script:ShortId = $ShortId.Substring(0, [System.Math]::Min(20, $ShortId.Length))

    if (($null -eq $CaseNumber) -or
        ([string]::IsNullOrEmpty($CaseNumber))) {
        $Case = ""
    } else {
        $Case = $CaseNumber + "_"
    }

    if ($ExportToExcel.IsPresent) {
        $script:FileName = "$($Case)CalLogSummary_$($ShortMeetingID).xlsx"
        Write-Host -ForegroundColor Blue -NoNewline "All Calendar Logs for meetings ending in ID [$ShortMeetingID] will be saved to : "
        Write-Host -ForegroundColor Yellow "$Filename"
    } else {
        $script:Filename = "$($Case)$($ShortId)_$ShortMeetingID.csv"
        $script:FilenameRaw = "$($Case)$($ShortId)_RAW_$($ShortMeetingID).csv"
        $Script:TimeLineFilename = "$($Case)$($ShortId)_TimeLine_$ShortMeetingID.csv"

        Write-Host -ForegroundColor Cyan -NoNewline "Enhanced Calendar Logs for [$Identity] has been saved to : "
        Write-Host -ForegroundColor Yellow "$Filename"

        Write-Host -ForegroundColor Cyan -NoNewline "Raw Calendar Logs for [$Identity] has been saved to : "
        Write-Host -ForegroundColor Yellow "$FilenameRaw"

        Write-Host -ForegroundColor Cyan -NoNewline "TimeLine for [$Identity] has been saved to : "
        Write-Host -ForegroundColor Yellow "$TimeLineFilename"
    }
}

function Export-CalLog {
    Get-FileName

    if ($ExportToExcel.IsPresent) {
        Export-CalLogExcel
    } else {
        Export-CalLogCSV
    }
}

function Export-CalLogCSV {
    $GCDOResults | Export-Csv -Path $Filename -NoTypeInformation -Encoding UTF8
    $script:GCDO | Export-Csv -Path $FilenameRaw -NoTypeInformation -Encoding UTF8
}

function Export-Timeline {
    Write-Verbose "Export to Excel is : $ExportToExcel"

    # Display Timeline to screen:
    Write-Host -ForegroundColor Cyan "Timeline for [$Identity]..."
    $script:TimeLineOutput

    if ($ExportToExcel.IsPresent) {
        Export-TimelineExcel
    } else {
        $script:TimeLineOutput | Export-Csv -Path $script:TimeLineFilename -NoTypeInformation -Encoding UTF8 -Append
    }
}
