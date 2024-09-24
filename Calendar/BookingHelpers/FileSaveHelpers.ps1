# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function BaseFileName([string]$Identity, [string]$Suffix) {
    $Smtp = $Identity.Split('@')[0]
    $Smtp = $Smtp -replace '[\\/:*?"<>|]', ''
    $Date = Get-Date -Format "yyyyMMdd"
    $Hour = Get-Date -Format "HHmm"
    if ([string]::IsNullOrEmpty($Suffix)) {
        $File = $Date + "_" + $Hour + "_" + $Smtp
    } else {
        $File = $Date + "_" + $Hour + "_" + $Smtp + "_" + $Suffix
    }
    return $File
}

function CSVFilename([string]$Identity, [string]$Suffix) {
    return (BaseFileName $Identity $Suffix) + ".csv"
}

function XLSXFilename([string]$Identity) {
    return (BaseFileName $Identity $Suffix) + ".xlsx"
}

function SaveDataAsCSV([string]$Identity) {
    $Filename = CSVFilename -Identity $Identity -suffix "TenantSettings"
    $script:TenantSettings | Export-Csv -Path $Filename -NoTypeInformation -ErrorAction SilentlyContinue

    $Filename = CSVFilename -identity $Identity -suffix "MBData"
    $script:BookingMBData | Export-Csv -Path $Filename -NoTypeInformation -ErrorAction SilentlyContinue

    $Filename = CSVFilename -identity $Identity -suffix "StaffMembershipLog"
    $script:BookingStaffMembershipLogArray | Export-Csv -Path $Filename -NoTypeInformation -ErrorAction SilentlyContinue

    $Filename = CSVFilename -identity $Identity -suffix "MTLogs"
    $script:MessageTrackingLogs | Export-Csv -Path $Filename -NoTypeInformation -ErrorAction SilentlyContinue

    $Filename = CSVFilename -identity $Identity -suffix "StaffData"
    $script:StaffData | Export-Csv -Path $Filename -NoTypeInformation -ErrorAction SilentlyContinue
}
