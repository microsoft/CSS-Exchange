# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function BaseFileName([string]$identity, [string]$suffix) {
    $smtp = $identity.Split('@')[0]
    $smtp = $smtp -replace '[\\/:*?"<>|]', ''
    $date = Get-Date -Format "yyyyMMdd"
    $hour = Get-Date -Format "HHmm"
    if ([string]::IsNullOrEmpty($suffix)) {
        $file = $date + "_" + $hour + "_" + $smtp
    } else {
        $file = $date + "_" + $hour + "_" + $smtp + "_" + $suffix
    }
    return $file
}

function CSVFilename([string]$identity, [string]$suffix) {
    return (BaseFileName $identity $suffix) + ".csv"
}

function XLSXFilename([string]$identity) {
    return (BaseFileName $identity $suffix) + ".xlsx"
}

function SaveDataAsCSV([string]$identity) {
    $filename = CSVFilename -Identity $identity -suffix "TenantSettings"
    $script:TenantSettings | Export-Csv -Path $filename -NoTypeInformation -ErrorAction SilentlyContinue

    $filename = CSVFilename -identity $identity -suffix "MBData"
    $script:bookingMBData | Export-Csv -Path $filename -NoTypeInformation -ErrorAction SilentlyContinue

    $filename = CSVFilename -identity $identity -suffix "StaffMembershipLog"
    $script:BookingStaffMembershipLogArray | Export-Csv -Path $filename -NoTypeInformation -ErrorAction SilentlyContinue

    $filename = CSVFilename -identity $identity -suffix "MTLogs"
    $script:MessageTrackingLogs | Export-Csv -Path $filename -NoTypeInformation -ErrorAction SilentlyContinue

    $filename = CSVFilename -identity $identity -suffix "StaffData"
    $script:StaffData | Export-Csv -Path $filename -NoTypeInformation -ErrorAction SilentlyContinue
}
