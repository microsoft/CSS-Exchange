# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-GraphBookingsServices {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )
    $GraphBookingBusiness = Get-MgBookingBusinessService -BookingBusinessId $Identity
    $MBStaff = Get-MgBookingBusinessStaffMember -BookingBusinessId $Identity
    $Services = @()
    foreach ($Service in $GraphBookingBusiness) {
        #determine serviceType
        $ServiceType = ""
        if ($Service.StaffMemberIds.Count -gt 1) {
            $ServiceType = "N"
        } else {
            $ServiceType = "1"
        }
        $ServiceType+= ":"
        if ($Service.MaximumAttendeesCount -gt 1) {
            $ServiceType += "N"
        } else {
            $ServiceType += "1"
        }
        #compose ServiceStaffIds
        $ServiceStaffIds = ""
        foreach ($StaffId in $Service.StaffMemberIds) {
            $ServiceStaffIds += $StaffId + "`r`n"
        }
        $StaffName1 = ""
        $StaffName2 = ""
        $StaffName3 = ""
        $StaffName4 = ""
        $StaffName5 = ""
        for ($I = 0; $I -lt $Service.StaffMemberIds.Count; $I++) {
            foreach ($StaffName in $MBStaff) {
                if ($StaffName.Id -eq $Service.StaffMemberIds[$I]) {
                    switch ($I) {
                        0 { $StaffName1 = $StaffName.AdditionalProperties["displayName"] }
                        1 { $StaffName2 = $StaffName.AdditionalProperties["displayName"] }
                        2 { $StaffName3 = $StaffName.AdditionalProperties["displayName"] }
                        3 { $StaffName4 = $StaffName.AdditionalProperties["displayName"] }
                        4 { $StaffName5 = $StaffName.AdditionalProperties["displayName"] }
                    }
                }
            }
        }

        $Services += [PSCustomObject]@{
            Id                    = $Service.Id
            ServiceType           = $ServiceType
            DisplayName           = $Service.DisplayName
            Description           = $Service.Description
            Duration              = $Service.DefaultDuration
            PreBuffer             = $Service.PreBuffer
            PostBuffer            = $Service.PostBuffer
            SchedulingPolicy      = $Service.SchedulingPolicy | ConvertTo-Json -Depth 10
            StaffMemberIds        = $ServiceStaffIds
            StaffName1            = $StaffName1
            StaffName2            = $StaffName2
            StaffName3            = $StaffName3
            StaffName4            = $StaffName4
            StaffName5            = $StaffName5
            MaximumAttendeesCount = $Service.MaximumAttendeesCount
            CustomQuestions       = $Service.CustomQuestions | ConvertTo-Json -Depth 10
            DefaultReminders      = $Service.DefaultReminders | ConvertTo-Json -Depth 10
            IsHiddenFromCustomers = $Service.IsHiddenFromCustomers
            IsLocationOnline      = $Service.IsLocationOnline
            DefaultLocation       = $Service.DefaultLocation | ConvertTo-Json -Depth 10
            Notes                 = $Service.Notes
            LanguageTag           = $Service.LanguageTag
            CreatedDateTime       = $Service.AdditionalProperties["createdDateTime"]
            LastUpdatedDateTime   = $Service.AdditionalProperties["lastUpdatedDateTime"]
            Price                 = $Service.AdditionalProperties["price"]
            Currency              = $Service.AdditionalProperties["currency"]
        }
    }
    return $Services
}
