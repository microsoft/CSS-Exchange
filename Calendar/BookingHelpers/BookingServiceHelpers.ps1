# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-GraphBookingsServices {
    param(
        [Parameter(Mandatory = $true)]
        [string]$identity
    )
    $GraphBookingBusiness = Get-MgBookingBusinessService -BookingBusinessId $identity
    $MBStaff = Get-MgBookingBusinessStaffMember -BookingBusinessId $identity
    $Services = @()
    foreach ($service in $GraphBookingBusiness) {
        #determine serviceType
        $serviceType = ""
        if ($service.StaffMemberIds.Count -gt 1) {
            $serviceType = "N"
        } else {
            $serviceType = "1"
        }
        $serviceType+= ":"
        if ($service.MaximumAttendeesCount -gt 1) {
            $serviceType += "N"
        } else {
            $serviceType += "1"
        }
        #compose ServiceStaffIds
        $ServicestaffIds = ""
        foreach ($staffId in $service.StaffMemberIds) {
            $ServicestaffIds += $staffId + "`r`n"
        }
        $StaffName1 = ""
        $StaffName2 = ""
        $StaffName3 = ""
        $StaffName4 = ""
        $StaffName5 = ""
        for ($i = 0; $i -lt $service.StaffMemberIds.Count; $i++) {
            foreach ($StaffName in $MBStaff) {
                if ($StaffName.Id -eq $service.StaffMemberIds[$i]) {
                    switch ($i) {
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
            Id                    = $service.Id
            ServiceType           = $serviceType
            DisplayName           = $service.DisplayName
            Description           = $service.Description
            Duration              = $service.DefaultDuration
            PreBuffer             = $service.PreBuffer
            PostBuffer            = $service.PostBuffer
            SchedulingPolicy      = $service.SchedulingPolicy | ConvertTo-Json -Depth 10
            StaffMemberIds        = $ServicestaffIds
            StaffName1            = $StaffName1
            StaffName2            = $StaffName2
            StaffName3            = $StaffName3
            StaffName4            = $StaffName4
            StaffName5            = $StaffName5
            MaximumAttendeesCount = $service.MaximumAttendeesCount
            CustomQuestions       = $service.CustomQuestions | ConvertTo-Json -Depth 10
            DefaultReminders      = $service.DefaultReminders | ConvertTo-Json -Depth 10
            IsHiddenFromCustomers = $service.IsHiddenFromCustomers
            IsLocationOnline      = $service.IsLocationOnline
            DefaultLocation       = $service.DefaultLocation | ConvertTo-Json -Depth 10
            Notes                 = $service.Notes
            LanguageTag           = $service.LanguageTag
            CreatedDateTime       = $service.AdditionalProperties["createdDateTime"]
            LastUpdatedDateTime   = $service.AdditionalProperties["lastUpdatedDateTime"]
            Price                 = $service.AdditionalProperties["price"]
            Currency              = $service.AdditionalProperties["currency"]
        }
    }
    return $Services
}
