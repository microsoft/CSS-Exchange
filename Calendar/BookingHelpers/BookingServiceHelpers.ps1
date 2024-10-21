# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-GraphBookingsServices {
    param(
        [Parameter(Mandatory = $true)]
        [string]$identity
    )
    $GraphBookingBusiness = Get-MgBookingBusinessService -BookingBusinessId $identity
    $MBStaff = Get-MgBookingBusinessStaffMember -BookingBusinessId $identity
    $services = @()
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
        $serviceStaffIds = ""
        foreach ($staffId in $service.StaffMemberIds) {
            $serviceStaffIds += $staffId + "`r`n"
        }
        $staffName1 = ""
        $staffName2 = ""
        $staffName3 = ""
        $staffName4 = ""
        $staffName5 = ""
        for ($i = 0; $i -lt $service.StaffMemberIds.Count; $i++) {
            foreach ($staffName in $MBStaff) {
                if ($staffName.Id -eq $service.StaffMemberIds[$i]) {
                    switch ($i) {
                        0 { $staffName1 = $staffName.AdditionalProperties["displayName"] }
                        1 { $staffName2 = $staffName.AdditionalProperties["displayName"] }
                        2 { $staffName3 = $staffName.AdditionalProperties["displayName"] }
                        3 { $staffName4 = $staffName.AdditionalProperties["displayName"] }
                        4 { $staffName5 = $staffName.AdditionalProperties["displayName"] }
                    }
                }
            }
        }

        $services += [PSCustomObject]@{
            Id                    = $service.Id
            ServiceType           = $serviceType
            DisplayName           = $service.DisplayName
            Description           = $service.Description
            Duration              = $service.DefaultDuration
            PreBuffer             = $service.PreBuffer
            PostBuffer            = $service.PostBuffer
            SchedulingPolicy      = $service.SchedulingPolicy | ConvertTo-Json -Depth 10
            StaffMemberIds        = $serviceStaffIds
            StaffName1            = $staffName1
            StaffName2            = $staffName2
            StaffName3            = $staffName3
            StaffName4            = $staffName4
            StaffName5            = $staffName5
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
    return $services
}
