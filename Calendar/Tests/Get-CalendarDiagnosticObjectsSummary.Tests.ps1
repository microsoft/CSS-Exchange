# Load the function from Get-CalendarDiagnosticObjectSummary.ps1
#. "/d:/src/CSS-Exchange/Calendar/Get-CalendarDiagnosticObjectSummary.ps1"

Describe "CreateShortClientName" {
    Context "When LogClientInfoString is empty" {
        It "Should return 'NotFound'" {
            $result = CreateShortClientName ""
            $result | Should Be "NotFound"
        }
    }

    Context "When LogClientInfoString contains 'Client=EBA' or 'Client=TBA'" {
        It "Should return 'ResourceBookingAssistant' if LogClientInfoString contains 'ResourceBookingAssistant'" {
            $result = CreateShortClientName "Client=EBA;Action=Create;Data=123;ResourceBookingAssistant"
            $result | Should Be "ResourceBookingAssistant"
        }

        It "Should return 'CalendarRepairAssistant' if LogClientInfoString contains 'CalendarRepairAssistant'" {
            $result = CreateShortClientName "Client=TBA;Action=Update;Data=456;CalendarRepairAssistant"
            $result | Should Be "CalendarRepairAssistant"
        }

        It "Should return the concatenated client, action, and data if LogClientInfoString does not contain 'ResourceBookingAssistant' or 'CalendarRepairAssistant'" {
            $result = CreateShortClientName "Client=EBA;Action=Delete;Data=789"
            $result | Should Be "EBA:Delete;789"
        }
    }

    Context "When LogClientInfoString contains 'Client=ActiveSync'" {
        It "Should return the user agent if LogClientInfoString contains 'UserAgent='" {
            $result = CreateShortClientName "Client=ActiveSync;UserAgent=Outlook-iOS-Android/2.0"
            $result | Should Be "Outlook-iOS-Android"
        }

        It "Should return 'OutlookMobile' if LogClientInfoString contains 'Outlook-iOS-Android'" {
            $result = CreateShortClientName "Client=ActiveSync;Outlook-iOS-Android"
            $result | Should Be "OutlookMobile"
        }

        It "Should return 'Outlook-iOS' if LogClientInfoString contains 'Outlook-iOS'" {
            $result = CreateShortClientName "Client=REST;;;Client=REST;InternalCalendarSharing (Client=OutlookService;Outlook-iOS/2.0;)[AppId=1c06531d-b56d-4cfb-8ad0-53c87d70093e];"
            $result | Should Be "Outlook-iOS"
        }

        It "Should return 'ActiveSyncUnknown' if LogClientInfoString does not match any conditions" {
            $result = CreateShortClientName "Client=ActiveSync;UnknownClient"
            $result | Should Be "ActiveSyncUnknown"
        }
    }

    Context "When LogClientInfoString contains 'Client=Rest'" {
        It "Should return 'LocationProcessor' if LogClientInfoString contains 'LocationAssistantProcessor'" {
            $result = CreateShortClientName "Client=Rest;LocationAssistantProcessor"
            $result | Should Be "LocationProcessor"
        }

        It "Should return 'CalendarReplication' if LogClientInfoString contains 'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d'" {
            $result = CreateShortClientName "Client=Rest;AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d"
            $result | Should Be "CalendarReplication"
        }

        It "Should return 'CiscoWebex' if LogClientInfoString contains 'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0'" {
            $result = CreateShortClientName "Client=Rest;AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0"
            $result | Should Be "CiscoWebex"
        }

        It "Should return 'TimeService' if LogClientInfoString contains 'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f'" {
            $result = CreateShortClientName "Client=Rest;AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f"
            $result | Should Be "TimeService"
        }

        It "Should return 'RestConnector' if LogClientInfoString contains 'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086'" {
            $result = CreateShortClientName "Client=Rest;AppId=48af08dc-f6d2-435f-b2a7-069abd99c086"
            $result | Should Be "RestConnector"
        }

        It "Should return 'OutlookAndroid' if LogClientInfoString contains 'Client=OutlookService;Outlook-Android'" {
            $result = CreateShortClientName "Client=Rest;Client=OutlookService;Outlook-Android"
            $result | Should Be "OutlookAndroid"
        }

        It "Should return 'GriffinRestClient' if LogClientInfoString contains 'GriffinRestClient'" {
            $result = CreateShortClientName "Client=Rest;GriffinRestClient"
            $result | Should Be "GriffinRestClient"
        }

        It "Should return 'MacOutlookRest' if LogClientInfoString contains 'MacOutlook'" {
            $result = CreateShortClientName "Client=Rest;MacOutlook"
            $result | Should Be "MacOutlookRest"
        }

        It "Should return 'Outlook-ModernCalendarSharing' if LogClientInfoString contains 'Microsoft Outlook 16'" {
            $result = CreateShortClientName "Client=Rest;Microsoft Outlook 16"
            $result | Should Be "Outlook-ModernCalendarSharing"
        }

        It "Should return 'Teams' if LogClientInfoString contains 'SkypeSpaces'" {
            $result = CreateShortClientName "Client=Rest;SkypeSpaces"
            $result | Should Be "Teams"
        }

        It "Should return 'Bookings B2 Service' if LogClientInfoString contains 'AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419'" {
            $result = CreateShortClientName "Client=Rest;AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419"
            $result | Should Be "Bookings B2 Service"
        }

        It "Should return 'ELC-B2' if LogClientInfoString contains 'AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95'" {
            $result = CreateShortClientName "Client=Rest;AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95"
            $result | Should Be "ELC-B2"
        }
    }
}

Describe "CreateShortClientName" {
    Context "When LogClientInfoString is empty" {
        It "Should return 'NotFound'" {
            $result = CreateShortClientName ""
            $result | Should Be "NotFound"
        }
    }

    Context "When LogClientInfoString contains 'Client=EBA' or 'Client=TBA'" {
        It "Should return 'ResourceBookingAssistant' if LogClientInfoString contains 'ResourceBookingAssistant'" {
            $result = CreateShortClientName "Client=EBA;Action=Create;Data=123;ResourceBookingAssistant"
            $result | Should Be "ResourceBookingAssistant"
        }

        It "Should return 'CalendarRepairAssistant' if LogClientInfoString contains 'CalendarRepairAssistant'" {
            $result = CreateShortClientName "Client=TBA;Action=Update;Data=456;CalendarRepairAssistant"
            $result | Should Be "CalendarRepairAssistant"
        }

        It "Should return the concatenated client, action, and data if LogClientInfoString does not contain 'ResourceBookingAssistant' or 'CalendarRepairAssistant'" {
            $result = CreateShortClientName "Client=EBA;Action=Delete;Data=789"
            $result | Should Be "EBA:Delete;789"
        }
    }

    Context "When LogClientInfoString contains 'Client=ActiveSync'" {
        It "Should return the user agent if LogClientInfoString contains 'UserAgent='" {
            $result = CreateShortClientName "Client=ActiveSync;UserAgent=Outlook-iOS-Android/2.0"
            $result | Should Be "Outlook-iOS-Android"
        }

        It "Should return 'OutlookMobile' if LogClientInfoString contains 'Outlook-iOS-Android'" {
            $result = CreateShortClientName "Client=ActiveSync;Outlook-iOS-Android"
            $result | Should Be "OutlookMobile"
        }

        It "Should return 'ActiveSyncUnknown' if LogClientInfoString does not match any conditions" {
            $result = CreateShortClientName "Client=ActiveSync;UnknownClient"
            $result | Should Be "ActiveSyncUnknown"
        }
    }

    Context "When LogClientInfoString contains 'Client=Rest'" {
        It "Should return 'LocationProcessor' if LogClientInfoString contains 'LocationAssistantProcessor'" {
            $result = CreateShortClientName "Client=Rest;LocationAssistantProcessor"
            $result | Should Be "LocationProcessor"
        }

        It "Should return 'CalendarReplication' if LogClientInfoString contains 'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d'" {
            $result = CreateShortClientName "Client=Rest;AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d"
            $result | Should Be "CalendarReplication"
        }

        It "Should return 'CiscoWebex' if LogClientInfoString contains 'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0'" {
            $result = CreateShortClientName "Client=Rest;AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0"
            $result | Should Be "CiscoWebex"
        }

        It "Should return 'TimeService' if LogClientInfoString contains 'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f'" {
            $result = CreateShortClientName "Client=Rest;AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f"
            $result | Should Be "TimeService"
        }

        It "Should return 'RestConnector' if LogClientInfoString contains 'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086'" {
            $result = CreateShortClientName "Client=Rest;AppId=48af08dc-f6d2-435f-b2a7-069abd99c086"
            $result | Should Be "RestConnector"
        }

        It "Should return 'OutlookAndroid' if LogClientInfoString contains 'Client=OutlookService;Outlook-Android'" {
            $result = CreateShortClientName "Client=Rest;Client=OutlookService;Outlook-Android"
            $result | Should Be "OutlookAndroid"
        }

        It "Should return 'GriffinRestClient' if LogClientInfoString contains 'GriffinRestClient'" {
            $result = CreateShortClientName "Client=Rest;GriffinRestClient"
            $result | Should Be "GriffinRestClient"
        }

        It "Should return 'MacOutlookRest' if LogClientInfoString contains 'MacOutlook'" {
            $result = CreateShortClientName "Client=Rest;MacOutlook"
            $result | Should Be "MacOutlookRest"
        }

        It "Should return 'Outlook-ModernCalendarSharing' if LogClientInfoString contains 'Microsoft Outlook 16'" {
            $result = CreateShortClientName "Client=Rest;Microsoft Outlook 16"
            $result | Should Be "Outlook-ModernCalendarSharing"
        }

        It "Should return 'Teams' if LogClientInfoString contains 'SkypeSpaces'" {
            $result = CreateShortClientName "Client=Rest;SkypeSpaces"
            $result | Should Be "Teams"
        }

        It "Should return 'Bookings B2 Service' if LogClientInfoString contains 'AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419'" {
            $result = CreateShortClientName "Client=Rest;AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419"
            $result | Should Be "Bookings B2 Service"
        }

        It "Should return 'ELC-B2' if LogClientInfoString contains 'AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95'" {
            $result = CreateShortClientName "Client=Rest;AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95"
            $result | Should Be "ELC-B2"
        }

        It "Should return 'RestUnknown' if LogClientInfoString contains 'NoUserAgent'" {
            $result = CreateShortClientName "Client=Rest;NoUserAgent"
            $result | Should Be "RestUnknown"
        }

        It "Should return '[Unknown Rest Client]' if LogClientInfoString does not match any conditions" {
            $result = CreateShortClientName "Client=Rest;UnknownClient"
            $result | Should Be "[Unknown Rest Client]"
        }
    }

    Context "When LogClientInfoString contains 'Client=WebServices'" {
        It "Should return 'ZoomPresence' if LogClientInfoString contains 'ZoomPresence'" {
            $result = CreateShortClientName "Client=WebServices;ZoomPresence"
            $result | Should Be "ZoomPresence"
        }

        It "Should return 'Unknown EWS App' if LogClientInfoString does not contain 'ZoomPresence'" {
            $result = CreateShortClientName "Client=WebServices;UnknownClient"
            $result | Should Be "Unknown EWS App"
        }
    }

    Context "When LogClientInfoString contains 'InternalCalendarSharing' and 'OWA' but not 'OneOutlook'" {
        It "Should return 'Owa-ModernCalendarSharing'" {
            $result = CreateShortClientName "Client=InternalCalendarSharing;OWA"
            $result | Should Be "Owa-ModernCalendarSharing"
        }
    }

    Context "When LogClientInfoString contains 'InternalCalendarSharing' and 'MacOutlook'" {
        It "Should return 'MacOutlook-ModernCalendarSharing'" {
            $result = CreateShortClientName "Client=InternalCalendarSharing;MacOutlook"
            $result | Should Be "MacOutlook-ModernCalendarSharing"
        }
    }

    Context "When LogClientInfoString contains 'InternalCalendarSharing' and 'Outlook'" {
        It "Should return 'Outlook-ModernCalendarSharing'" {
            $result = CreateShortClientName "Client=InternalCalendarSharing;Outlook"
            $result | Should Be "Outlook-ModernCalendarSharing"
        }
    }

    Context "When LogClientInfoString contains 'Client=ActiveSync' and 'Outlook'" {
        It "Should return 'Outlook-ModernCalendarSharing'" {
            $result = CreateShortClientName "Client=ActiveSync;Outlook"
            $result | Should Be "Outlook-ModernCalendarSharing"
        }
    }

    Context "When LogClientInfoString contains 'OneOutlook'" {
        It "Should return 'NewOutlook'" {
            $result = CreateShortClientName "Client=Rest;OneOutlook"
            $result | Should Be "NewOutlook"
        }
    }

    Context "When no conditions match" {
        It "Should return '[NoShortNameFound]'" {
            $result = CreateShortClientName "Client=Unknown"
            $result | Should Be "[NoShortNameFound]"
        }
    }
}
```