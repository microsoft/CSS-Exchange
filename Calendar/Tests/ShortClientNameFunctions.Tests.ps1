# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

Describe "CreateShortClientName" {
    BeforeAll {
        . $PSScriptRoot\..\CalLogHelpers\ShortClientNameFunctions.ps1
    }

    Context "When LogClientInfoString is empty" {
        It "Should return 'NotFound'" {
            $result = CreateShortClientName -LogClientInfoString ""
            $result | Should -Be "NotFound"
        }
    }

    Context "When LogClientInfoString is Client=MSExchangeRPC" {
        It "Should return 'Outlook : Desktop : MAPI'" {
            $result = CreateShortClientName -LogClientInfoString "Client=MSExchangeRPC"
            $result | Should -Be "Outlook : Desktop : MAPI"
        }
    }

    Context "When LogClientInfoString is Client=WebServices;Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro);;Client=WebServices;ExchangeServicesClient/0.9.248.0;" {
        It "Should return 'Outlook : Desktop : MAPI' if LogClientInfoString FileContentMatch 'AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95'" {
            $result = CreateShortClientName "Client=WebServices;Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro);;Client=WebServices;ExchangeServicesClient/0.9.248.0;"
            $result | Should -Be "Outlook : Desktop"
        }
    }

    Context "When LogClientInfoString is Client=Hub Transport" {
        It "Should return 'Transport'" {
            $result = CreateShortClientName -LogClientInfoString "Client=Hub Transport"
            $result | Should -Be "Transport"
        }
    }

    Context "When LogClientInfoString is Client=OutlookService;Outlook-iOS/2.0;;Outlook-iOS/2.0" {
        It "Should return 'OutlookiOS'" {
            $result = CreateShortClientName -LogClientInfoString "Client=OutlookService;Outlook-iOS/2.0;;Outlook-iOS/2.0"
            $result | Should -Be "OutlookiOS"
        }
    }

    Context "When LogClientInfoString is Client=REST;;;Client=REST;InternalCalendarSharing (Client=OutlookService;Outlook-iOS/2.0;)[AppId=1c06531d-b56d-4cfb-8ad0-53c87d70093e];" {
        It "Should return 'OutlookiOS'" {
            $result = CreateShortClientName -LogClientInfoString "Client=REST;;;Client=REST;InternalCalendarSharing (Client=OutlookService;Outlook-iOS/2.0;)[AppId=1c06531d-b56d-4cfb-8ad0-53c87d70093e];"
            $result | Should -Be "OutlookiOS"
        }
    }
    Context "When LogClientInfoString FileContentMatch 'Client=EBA' or 'Client=TBA'" {
        It "Should return 'ResourceBookingAssistant' if LogClientInfoString FileContentMatch 'ResourceBookingAssistant'" {
            $result = CreateShortClientName "Client=EBA;Action=FreeBusyPublishingAssistant;ResourceBookingAssistant"
            $result | Should -Be "ResourceBookingAssistant"
        }

        It "Should return 'CalendarRepairAssistant' if LogClientInfoString FileContentMatch 'CalendarRepairAssistant'" {
            $result = CreateShortClientName "Client=TBA;Service=MSExchangeMailboxAssistants;Action=CalendarRepairAssistant"
            $result | Should -Be "CalendarRepairAssistant"
        }

        It "Should return the concatenated client, action, and data if LogClientInfoString does not contain 'ResourceBookingAssistant' or 'CalendarRepairAssistant'" {
            $result = CreateShortClientName "Client=EBA;Action=Delete;Data=789"
            $result | Should -Be "Other EBA"
        }
    }

    Context "When LogClientInfoString FileContentMatch 'Client=ActiveSync'" {
        It "Should return the user agent if LogClientInfoString FileContentMatch 'UserAgent='" {
            $result = CreateShortClientName  "Client=ActiveSync;UserAgent=Apple-iPhone9C1/1402.100;Version=160;Action=/Microsoft-Server-ActiveSync/Proxy/default.eas?User=test@Contoso.com&DeviceId=MyTestDevice&DeviceType=iPhone&Cmd=Sync"
            $result | Should -Be "Apple-iPhone9C1"
        }

        It "Should return the user agent if LogClientInfoString FileContentMatch 'UserAgent='" {
            $result = CreateShortClientName  "Client=ActiveSync;UserAgent=Android-14/;Action=/Microsoft-Server-ActiveSync/Proxy/default.eas"
            $result | Should -Be "Android-14"
        }

        It "Should return unknown if the user agent is Blank" {
            $result = CreateShortClientName "Client=ActiveSync;UserAgent=;Action=/Microsoft-Server-ActiveSync/default.eas?Cmd=SendMail"
            $result | Should -Be "ActiveSyncUnknown"
        }

        It "Should return 'Outlook : ActiveSync' if LogClientInfoString FileContentMatch 'Outlook-iOS-Android'" {
            $result = CreateShortClientName "Client=ActiveSync;UserAgent=Outlook-iOS-Android/1.0;Action=/Microsoft-Server-ActiveSync/Proxy/default.eas?User=test%40microsoft.com&DeviceId=BF36923991ADFBA9&DeviceType=Outlook&Cmd=SendMail"
            $result | Should -Be "Outlook : ActiveSync"
        }

        It "Should return 'ActiveSyncUnknown' if LogClientInfoString does not match any conditions" {
            $result = CreateShortClientName "Client=ActiveSync;UnknownClient"
            $result | Should -Be "ActiveSyncUnknown"
        }
    }

    Context "When LogClientInfoString FileContentMatch 'Client=Rest'" {
        It "Should return 'LocationProcessor' if LogClientInfoString FileContentMatch 'LocationAssistantProcessor'" {
            $result = CreateShortClientName "Client=Rest;LocationAssistantProcessor"
            $result | Should -Be "LocationProcessor"
        }

        It "Should return 'CalendarReplication' if LogClientInfoString FileContentMatch 'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d'" {
            $result = CreateShortClientName "Client=Rest;AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d"
            $result | Should -Be "CalendarReplication"
        }

        It "Should return 'CiscoWebex' if LogClientInfoString FileContentMatch 'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0'" {
            $result = CreateShortClientName "Client=Rest;AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0"
            $result | Should -Be "CiscoWebex"
        }

        It "Should return 'TimeService' if LogClientInfoString FileContentMatch 'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f'" {
            $result = CreateShortClientName "Client=Rest;AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f"
            $result | Should -Be "TimeService"
        }

        It "Should return 'RestConnector' if LogClientInfoString FileContentMatch 'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086'" {
            $result = CreateShortClientName "Client=Rest;AppId=48af08dc-f6d2-435f-b2a7-069abd99c086"
            $result | Should -Be "RestConnector"
        }

        It "Should return 'Teams' if LogClientInfoString FileContentMatch 'MicrosoftNinja'" {
            $result = CreateShortClientName "Client=WebServices;MicrosoftNinja/1.0 Teams/1.0 (ExchangeServicesClient/1.0.0.0) SkypeSpaces/1.0a$*+;"
            $result | Should -Be "Teams"
        }

        It "Should return 'OutlookAndroid' if LogClientInfoString FileContentMatch 'Client=OutlookService;Outlook-Android'" {
            $result = CreateShortClientName "Client=Rest;Client=OutlookService;Outlook-Android"
            $result | Should -Be "OutlookAndroid"
        }

        It "Should return 'GriffinRestClient' if LogClientInfoString FileContentMatch 'GriffinRestClient'" {
            $result = CreateShortClientName "Client=Rest;GriffinRestClient"
            $result | Should -Be "GriffinRestClient"
        }

        It "Should return 'MacOutlookRest' if LogClientInfoString FileContentMatch 'MacOutlook'" {
            $result = CreateShortClientName "Client=Rest;MacOutlook"
            $result | Should -Be "MacOutlookRest"
        }

        It "Should return 'Outlook-ModernCalendarSharing' if LogClientInfoString FileContentMatch 'Microsoft Outlook 16'" {
            $result = CreateShortClientName "Client=Rest;Microsoft Outlook 16"
            $result | Should -Be "Outlook-ModernCalendarSharing"
        }

        It "Should return 'Teams' if LogClientInfoString FileContentMatch 'SkypeSpaces'" {
            $result = CreateShortClientName "Client=Rest;SkypeSpaces"
            $result | Should -Be "Teams"
        }

        It "Should return 'Bookings B2 Service' if LogClientInfoString FileContentMatch 'AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419'" {
            $result = CreateShortClientName "Client=Rest;AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419"
            $result | Should -Be "Bookings B2 Service"
        }

        It "Should return 'ELC-B2' if LogClientInfoString FileContentMatch 'AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95'" {
            $result = CreateShortClientName "Client=Rest;AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95"
            $result | Should -Be "ELC-B2"
        }
    }
}

Describe "CreateShortClientName-FindMatch" {
    BeforeAll {
        . $PSScriptRoot\..\CalLogHelpers\ShortClientNameFunctions.ps1
    }

    Context 'Test CreateShortClientName focusing on the FindMatch function' -ForEach @(
        @{ LogClientInfoString = 'Client=Hub Transport'; Expected = "Transport" },
        @{ LogClientInfoString = 'Client=MSExchangeRPC'; Expected = "Outlook : Desktop : MAPI" },
        @{ LogClientInfoString = 'OneOutlook'; Expected = "OneOutlook" },
        @{ LogClientInfoString = 'Lync for Mac'; Expected = "LyncMac" },
        @{ LogClientInfoString = 'AppId=00000004-0000-0ff1-ce00-000000000000'; Expected = "SkypeMMS" },
        @{ LogClientInfoString = 'MicrosoftNinja'; Expected = "Teams" },
        @{ LogClientInfoString = 'SkypeSpaces'; Expected = "Teams" },
        @{ LogClientInfoString = 'Remove-CalendarEvents'; Expected = "RemoveCalendarEvent" },
        @{ LogClientInfoString = 'Client=POP3/IMAP4'; Expected = "PopImap" },
        @{ LogClientInfoString = 'Client=OWA'; Expected = "OWA" },
        @{ LogClientInfoString = 'PublishedBookingCalendar'; Expected = "BookingAgent" },
        @{ LogClientInfoString = 'LocationAssistantProcessor'; Expected = "LocationProcessor" },
        @{ LogClientInfoString = 'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d'; Expected = "CalendarReplication" },
        @{ LogClientInfoString = 'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0'; Expected = "CiscoWebex" },
        @{ LogClientInfoString = 'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f'; Expected = "Time Service" },
        @{ LogClientInfoString = 'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086'; Expected = "RestConnector" },
        @{ LogClientInfoString = 'AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419'; Expected = "Bookings B2 Service" },
        @{ LogClientInfoString = 'GriffinRestClient'; Expected = "GriffinRestClient" },
        @{ LogClientInfoString = 'MacOutlook'; Expected = "MacOutlookRest" },
        @{ LogClientInfoString = 'Outlook-iOS-Android'; Expected = "OutlookMobile" },
        @{ LogClientInfoString = 'Client=WebServices;Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro);;Client=WebServices;ExchangeServicesClient/0.9.248.0;;'; Expected = "Outlook : Desktop" },
        @{ LogClientInfoString = 'Client=OutlookService;Outlook-Android'; Expected = "OutlookAndroid" },
        @{ LogClientInfoString = 'Client=REST;;;Client=REST;InternalCalendarSharing (Client=OutlookService;Outlook-Android/2.0;)[AppId=1c06531d-b56d-4cfb-8ad0-53c87d70093e];'; Expected = "OutlookAndroid" },
        @{ LogClientInfoString = 'Client=OutlookService;Outlook-iOS'; Expected = "OutlookiOS" }

    ) {
        It 'Should return the expected value' {
            $result = CreateShortClientName -LogClientInfoString $LogClientInfoString
            $result | Should -Be $Expected
        }
    }
}
