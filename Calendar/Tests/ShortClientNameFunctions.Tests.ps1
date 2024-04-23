# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param()

#Load the functions to be tested from ShortClientNameFunctions.ps1 file
   # . ".\$PSScriptRoot\CalLogHelpers\ShortClientNameFunctions.ps1"
    # . "D:\src\CSS-Exchange\Calendar\CalLogHelpers\ShortClientNameFunctions.Tests.ps1"
   #  Import-Module "$PSScriptRoot\CalLogHelpers\ShortClientNameFunctions.ps1"
   #  Import-Module  D:\src\CSS-Exchange\Calendar\CalLogHelpers\ShortClientNameFunctions.ps1

Describe "CreateShortClientName" {
    BeforeAll {
        . $PSScriptRoot\..\CalLogHelpers\ShortClientNameFunctions.ps1
    }

    Context "When ClientInfoString is empty" {
        It "Should return 'NotFound'" {
            $result = CreateShortClientName -ClientInfoString ""
            $result | Should -Be "NotFound"
        }
    }

    Context "When ClientInfoString is Client=MSExchangeRPC" {
        It "Should return 'Outlook : Desktop'" {
            $result = CreateShortClientName -ClientInfoString "Client=MSExchangeRPC"
            $result | Should -Be "Outlook : Desktop"
        }
    }

    Context "When ClientInfoString is Client=Hub Transport" {
        It "Should return 'Outlook : Desktop'" {
            $result = CreateShortClientName -ClientInfoString "Client=Hub Transport"
            $result | Should -Be "Transport"
        }
    }

    Context "When ClientInfoString is Client=OutlookService;Outlook-iOS/2.0;;Outlook-iOS/2.0" {
        It "Should return 'Outlook : Desktop'" {
            $result = CreateShortClientName -ClientInfoString "Client=OutlookService;Outlook-iOS/2.0;;Outlook-iOS/2.0"
            $result | Should -Be "OutlookiOS"
        }
    }

    Context "When ClientInfoString FileContentMatch 'Client=EBA' or 'Client=TBA'" {
        It "Should return 'ResourceBookingAssistant' if ClientInfoString FileContentMatch 'ResourceBookingAssistant'" {
            $result = CreateShortClientName "Client=EBA;Action=FreeBusyPublishingAssistant;ResourceBookingAssistant"
            $result | Should -Be "ResourceBookingAssistant"
        }

        It "Should return 'CalendarRepairAssistant' if ClientInfoString FileContentMatch 'CalendarRepairAssistant'" {
            $result = CreateShortClientName "Client=TBA;Service=MSExchangeMailboxAssistants;Action=CalendarRepairAssistant"
            $result | Should -Be "CalendarRepairAssistant"
        }

        It "Should return the concatenated client, action, and data if ClientInfoString does not contain 'ResourceBookingAssistant' or 'CalendarRepairAssistant'" {
            $result = CreateShortClientName "Client=EBA;Action=Delete;Data=789"
            $result | Should -Be "EBA:Delete;Data=789"
        }
    }

    Context "When ClientInfoString FileContentMatch 'Client=ActiveSync'" {
        It "Should return the user agent if ClientInfoString FileContentMatch 'UserAgent='" {
            $result = CreateShortClientName  "Client=ActiveSync;UserAgent=Apple-iPhone9C1/1402.100;Version=160;Action=/Microsoft-Server-ActiveSync/Proxy/default.eas?User=test@Contoso.com&DeviceId=LEDDJVC7GT7886JH9N4T9LR1Q0&DeviceType=iPhone&Cmd=Sync"
            $result | Should -Be "Apple-iPhone9C1"
        }

        It "Should return the user agent if ClientInfoString FileContentMatch 'UserAgent='" {
            $result = CreateShortClientName  "Client=ActiveSync;UserAgent=Android-14/;Action=/Microsoft-Server-ActiveSync/Proxy/default.eas"
            $result | Should -Be "Android-14"
        }

        It "Should return unknown if the user agent is Blank" {
            $result = CreateShortClientName "Client=ActiveSync;UserAgent=;Action=/Microsoft-Server-ActiveSync/default.eas?Cmd=SendMail"
            $result | Should -Be "ActiveSyncUnknown"
        }

        It "Should return 'Outlook-ModernCalendarSharing' if ClientInfoString FileContentMatch 'Outlook-iOS-Android'" {
            $result = CreateShortClientName "Client=ActiveSync;UserAgent=Outlook-iOS-Android/1.0;Action=/Microsoft-Server-ActiveSync/Proxy/default.eas?User=test%40microsoft.com&DeviceId=BF36923991ADFBA9&DeviceType=Outlook&Cmd=SendMail"
            $result | Should -Be "Outlook-ModernCalendarSharing"
        }

        It "Should return 'ActiveSyncUnknown' if ClientInfoString does not match any conditions" {
            $result = CreateShortClientName "Client=ActiveSync;UnknownClient"
            $result | Should -Be "ActiveSyncUnknown"
        }
    }

    Context "When ClientInfoString FileContentMatch 'Client=Rest'" {
        It "Should return 'LocationProcessor' if ClientInfoString FileContentMatch 'LocationAssistantProcessor'" {
            $result = CreateShortClientName "Client=Rest;LocationAssistantProcessor"
            $result | Should -Be "LocationProcessor"
        }

        It "Should return 'CalendarReplication' if ClientInfoString FileContentMatch 'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d'" {
            $result = CreateShortClientName "Client=Rest;AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d"
            $result | Should -Be "CalendarReplication"
        }

        It "Should return 'CiscoWebex' if ClientInfoString FileContentMatch 'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0'" {
            $result = CreateShortClientName "Client=Rest;AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0"
            $result | Should -Be "CiscoWebex"
        }

        It "Should return 'TimeService' if ClientInfoString FileContentMatch 'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f'" {
            $result = CreateShortClientName "Client=Rest;AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f"
            $result | Should -Be "TimeService"
        }

        It "Should return 'RestConnector' if ClientInfoString FileContentMatch 'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086'" {
            $result = CreateShortClientName "Client=Rest;AppId=48af08dc-f6d2-435f-b2a7-069abd99c086"
            $result | Should -Be "RestConnector"
        }

        It "Should return 'OutlookAndroid' if ClientInfoString FileContentMatch 'Client=OutlookService;Outlook-Android'" {
            $result = CreateShortClientName "Client=Rest;Client=OutlookService;Outlook-Android"
            $result | Should -Be "OutlookAndroid"
        }

        It "Should return 'GriffinRestClient' if ClientInfoString FileContentMatch 'GriffinRestClient'" {
            $result = CreateShortClientName "Client=Rest;GriffinRestClient"
            $result | Should -Be "GriffinRestClient"
        }

        It "Should return 'MacOutlookRest' if ClientInfoString FileContentMatch 'MacOutlook'" {
            $result = CreateShortClientName "Client=Rest;MacOutlook"
            $result | Should -Be "MacOutlookRest"
        }

        It "Should return 'Outlook-ModernCalendarSharing' if ClientInfoString FileContentMatch 'Microsoft Outlook 16'" {
            $result = CreateShortClientName "Client=Rest;Microsoft Outlook 16"
            $result | Should -Be "Outlook-ModernCalendarSharing"
        }

        It "Should return 'Teams' if ClientInfoString FileContentMatch 'SkypeSpaces'" {
            $result = CreateShortClientName "Client=Rest;SkypeSpaces"
            $result | Should -Be "Teams"
        }

        It "Should return 'Bookings B2 Service' if ClientInfoString FileContentMatch 'AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419'" {
            $result = CreateShortClientName "Client=Rest;AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419"
            $result | Should -Be "Bookings B2 Service"
        }

        It "Should return 'ELC-B2' if ClientInfoString FileContentMatch 'AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95'" {
            $result = CreateShortClientName "Client=Rest;AppId=bcad1a65-78eb-4725-9bce-ce1a8ed30b95"
            $result | Should -Be "ELC-B2"
        }
    }
}

Describe "FindMatch" {
    BeforeAll {
        . $PSScriptRoot\..\CalLogHelpers\ShortClientNameFunctions.ps1
    }

    Context 'Test FindMatch fuction' -ForEach @( 
        @{ KeyInput = 'Client=Hub Transport'; Expected = "Transport" },
        @{ KeyInput = 'Client=MSExchangeRPC'; Expected = "Outlook : Desktop" },
        @{ KeyInput = 'OneOutlook'; Expected = "OneOutlook" },
        @{ KeyInput = 'Lync for Mac'; Expected = "LyncMac"},
        @{ KeyInput = 'AppId=00000004-0000-0ff1-ce00-000000000000'; Expected = "SkypeMMS" },
        @{ KeyInput = 'MicrosoftNinja'; Expected = "Teams" },
        @{ KeyInput = 'SkypeSpaces'; Expected = "Teams" },
        @{ KeyInput = 'Remove-CalendarEvents'; Expected = "RemoveCalendarEvent" },
        @{ KeyInput = 'Client=POP3/IMAP4'; Expected = "PopImap" },
        @{ KeyInput = 'Client=OWA'; Expected = "OWA" },
        @{ KeyInput = 'PublishedBookingCalendar'; Expected = "BookingAgent" },
        @{ KeyInput = 'LocationAssistantProcessor'; Expected = "LocationProcessor" },
        @{ KeyInput = 'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d'; Expected = "CalendarReplication" },
        @{ KeyInput = 'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0'; Expected = "CiscoWebex" },
        @{ KeyInput = 'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f'; Expected = "Time Service" },
        @{ KeyInput = 'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086'; Expected = "RestConnector" },
        @{ KeyInput = 'AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419'; Expected = "Bookings B2 Service" },
        @{ KeyInput = 'GriffinRestClient'; Expected = "GriffinRestClient" },
        @{ KeyInput = 'MacOutlook'; Expected = "MacOutlookRest" },
        @{ KeyInput = 'Outlook-iOS-Android'; Expected = "OutlookMobile" },
        @{ KeyInput = 'Client=OutlookService;Outlook-Android'; Expected = "OutlookAndroid" },
        @{ KeyInput = 'Client=OutlookService;Outlook-iOS'; Expected = "OutlookiOS" }
        
    ) {
        It 'Should return the expected value' {
            $result = FindMatch -KeyInput $KeyInput
            $result | Should -Be $Expected

        }
    }
}
