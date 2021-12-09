# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

BeforeAll {
    $parent = Split-Path -Parent $PSScriptRoot
    $scriptName = "Get-ServerRebootPending.ps1"

    . "$parent\$scriptName"

    Function Get-SCCMRebootObject {
        $t = New-Object PSCustomObject
        $t | Add-Member -MemberType NoteProperty -Name "RebootPending" -Value $false
        $t | Add-Member -MemberType NoteProperty -Name "IsHardRebootPending" -Value $false
        return $t
    }
}

Describe "Testing Get-ServerRebootPending" {

    Context "Good Test with throws" {

        BeforeEach {
            Mock Get-ItemProperty { throw }
            Mock Invoke-CimMethod { return $false }
        }

        It "Get-ServerRebootPending reboot not pending" {
            Mock Test-Path { return $false }
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $false
        }

        It "Get-ServerRebootPending reboot is pending" {
            Mock Test-Path { return $true }
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $true
        }
    }

    Context "Good Test with throws - no mock on Test-Path" {

        It "Get-ServerRebootPending reboot not pending" {
            Mock Get-ItemProperty { throw }
            Mock Invoke-CimMethod { throw }
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $false
        }
    }


    Context "Full Test on Get-PendingSCCMReboot" {

        BeforeEach {
            Mock Get-ItemProperty { throw }
            Mock Test-Path { return $false }
            Mock Invoke-CimMethod { return $null }
        }

        It "Get-ServerRebootPending reboot not pending - CimMethod null" {
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $false
        }

        It "Get-ServerRebootPending reboot not pending - CimMethod both values set to false" {
            Mock Invoke-CimMethod { return Get-SCCMRebootObject }
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $false
        }

        It "Get-ServerRebootPending reboot pending - CimMethod RebootPending set to true" {
            Mock Invoke-CimMethod { $r = Get-SCCMRebootObject; $r.RebootPending = $true; return $r }
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $true
        }

        It "Get-ServerRebootPending reboot pending - CimMethod IsHardRebootPending set to true" {
            Mock Invoke-CimMethod { $r = Get-SCCMRebootObject; $r.IsHardRebootPending = $true; return $r }
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $true
        }
    }

    Context "Test out Get-PendingFileReboot" {

        BeforeEach {
            Mock Test-Path { return $false }
            Mock Invoke-CimMethod { return $null }
            Mock Get-ItemProperty { return $false }
        }

        It "Get-ServerRebootPending reboot not pending" {
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $false
        }

        It "Get-ServerRebootPending reboot pending" {
            Mock Get-ItemProperty { return $true }
            $results = Get-ServerRebootPending -ServerName $env:COMPUTERNAME
            $results.PendingReboot | Should -Be $true
        }
    }
}
