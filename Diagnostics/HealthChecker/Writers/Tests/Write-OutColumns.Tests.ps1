# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Tests for Write-OutColumns.

    Write-OutColumns wraps the shared Out-Columns rendering helper for the
    HealthChecker writer pipeline. Its OutColumns.ColorizerFunctions property
    can arrive as [ScriptBlock[]] from in-process callers, or as string[] when
    the OutColumns object has been through a PowerShell remoting round-trip
    that serialized the ScriptBlock bodies. Both shapes are covered here.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester scoped fixture variables')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test builders return objects only')]
[CmdletBinding()]
param()

BeforeAll {
    . $PSScriptRoot\..\Write-Functions.ps1

    # Stubs to avoid loading the HealthChecker logger module.
    function Write-LoggerInstance {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            $InputObject,
            [Parameter(Position = 0)]
            $Message
        )
        process { }
        end { return $InputObject }
    }
    $Script:Logger = [PSCustomObject]@{ Stub = $true }

    function New-DisplayObject {
        param(
            [string]$State,
            [string]$Name = "Row1"
        )
        return [PSCustomObject]@{
            Name  = $Name
            State = $State
        }
    }

    function New-OutColumnsObject {
        param(
            [object[]]$DisplayObject,
            [object[]]$ColorizerFunctions
        )
        return [PSCustomObject]@{
            DisplayObject      = $DisplayObject
            SelectProperties   = @("Name", "State")
            ColorizerFunctions = $ColorizerFunctions
            IndentSpaces       = 0
        }
    }
}

Describe "Write-OutColumns" {

    BeforeEach {
        $Script:OutputFullPath = Join-Path -Path $TestDrive -ChildPath "Write-OutColumns.log"
        if (Test-Path -Path $Script:OutputFullPath) { Remove-Item -Path $Script:OutputFullPath -Force }
        $Script:InvocationLog = New-Object 'System.Collections.Generic.List[string]'
    }

    Context "Null input" {

        It "Returns without touching the log file when OutColumns is null" {
            Write-OutColumns -OutColumns $null
            Test-Path -Path $Script:OutputFullPath | Should -BeFalse
        }
    }

    Context "In-process ScriptBlock ColorizerFunctions" {

        It "Invokes each colorizer once per row/property pair and writes the rendered text" {
            $rows = @(New-DisplayObject -State "Started"; New-DisplayObject -Name "Row2" -State "Stopped")
            $sbState = {
                param($o, $p)
                $Script:InvocationLog.Add("$p=$($o.$p)") | Out-Null
                if ($p -eq "State") {
                    if ($o.$p -eq "Started") { "Green" } else { "Red" }
                }
            }
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerFunctions @($sbState)

            Write-OutColumns -OutColumns $outColumns

            # 2 rows * 2 properties = 4 invocations.
            $Script:InvocationLog.Count | Should -Be 4
            $Script:InvocationLog | Should -Contain "State=Started"
            $Script:InvocationLog | Should -Contain "State=Stopped"

            Test-Path -Path $Script:OutputFullPath | Should -BeTrue
            $logContent = Get-Content -Path $Script:OutputFullPath -Raw
            $logContent | Should -Match "Started"
            $logContent | Should -Match "Stopped"
        }

        It "Renders without invoking any colorizer when ColorizerFunctions is null" {
            $rows = @(New-DisplayObject -State "Started")
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerFunctions $null

            Write-OutColumns -OutColumns $outColumns

            $Script:InvocationLog.Count | Should -Be 0
            Test-Path -Path $Script:OutputFullPath | Should -BeTrue
        }

        It "Leaves the source DisplayObject unmodified after rendering" {
            $rows = @(New-DisplayObject -State "Started")
            $originalState = $rows[0].State
            $sb = { param($o, $p) "Green" }
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerFunctions @($sb)

            Write-OutColumns -OutColumns $outColumns

            $rows[0].State | Should -Be $originalState
        }
    }

    Context "String-form ColorizerFunctions (post-remoting shape)" {

        It "PSSerializer round-trip converts ScriptBlock entries to strings" {
            $sb = { param($o, $p) if ($p -eq "State") { "Yellow" } }
            $original = New-OutColumnsObject -DisplayObject @(New-DisplayObject -State "Started") -ColorizerFunctions @($sb)

            $xml = [System.Management.Automation.PSSerializer]::Serialize($original)
            $roundTripped = [System.Management.Automation.PSSerializer]::Deserialize($xml)

            $roundTripped.ColorizerFunctions[0].GetType().Name | Should -Be "String"
            $roundTripped.ColorizerFunctions[0] | Should -Match "Yellow"
        }

        It "Rebuilds ScriptBlocks from string ColorizerFunctions and invokes them" {
            $rows = @(New-DisplayObject -State "Started")
            $colorizerBody = '$Script:InvocationLog.Add("STRING-BODY-INVOKED") | Out-Null; "Yellow"'
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerFunctions @($colorizerBody)

            Write-OutColumns -OutColumns $outColumns

            # 1 row * 2 properties = 2 invocations.
            $Script:InvocationLog | Should -Contain "STRING-BODY-INVOKED"
            $Script:InvocationLog.Count | Should -Be 2
        }

        It "Invokes ColorizerFunctions rebuilt from a PSSerializer round-trip" {
            $sb = {
                param($o, $p)
                $Script:InvocationLog.Add("ROUND-TRIP-INVOKED") | Out-Null
                if ($p -eq "State") { "Yellow" }
            }
            $original = New-OutColumnsObject -DisplayObject @(New-DisplayObject -State "Started") -ColorizerFunctions @($sb)

            $xml = [System.Management.Automation.PSSerializer]::Serialize($original)
            $roundTripped = [System.Management.Automation.PSSerializer]::Deserialize($xml)

            Write-OutColumns -OutColumns $roundTripped

            $Script:InvocationLog | Should -Contain "ROUND-TRIP-INVOKED"
        }
    }
}
