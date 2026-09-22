# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Tests for Write-OutColumns.

    Write-OutColumns wraps the shared Out-Columns rendering helper for the
    HealthChecker writer pipeline. Table colorization is expressed by the
    analyzer as string IDs on the OutColumns.ColorizerIds property; the
    writer resolves those IDs through the local Get-HealthCheckerColorizer
    registry at render time.
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
            [string[]]$ColorizerIds
        )
        return [PSCustomObject]@{
            DisplayObject    = $DisplayObject
            SelectProperties = @("Name", "State")
            ColorizerIds     = $ColorizerIds
            IndentSpaces     = 0
        }
    }
}

Describe "Write-OutColumns" {

    BeforeEach {
        $Script:OutputFullPath = Join-Path -Path $TestDrive -ChildPath "Write-OutColumns.log"
        if (Test-Path -Path $Script:OutputFullPath) { Remove-Item -Path $Script:OutputFullPath -Force }
        $Script:CapturedColorizers = $null
    }

    Context "Null input" {

        It "Returns without touching the log file when OutColumns is null" {
            Write-OutColumns -OutColumns $null
            Test-Path -Path $Script:OutputFullPath | Should -BeFalse
        }
    }

    Context "ColorizerIds resolved from the local registry" {

        It "Resolves ColorizerIds to a real ScriptBlock array and passes it to Out-Columns" {
            $rows = @(New-DisplayObject -State "Started")
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerIds @("IisState")

            Mock Out-Columns {
                $Script:CapturedColorizers = $ColorizerFunctions
            }

            Write-OutColumns -OutColumns $outColumns

            Should -Invoke Out-Columns -Times 1 -Exactly
            $Script:CapturedColorizers | Should -Not -BeNullOrEmpty
            ($Script:CapturedColorizers -is [ScriptBlock[]]) | Should -BeTrue -Because "Out-Columns requires a [ScriptBlock[]] parameter"
            $Script:CapturedColorizers.Count | Should -Be 1

            # The resolved ScriptBlock came from the registry: it should map "Started" -> Green.
            $color = & $Script:CapturedColorizers[0] $rows[0] "State"
            $color | Should -Be "Green"
        }

        It "Resolves multiple ColorizerIds in the same order they were supplied" {
            $rows = @(New-DisplayObject -State "Started")
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerIds @("IisState", "IisAppPoolRestart")

            Mock Out-Columns {
                $Script:CapturedColorizers = $ColorizerFunctions
            }

            Write-OutColumns -OutColumns $outColumns

            ($Script:CapturedColorizers -is [ScriptBlock[]]) | Should -BeTrue
            $Script:CapturedColorizers.Count | Should -Be 2

            # Prove index 0 is IisState: it colors State=Started as Green.
            $iisRow = [PSCustomObject]@{ State = "Started"; RestartConditionSet = $true }
            (& $Script:CapturedColorizers[0] $iisRow "State") | Should -Be "Green" -Because "index 0 must be IisState"

            # Prove index 1 is IisAppPoolRestart: it colors RestartConditionSet=$true as Red.
            (& $Script:CapturedColorizers[1] $iisRow "RestartConditionSet") | Should -Be "Red" -Because "index 1 must be IisAppPoolRestart"
        }

        It "Renders without color when ColorizerIds is null" {
            $rows = @(New-DisplayObject -State "Started")
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerIds $null

            Mock Out-Columns {
                $Script:CapturedColorizers = $ColorizerFunctions
            }

            { Write-OutColumns -OutColumns $outColumns } | Should -Not -Throw
            Should -Invoke Out-Columns -Times 1 -Exactly
            $Script:CapturedColorizers | Should -BeNullOrEmpty
        }

        It "Leaves the source DisplayObject unmodified after rendering" {
            $rows = @(New-DisplayObject -State "Started")
            $originalState = $rows[0].State
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerIds @("IisState")

            Write-OutColumns -OutColumns $outColumns

            $rows[0].State | Should -Be $originalState
        }

        It "Get-HealthCheckerColorizer throws on an unknown ColorizerId" {
            {
                Get-HealthCheckerColorizer -ColorizerId "NotARegisteredColorizer"
            } | Should -Throw -ExpectedMessage "*Unknown HealthChecker colorizer ID*" -Because "unknown IDs must fail loudly at dev/test time so they cannot silently reach a customer environment"
        }

        It "Get-HealthCheckerColorizer returns a [ScriptBlock[]] for a single ColorizerId" {
            $result = Get-HealthCheckerColorizer -ColorizerId "IisState"
            ($result -is [ScriptBlock[]]) | Should -BeTrue -Because "Out-Columns and Add-AnalyzedResultInformation both bind [ScriptBlock[]] parameters, and the resolver's [OutputType] declares this contract"
            $result.Count | Should -Be 1
        }

        It "Get-HealthCheckerColorizer returns a [ScriptBlock[]] preserving supplied order for multiple ColorizerIds" {
            $result = Get-HealthCheckerColorizer -ColorizerId "IisState", "IisAppPoolRestart"
            ($result -is [ScriptBlock[]]) | Should -BeTrue
            $result.Count | Should -Be 2

            $row = [PSCustomObject]@{ State = "Started"; RestartConditionSet = $true }
            (& $result[0] $row "State") | Should -Be "Green"
            (& $result[1] $row "RestartConditionSet") | Should -Be "Red"
        }

        It "Write-OutColumns does not render the table when a ColorizerId is not registered" {
            $rows = @(New-DisplayObject -State "Started")
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerIds @("NotARegisteredColorizer")

            Mock Out-Columns { }

            # The outer catch inside Write-OutColumns swallows the resolver throw and logs it, so no exception escapes.
            { Write-OutColumns -OutColumns $outColumns } | Should -Not -Throw
            Should -Invoke Out-Columns -Times 0 -Exactly -Because "the table must not render with a partial/incorrect colorizer state"
        }

        It "Does not execute a code-shaped ColorizerId as PowerShell" {
            $rows = @(New-DisplayObject -State "Started")
            $Script:CanaryPwned = $false
            $malicious = '$Script:CanaryPwned = $true; "Red"'
            $outColumns = New-OutColumnsObject -DisplayObject $rows -ColorizerIds @($malicious)

            { Write-OutColumns -OutColumns $outColumns } | Should -Not -Throw
            $Script:CanaryPwned | Should -BeFalse
        }

        It "Resolves ColorizerIds after a PowerShell remoting round-trip (PSSerializer)" {
            $rows = @(New-DisplayObject -State "Started")
            $original = New-OutColumnsObject -DisplayObject $rows -ColorizerIds @("IisState")

            $xml = [System.Management.Automation.PSSerializer]::Serialize($original)
            $roundTripped = [System.Management.Automation.PSSerializer]::Deserialize($xml)

            $roundTripped.ColorizerIds[0] | Should -Be "IisState"
            $roundTripped.ColorizerIds[0].GetType().Name | Should -Be "String"

            Mock Out-Columns {
                $Script:CapturedColorizers = $ColorizerFunctions
            }

            Write-OutColumns -OutColumns $roundTripped

            $Script:CapturedColorizers | Should -Not -BeNullOrEmpty
            $Script:CapturedColorizers[0] | Should -BeOfType [ScriptBlock]
        }
    }
}
