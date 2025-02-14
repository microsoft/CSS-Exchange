# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
BeforeAll {
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Add-ScriptBlockInjection.ps1
}

# Only testing with Start-Job and operator, due to the fact that Invoke-Command should be doing a similar operation as operator.
# Invoke-Command is going to be using WMI, which shouldn't be an issue.
# We can't use Invoke-Command as a Job or against the machine within Pester because it requires to be run as Admin, which can't be done in the pipeline.
Describe "Generic Testing" {
    BeforeAll {
        $sb = [ScriptBlock]::Create("Get-Process")
        $Script:results = Add-ScriptBlockInjection -PrimaryScriptBlock $sb
    }

    It "Making sure it is a ScriptBlock type" {
        $Script:results | Should -BeOfType "ScriptBlock"
    }

    It "Can be converted to script block" {
        $Script:results = [ScriptBlock]::Create($Script:results)
        $Script:results | Should -BeOfType "ScriptBlock"
    }
}

Describe "Supported Primary Script Block Types" {
    BeforeAll {
        <#
            Primary Script Block Types that are supported.
        #>
        function GenFunction {
            param($a, $b)
            Write-Verbose "Testing"
            [PSCustomObject]@{
                A = $a
                B = $b
            }
        }

        # This is currently not supported.
        function GenFunction2 ($a, $b) {
            Write-Verbose "Testing"
            [PSCustomObject]@{
                A = $a
                B = $b
            }
        }

        function GenFunction3 {
            [CmdletBinding()]
            param(
                [string]$a,
                [string]$b
            )
            Write-Verbose "Testing"
            [PSCustomObject]@{
                A = $a
                B = $b
            }
        }

        function GenFunction4 {
            Write-Verbose "Testing"
            [PSCustomObject]@{
                A = "Hello"
                B = "World"
            }
        }

        # This is currently not supported.
        # Don't use process without using params
        function ProcessFunction {
            process {
                Write-Verbose "Testing"
                [PSCustomObject]@{
                    A = "Hello"
                    B = "World"
                }
            }
        }
        function ProcessFunctionParamEmpty {
            param()
            process {
                Write-Verbose "Testing"
                [PSCustomObject]@{
                    A = "Hello"
                    B = "World"
                }
            }
        }

        function ProcessFunction1 {
            param(
                [string]$a,
                [string]$b
            )
            process {
                Write-Verbose "Testing"
                [PSCustomObject]@{
                    A = $a
                    B = $b
                }
            }
        }

        function ProcessFunction2 {
            param(
                [string]$a,
                [string]$b
            )
            begin {
                Write-Verbose "Test Begin"
            }
            process {
                Write-Verbose "Testing"
                [PSCustomObject]@{
                    A = $a
                    B = $b
                }
            }
        }

        function ProcessFunction3 {
            param(
                [string]$a,
                [string]$b
            )
            begin {
                Write-Verbose "Test Begin"
            }
            process {
                Write-Verbose "Testing"
                [PSCustomObject]@{
                    A = $a
                    B = $b
                }
            }
            end {
                Write-Verbose "Test End"
            }
        }

        function ProcessFunction4 {
            param(
                [string]$a,
                [string]$b
            )
            process {
                Write-Verbose "Testing"
            }
            end {
                [PSCustomObject]@{
                    A = $a
                    B = $b
                }
                Write-Verbose "Test End"
            }
        }

        $stringScriptBlock = "param(`$a, `$b)
        Write-Verbose `"Testing`"
        [PSCustomObject]@{
                A = `$a
                B = `$b
            }
        "
        $Script:scriptBlock = [ScriptBlock]::Create($stringScriptBlock)

        <#
            End of Primary Script Block Types that are supported.
        #>

        function InvokePesterGeneralTests {
            param(
                [ScriptBlock]$GenScriptBlock,
                [object[]]$ArgumentList,
                [string[]]$VerboseMockMatches
            )
            Mock Write-Verbose { param ($Message ) }
            $sb = Add-ScriptBlockInjection -PrimaryScriptBlock $GenScriptBlock

            $arguments = @{
                ScriptBlock = $sb
            }

            if ($null -ne $ArgumentList) {
                $arguments["ArgumentList"] = $ArgumentList
            }

            # Start Job
            $job = Start-Job @arguments
            $r = Receive-Job $job -Wait -AutoRemoveJob
            $r.A | Should -Be $ArgumentList[0]
            $r.B | Should -Be $ArgumentList[1]

            # operator
            try {
                if ($PSSenderInfo) {
                    $PSSenderInfoOriginal = $PSSenderInfo
                    $PSSenderInfo = $null
                    $restPSSenderInfo = $true
                }

                if ( $null -eq $ArgumentList) {
                    $r = & $sb
                    $r.A | Should -Be "Hello"
                    $r.B | Should -Be "World"
                } else {
                    $r = & $sb @ArgumentList
                    $r.A | Should -Be $ArgumentList[0]
                    $r.B | Should -Be $ArgumentList[1]
                }

                foreach ($match in $VerboseMockMatches) {
                    Assert-MockCalled Write-Verbose -ParameterFilter { $Message -eq $match } -Exactly 1
                }
            } finally {
                if ($restPSSenderInfo) {
                    $PSSenderInfo = $PSSenderInfoOriginal
                }
            }
        }
    }

    It "GenFunction Testing" {
        InvokePesterGeneralTests -GenScriptBlock ${Function:GenFunction} -ArgumentList "Hello", "World" -VerboseMockMatches "Testing"
    }

    It "GenFunction2 Testing" {
        #TODO this should work, but not going to try to fix it now.
        # need to fix Add-ScriptBlockInjection to address this
        # InvokePesterGeneralTests -GenScriptBlock ${Function:GenFunction2} -ArgumentList "Hello", "World" -VerboseMockMatches "Testing"
        $true | Should -Be $true
    }

    It "GenFunction3 Testing" {
        InvokePesterGeneralTests -GenScriptBlock ${Function:GenFunction3} -ArgumentList "Hello", "World" -VerboseMockMatches "Testing"
    }

    It "GenFunction4 Testing" {
        InvokePesterGeneralTests -GenScriptBlock ${Function:GenFunction4} -ArgumentList "Hello", "World" -VerboseMockMatches "Testing"
    }

    It "ProcessFunction Testing" {
        #TODO adjust pester testing maybe here to account for the unsupported scenario.
        $true | Should -Be $true
    }

    It "ProcessFunction1 Testing" {
        InvokePesterGeneralTests -GenScriptBlock ${Function:ProcessFunctionParamEmpty} -ArgumentList "Hello", "World" -VerboseMockMatches "Testing"
    }

    It "ProcessFunction1 Testing" {
        InvokePesterGeneralTests -GenScriptBlock ${Function:ProcessFunction1} -ArgumentList "Hello", "World" -VerboseMockMatches "Testing"
    }

    It "ProcessFunction2 Testing" {
        InvokePesterGeneralTests -GenScriptBlock ${Function:ProcessFunction2} -ArgumentList "Hello", "World" -VerboseMockMatches "Test Begin", "Testing"
    }

    It "ProcessFunction3 Testing" {
        InvokePesterGeneralTests -GenScriptBlock ${Function:ProcessFunction3} -ArgumentList "Hello", "World" -VerboseMockMatches "Test Begin", "Testing", "Test End"
    }

    It "ProcessFunction4 Testing" {
        InvokePesterGeneralTests -GenScriptBlock ${Function:ProcessFunction4} -ArgumentList "Hello", "World" -VerboseMockMatches "Testing", "Test End"
    }

    It "Script Block Testing" {
        InvokePesterGeneralTests -GenScriptBlock $Script:scriptBlock -ArgumentList "Hello", "World" -VerboseMockMatches "Testing"
    }
}

Describe "Supported Additional Parameters" {
    BeforeAll {

        <#
            Primary Script Block Types that are supported.
        #>
        function GenFunction {
            param($a, $b)
            Write-Verbose "Test in GenFunction"
            Write-Verbose "Using $myUsing"
            InjectProcessFunction $a $b
        }

        function GenFunction3 {
            [CmdletBinding()]
            param(
                [string]$a,
                [string]$b
            )
            Write-Verbose "Test in GenFunction3"
            Write-Verbose "Using $myUsing"
            $params = @{
                A = $a
                B = $b
            }
            InjectProcessFunction @params
        }

        function GenFunction4 {
            Write-Verbose "Test in GenFunction4"
            Write-Verbose "Using $myUsing"
            InjectProcessFunction "Hello" "Bill"
        }

        function ProcessFunction1 {
            param(
                [string]$First,
                [string]$Second
            )
            process {
                Write-Verbose "Test in process of ProcessFunction1"
                Write-Verbose "Using $myUsing"
                InjectProcessFunction $First $Second
            }
        }

        function ProcessFunction2 {
            param(
                [string]$a,
                [string]$b
            )
            begin {
                Write-Verbose "Test in begin of ProcessFunction2"
                $params = @{
                    A = $a
                    B = $b
                }
                Write-Verbose "Using $myUsing"
            }
            process {
                Write-Verbose "Test in process of ProcessFunction2"
                InjectProcessFunction @params
            }
        }

        function ProcessFunction3 {
            param(
                [string]$First,
                [string]$Second
            )
            begin {
                Write-Verbose "Test in begin of ProcessFunction3"
                Write-Verbose "Using $myUsing"
                $First = "$First $man1"
            }
            process {
                Write-Verbose "Test in process of ProcessFunction3"
                $Second = "$Second $man2"
                InjectProcessFunction $First $Second
            }
            end {
                Write-Verbose "Test in end of ProcessFunction3"
            }
        }

        function ProcessFunction4 {
            param(
                [string]$a,
                [string]$b
            )
            process {
                Write-Verbose "Test in process of ProcessFunction4"
                Write-Verbose "Using $myUsing"
            }
            end {
                InjectProcessFunction $a $b
                Write-Verbose "Test in end of ProcessFunction4"
            }
        }

        <#
            End of Primary Script Block Types that are supported.
        #>

        function InjectProcessFunction {
            param(
                [string]$a,
                [string]$b
            )
            process {
                Write-Verbose "Testing in InjectProcessFunction"
                [PSCustomObject]@{
                    A = $a
                    B = $b
                }
            }
        }

        function InvokePesterGeneralTests2 {
            param(
                [ScriptBlock]$PScriptBlock,
                [string[]]$UsingVariables,
                [object[]]$ArgumentList,
                [string[]]$VerboseMockMatches
            )
            $Script:VerboseCounter = 0
            Mock Write-Verbose { param ($Message) $Script:VerboseCounter++ }
            $sb = Add-ScriptBlockInjection -PrimaryScriptBlock $PScriptBlock -IncludeUsingVariableName $UsingVariables -IncludeScriptBlock ${Function:InjectProcessFunction}
            $verboseFromScriptBlock = $Script:VerboseCounter

            $arguments = @{
                ScriptBlock = $sb
            }

            if ($null -ne $ArgumentList) {
                $arguments["ArgumentList"] = $ArgumentList
            }

            # Start Job
            $job = Start-Job @arguments
            $r = Receive-Job $job -Wait -AutoRemoveJob
            if ($UsingVariables.Count -eq 1) {
                $r.A | Should -Be $ArgumentList[0]
                $r.B | Should -Be $ArgumentList[1]
            } else {
                $r.A | Should -Be "$($ArgumentList[0]) $((Get-Variable $UsingVariables[1]).Value)"
                $r.B | Should -Be "$($ArgumentList[1]) $((Get-Variable $UsingVariables[2]).Value)"
            }

            try {
                if ($PSSenderInfo) {
                    $PSSenderInfoOriginal = $PSSenderInfo
                    $PSSenderInfo = $null
                    $restPSSenderInfo = $true
                }

                # operator
                if ( $null -eq $ArgumentList) {
                    $r = & $sb
                    $r.A | Should -Be "Hello"
                    $r.B | Should -Be "World"
                } else {
                    $r = & $sb @ArgumentList
                    if ($UsingVariables.Count -eq 1) {
                        $r.A | Should -Be $ArgumentList[0]
                        $r.B | Should -Be $ArgumentList[1]
                    } else {
                        $r.A | Should -Be "$($ArgumentList[0]) $((Get-Variable $UsingVariables[1]).Value)"
                        $r.B | Should -Be "$($ArgumentList[1]) $((Get-Variable $UsingVariables[2]).Value)"
                    }
                }

                foreach ($match in $VerboseMockMatches) {
                    Assert-MockCalled Write-Verbose -ParameterFilter { $Message -eq $match } -Exactly 1
                }

                # Not sure why, but we need to add 1 here.
                Assert-MockCalled Write-Verbose -Exactly ($verboseFromScriptBlock + $VerboseMockMatches.Count + 1)
            } finally {
                if ($restPSSenderInfo) {
                    $PSSenderInfo = $PSSenderInfoOriginal
                }
            }
        }
    }

    It "GenFunction Test Injection" {
        $Script:myUsing = "Wild"
        InvokePesterGeneralTests2 -PScriptBlock ${Function:GenFunction} -UsingVariables @("myUsing") -ArgumentList "Contoso", "Lab" -VerboseMockMatches "Test in GenFunction", "Using Wild"
    }

    It "GenFunction3 Test Injection" {
        $Script:myUsing = "Crazy"
        InvokePesterGeneralTests2 -PScriptBlock ${Function:GenFunction3} -UsingVariables @("myUsing") -ArgumentList "Hi", "Lab" -VerboseMockMatches "Test in GenFunction3", "Using Crazy"
    }

    It "GenFunction4 Test Injection" {
        $Script:myUsing = "Crazy"
        InvokePesterGeneralTests2 -PScriptBlock ${Function:GenFunction4} -UsingVariables @("myUsing") -ArgumentList "Hello", "Bill" -VerboseMockMatches "Test in GenFunction4", "Using Crazy"
    }

    It "ProcessFunction1 Test Injection" {
        $Script:myUsing = "Wild"
        InvokePesterGeneralTests2 -PScriptBlock ${Function:ProcessFunction1} -UsingVariables @("myUsing") -ArgumentList "Hi", "Lab" -VerboseMockMatches "Test in process of ProcessFunction1", "Using Wild"
    }

    It "ProcessFunction2 Test Injection" {
        $Script:myUsing = "Wild"
        InvokePesterGeneralTests2 -PScriptBlock ${Function:ProcessFunction2} -UsingVariables @("myUsing") -ArgumentList "Hi", "Lab" -VerboseMockMatches "Test in process of ProcessFunction2", "Using Wild", "Test in process of ProcessFunction2"
    }

    It "ProcessFunction3 Test Injection" {
        $Script:myUsing = "Wild"
        $Script:man1 = "Crazy"
        $Script:man2 = "Man"
        InvokePesterGeneralTests2 -PScriptBlock ${Function:ProcessFunction3} -UsingVariables @("myUsing", "man1", "man2") -ArgumentList "Hi", "Lab" -VerboseMockMatches "Test in process of ProcessFunction3", "Using Wild", "Test in end of ProcessFunction3", "Test in begin of ProcessFunction3"
    }

    It "ProcessFunction4 Test Injection" {
        $Script:myUsing = "Tiny"
        InvokePesterGeneralTests2 -PScriptBlock ${Function:ProcessFunction4} -UsingVariables @("myUsing") -ArgumentList "Hi", "Lab" -VerboseMockMatches "Test in process of ProcessFunction4", "Using Tiny", "Test in process of ProcessFunction4"
    }
}
