# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Regression gates for HealthChecker analyzer and writer code.

    Analyzer output travels across a PowerShell remoting boundary before the
    writer renders it, so table colorization is expressed as string IDs
    (ColorizerIds) that the writer resolves through a local registry. Two
    AST-based gates guard the fix:

        1. Analyzer files must not reference ColorizerFunctions (as a
           hashtable key or as a member expression).
        2. Non-test files under Diagnostics/HealthChecker must not contain
           dynamic string-to-code sinks that could recompile a serialized
           string into executable code.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester scoped fixture variables')]
[CmdletBinding()]
param()

BeforeDiscovery {
    $analyzerRoot = (Resolve-Path -Path "$PSScriptRoot\..").Path
    $healthCheckerRoot = (Resolve-Path -Path "$PSScriptRoot\..\..").Path

    $Script:AnalyzerFiles = @(
        Get-ChildItem -Path $analyzerRoot -Filter *.ps1 -Recurse |
            Where-Object { $_.FullName -notmatch '[\\/]Tests[\\/]' } |
            ForEach-Object { @{ FilePath = $_.FullName; FileName = $_.Name } }
    )

    $Script:HealthCheckerProdFiles = @(
        Get-ChildItem -Path $healthCheckerRoot -Filter *.ps1 -Recurse |
            Where-Object { $_.FullName -notmatch '[\\/]Tests[\\/]' } |
            ForEach-Object { @{ FilePath = $_.FullName; FileName = $_.Name } }
    )
}

BeforeAll {
    # Re-enumerate in run phase so runtime It blocks can assert non-empty coverage.
    $analyzerRoot = (Resolve-Path -Path "$PSScriptRoot\..").Path
    $healthCheckerRoot = (Resolve-Path -Path "$PSScriptRoot\..\..").Path

    $Script:AnalyzerFileCount = @(
        Get-ChildItem -Path $analyzerRoot -Filter *.ps1 -Recurse |
            Where-Object { $_.FullName -notmatch '[\\/]Tests[\\/]' }
    ).Count

    $Script:HealthCheckerProdFileCount = @(
        Get-ChildItem -Path $healthCheckerRoot -Filter *.ps1 -Recurse |
            Where-Object { $_.FullName -notmatch '[\\/]Tests[\\/]' }
    ).Count
}

Describe "HealthChecker analyzer files use ColorizerIds, not raw ColorizerFunctions ScriptBlocks" {

    It "Discovers at least one analyzer file to scan" {
        $Script:AnalyzerFileCount | Should -BeGreaterThan 0 -Because "an empty analyzer file list would let regressions pass unnoticed"
    }

    It "<FileName> does not reference ColorizerFunctions" -ForEach $Script:AnalyzerFiles {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $FilePath, [ref]$tokens, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty -Because "the analyzer file must parse cleanly"

        $offenders = $ast.FindAll({
                param($node)

                if ($node -is [System.Management.Automation.Language.HashtableAst]) {
                    foreach ($pair in $node.KeyValuePairs) {
                        $keyAst = $pair.Item1
                        if ($keyAst -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                            $keyAst.Value -eq "ColorizerFunctions") {
                            return $true
                        }
                    }
                    return $false
                }

                if ($node -is [System.Management.Automation.Language.MemberExpressionAst]) {
                    $memberAst = $node.Member
                    if ($memberAst -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                        $memberAst.Value -eq "ColorizerFunctions") {
                        return $true
                    }
                }

                # Catch any literal use of the name (indexer keys, Add-Member arguments,
                # variable assignments, etc.) so the gate does not depend on the exact
                # syntactic form.
                if ($node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $node.Value -eq "ColorizerFunctions") {
                    return $true
                }

                return $false
            }, $true)

        $offenderLines = ($offenders | ForEach-Object { "line $($_.Extent.StartLineNumber)" }) -join ", "
        $offenders | Should -BeNullOrEmpty -Because "analyzer files must set ColorizerIds resolved via Get-HealthCheckerColorizer, not reference ColorizerFunctions. Found ColorizerFunctions reference at: $offenderLines"
    }
}

Describe "HealthChecker production files do not contain in-process string-to-code execution sinks" {

    It "Discovers at least one HealthChecker production file to scan" {
        $Script:HealthCheckerProdFileCount | Should -BeGreaterThan 0 -Because "an empty file list would let regressions pass unnoticed"
    }

    It "<FileName> does not use [ScriptBlock]::Create, Invoke-Expression, AddScript, InvokeScript, NewScriptBlock, or ExpandString" -ForEach $Script:HealthCheckerProdFiles {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $FilePath, [ref]$tokens, [ref]$parseErrors)
        $parseErrors | Should -BeNullOrEmpty -Because "the HealthChecker file must parse cleanly"

        $blockedMemberNames = @("Create", "AddScript", "InvokeScript")
        $blockedInvokeCommandMembers = @("NewScriptBlock", "ExpandString")
        $blockedCommandNames = @("Invoke-Expression", "iex")

        $offenders = $ast.FindAll({
                param($node)

                if ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
                    $memberAst = $node.Member
                    if ($memberAst -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                        $blockedMemberNames -contains $memberAst.Value) {

                        if ($memberAst.Value -eq "Create") {
                            $exprAst = $node.Expression
                            if ($exprAst -is [System.Management.Automation.Language.TypeExpressionAst] -and
                                $exprAst.TypeName.Name -match '^(ScriptBlock|System\.Management\.Automation\.ScriptBlock)$') {
                                return $true
                            }
                            return $false
                        }

                        return $true
                    }

                    # $ExecutionContext.InvokeCommand.NewScriptBlock / .ExpandString sinks.
                    # Receiver-scoped so we do not flag unrelated APIs that happen to expose
                    # methods with the same name.
                    if ($memberAst -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                        $blockedInvokeCommandMembers -contains $memberAst.Value) {
                        $receiverAst = $node.Expression
                        if ($receiverAst -is [System.Management.Automation.Language.MemberExpressionAst]) {
                            $receiverMember = $receiverAst.Member
                            $receiverTarget = $receiverAst.Expression
                            if ($receiverMember -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                                $receiverMember.Value -eq "InvokeCommand" -and
                                $receiverTarget -is [System.Management.Automation.Language.VariableExpressionAst] -and
                                $receiverTarget.VariablePath.UserPath -eq "ExecutionContext") {
                                return $true
                            }
                        }
                    }
                }

                if ($node -is [System.Management.Automation.Language.CommandAst]) {
                    $commandName = $node.GetCommandName()
                    if ($null -ne $commandName) {
                        # GetCommandName returns the raw text, which may be module-qualified (e.g. "Microsoft.PowerShell.Utility\Invoke-Expression").
                        $bareName = $commandName.Substring($commandName.LastIndexOf('\') + 1)
                        if ($blockedCommandNames -contains $bareName) {
                            return $true
                        }
                    }
                }

                return $false
            }, $true)

        $offenderDetails = ($offenders | ForEach-Object {
                "line $($_.Extent.StartLineNumber): $($_.Extent.Text.Trim())"
            }) -join "; "
        $offenders | Should -BeNullOrEmpty -Because "HealthChecker production code must not compile or invoke dynamic strings as PowerShell code. Found sink usage at: $offenderDetails"
    }
}
