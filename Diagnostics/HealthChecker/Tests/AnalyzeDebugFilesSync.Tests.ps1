# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Sync guard for the `.github/skills/analyze-debug-files/` skill.
#
# The skill's Get-DebugFileMetadata.ps1 hard-codes regexes that match
# specific string literals emitted by CSS-Exchange scripts:
#
#   - Diagnostics/HealthChecker/Helpers/Get-ErrorsThatOccurred.ps1
#   - Diagnostics/HealthChecker/Helpers/HiddenJobUnhandledErrorFunctions.ps1
#   - Shared/ErrorMonitorFunctions.ps1
#
# If any of those producer strings is edited (typo fix, grammar cleanup,
# reformat) without also updating the consumer regexes, the skill silently
# misclassifies debug logs. This test enforces the sync contract by:
#
#   1. Extracting each producer Write-Verbose argument via AST scoped to
#      its containing function, so a copy of the marker elsewhere in the
#      file cannot mask its removal from the function the skill relies on.
#   2. Asserting the extracted value equals the expected literal EXACTLY
#      (via `-ceq`), so a producer change that adds a prefix/suffix or
#      alters casing fails loudly rather than passing a substring check.
#   3. Running the consumer regex against the actual log-line form of the
#      extracted value (via a logger simulator), not against a synthetic
#      pristine reconstruction.
#   4. Extracting the consumer's regex table AND its CompletionSignals /
#      BodyEvidenceMarkerRegexes arrays via AST, resolving variable-
#      reference patterns and `IsTimestamped` flags so that wiring bugs
#      (a signal marked as timestamped when its banner is not, a body-
#      evidence regex removed, or a completion signal removed) also
#      fail loudly.
#
# When this fails, either a producer wording changed (update the skill's
# regexes) or a consumer regex/wiring changed (revert or resync).

[CmdletBinding()]
param()

Describe "analyze-debug-files skill: producer/consumer string sync" {

    BeforeAll {
        $Script:repoRoot = (Get-Item "$PSScriptRoot\..\..\..").FullName
        $Script:consumerPath = Join-Path $Script:repoRoot '.github\skills\analyze-debug-files\Get-DebugFileMetadata.ps1'
        $Script:errorsPath = Join-Path $Script:repoRoot 'Diagnostics\HealthChecker\Helpers\Get-ErrorsThatOccurred.ps1'
        $Script:remotePath = Join-Path $Script:repoRoot 'Diagnostics\HealthChecker\Helpers\HiddenJobUnhandledErrorFunctions.ps1'
        $Script:monitorPath = Join-Path $Script:repoRoot 'Shared\ErrorMonitorFunctions.ps1'

        function Get-AstFromFile {
            param([Parameter(Mandatory)][string]$Path)
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
            if ($parseErrors -and $parseErrors.Count -gt 0) {
                throw "Parse errors in ${Path}: $($parseErrors[0].Message)"
            }
            return $ast
        }

        function Get-EnclosingFunctionName {
            # Walks an AST node's Parent chain and returns the innermost
            # enclosing FunctionDefinitionAst.Name. Returns '<TopLevel>'
            # when the node is at file scope.
            param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Node)
            $cur = $Node.Parent
            while ($null -ne $cur) {
                if ($cur -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
                    return $cur.Name
                }
                $cur = $cur.Parent
            }
            return '<TopLevel>'
        }

        function Get-WriteVerboseRecords {
            # Returns [PSCustomObject]{Function, Value, Line} for every
            # Write-Verbose call whose first argument is a string literal.
            # Function is the innermost enclosing FunctionDefinitionAst.Name.
            # Value is preserved verbatim; expandable-string interpolations
            # remain as `$Var` tokens (unresolved) so assertions can match
            # the producer's exact source form.
            param([Parameter(Mandatory)][string]$Path)
            $ast = Get-AstFromFile -Path $Path
            $calls = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.CommandAst] -and
                    $n.CommandElements.Count -ge 2 -and
                    $n.CommandElements[0].Value -eq 'Write-Verbose'
                }, $true)
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($c in $calls) {
                $arg = $c.CommandElements[1]
                if ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    $arg -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                    $out.Add([PSCustomObject]@{
                            Function = Get-EnclosingFunctionName -Node $c
                            Value    = $arg.Value
                            Line     = $c.Extent.StartLineNumber
                        })
                }
            }
            return , $out.ToArray()
        }

        function Get-StringLiteralRecords {
            # Returns [PSCustomObject]{Function, Value, Line} for every
            # StringConstantExpressionAst in the file. Useful for producers
            # that build their emitted string via concatenation (e.g.
            # WriteRemoteErrorInformation in HiddenJobUnhandledErrorFunctions.ps1
            # concatenates the banner into a local variable that is later
            # passed to Write-Verbose).
            param([Parameter(Mandatory)][string]$Path)
            $ast = Get-AstFromFile -Path $Path
            $nodes = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                }, $true)
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($n in $nodes) {
                $out.Add([PSCustomObject]@{
                        Function = Get-EnclosingFunctionName -Node $n
                        Value    = $n.Value
                        Line     = $n.Extent.StartLineNumber
                    })
            }
            return , $out.ToArray()
        }

        function Test-FunctionHasWriteVerboseWithVariable {
            # Verifies that a specific function in the given file contains a
            # `Write-Verbose <VariableExpression>` call whose variable matches
            # $VariableName. Used to prove that the remote-banner literal
            # extracted from WriteRemoteErrorInformation actually flows into
            # a Write-Verbose call (via the local `$errorInformation` sink),
            # not just that it exists as a string somewhere in scope.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$FunctionName,
                [Parameter(Mandatory)][string]$VariableName
            )
            $ast = Get-AstFromFile -Path $Path
            $fn = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $n.Name -eq $FunctionName
                }, $true) | Select-Object -First 1
            if (-not $fn) { return $false }
            $calls = $fn.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.CommandAst] -and
                    $n.CommandElements.Count -ge 2 -and
                    $n.CommandElements[0].Value -eq 'Write-Verbose'
                }, $true)
            foreach ($c in $calls) {
                $arg = $c.CommandElements[1]
                if ($arg -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $arg.VariablePath.UserPath -eq $VariableName) {
                    return $true
                }
            }
            return $false
        }

        function Test-StringLiteralAssignedToVariable {
            # Verifies that $StringLiteral appears as a StringConstantExpressionAst
            # descendant of an AssignmentStatementAst whose Left-hand side names
            # $VariableName, scoped to $FunctionName. Closes the data-flow gap
            # that `Test-FunctionHasWriteVerboseWithVariable` alone leaves open:
            # a producer could keep both the literal and the Write-Verbose call
            # but disconnect them (e.g. `$unused = '<banner>'; $errorInformation
            # = 'different'; Write-Verbose $errorInformation`).
            #
            # AssignmentStatementAst covers both `=` and `+=`, so this matches
            # both the initial assignment and any subsequent concatenation.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$FunctionName,
                [Parameter(Mandatory)][string]$VariableName,
                [Parameter(Mandatory)][string]$StringLiteral
            )
            $ast = Get-AstFromFile -Path $Path
            $fn = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $n.Name -eq $FunctionName
                }, $true) | Select-Object -First 1
            if (-not $fn) { return $false }
            $assigns = $fn.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]
                }, $true)
            foreach ($a in $assigns) {
                # Left side may be `[type]$var`, `$var`, `$var.Property`, etc.
                # Look for a VariableExpressionAst descendant that names
                # $VariableName.
                $lhsVar = $a.Left.Find({
                        param($n)
                        $n -is [System.Management.Automation.Language.VariableExpressionAst] -and
                        $n.VariablePath.UserPath -eq $VariableName
                    }, $true)
                if (-not $lhsVar) { continue }
                $rhsLiteral = $a.Right.Find({
                        param($n)
                        $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                        $n.Value -ceq $StringLiteral
                    }, $true)
                if ($rhsLiteral) { return $true }
            }
            return $false
        }

        function Get-ConsumerRegexTables {
            # Walks the consumer AST and returns three hash tables:
            #   .Named          -> {logical-name -> compiled regex}
            #   .Signals        -> {signal-name  -> @{Regex; IsTimestamped}}
            #   .BodyEvidence   -> {marker-kind  -> compiled regex}
            #
            # Handles both inline `[regex]::new(...)` patterns AND variable-
            # reference patterns (e.g. `Pattern = $Script:HandledSummaryHeaderRegex`);
            # the latter are resolved through the .Named table. Also captures
            # each signal's `IsTimestamped` flag so wiring-flip bugs surface.
            param([Parameter(Mandatory)][string]$Path)
            $ast = Get-AstFromFile -Path $Path

            $assignments = $ast.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]
                }, $true)

            $shapeAssign = $assignments | Where-Object {
                $_.Left.Extent.Text -eq '$Script:BracketedTimestampShape'
            } | Select-Object -First 1
            if (-not $shapeAssign) {
                throw "Consumer does not define `$Script:BracketedTimestampShape."
            }
            $shapeLiteral = $shapeAssign.Right.Find({
                    param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                }, $true)
            if (-not $shapeLiteral) {
                throw "Consumer's `$Script:BracketedTimestampShape assignment is not a plain string literal."
            }
            $shapeValue = $shapeLiteral.Value

            function Get-PatternStringFromRegexCall {
                param($InvokeMemberExpression)
                if (-not $InvokeMemberExpression) { return $null }
                if ($InvokeMemberExpression.Arguments.Count -lt 1) { return $null }
                $patternArg = $InvokeMemberExpression.Arguments[0]
                if ($patternArg -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    $patternArg -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                    return $patternArg.Value
                }
                return $null
            }

            function Resolve-InterpolatedPattern {
                param([string]$Pattern, [string]$ShapeValue)
                if ($null -eq $Pattern) { return $null }
                return $Pattern -replace [regex]::Escape('$Script:BracketedTimestampShape'), $ShapeValue
            }

            $named = @{}

            # Named top-level regexes.
            $namedRegexes = @(
                'HandledSummaryHeaderRegex',
                'UnhandledSummaryHeaderRegex',
                'UnhandledRemoteSummaryHeaderRegex',
                'RemoteErrorInformationHeaderRegex',
                'HandledMarkerRegex',
                'SummaryFooterRegex',
                'ErrorIndexRegex'
            )
            foreach ($name in $namedRegexes) {
                $target = "`$Script:$name"
                $a = $assignments | Where-Object { $_.Left.Extent.Text -eq $target } | Select-Object -First 1
                if (-not $a) { throw "Consumer does not define $target." }
                $invoke = $a.Right.Find({
                        param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
                    }, $true)
                $pattern = Get-PatternStringFromRegexCall $invoke
                $pattern = Resolve-InterpolatedPattern -Pattern $pattern -ShapeValue $shapeValue
                if (-not $pattern) { throw "Could not extract pattern for $target." }
                $named[$name] = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::None)
            }

            # CompletionSignals: array of PSCustomObjects with Name / Pattern /
            # IsTimestamped. Pattern may be an inline `[regex]::new(...)` call
            # OR a variable reference (`$Script:HandledSummaryHeaderRegex`).
            $signals = @{}
            $signalsAssign = $assignments | Where-Object {
                $_.Left.Extent.Text -eq '$Script:CompletionSignals'
            } | Select-Object -First 1
            if (-not $signalsAssign) { throw "Consumer does not define `$Script:CompletionSignals." }
            $signalTables = $signalsAssign.Right.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.HashtableAst]
                }, $true)
            foreach ($ht in $signalTables) {
                $pairs = @{}
                foreach ($kv in $ht.KeyValuePairs) {
                    $keyNode = $kv.Item1.Find({
                            param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                        }, $true)
                    if (-not $keyNode) { continue }
                    $pairs[$keyNode.Value] = $kv.Item2
                }
                if (-not $pairs.ContainsKey('Name') -or -not $pairs.ContainsKey('Pattern')) { continue }

                $nameNode = $pairs['Name'].Find({
                        param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $true)
                if (-not $nameNode) { continue }
                $signalName = $nameNode.Value

                # Pattern: try inline [regex]::new(...) first; fall back to
                # variable-reference lookup in $named.
                $patternRegex = $null
                $invoke = $pairs['Pattern'].Find({
                        param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
                    }, $true)
                if ($invoke) {
                    $pattern = Get-PatternStringFromRegexCall $invoke
                    if ($pattern) {
                        $pattern = Resolve-InterpolatedPattern -Pattern $pattern -ShapeValue $shapeValue
                        $patternRegex = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::None)
                    }
                } else {
                    $varRef = $pairs['Pattern'].Find({
                            param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst]
                        }, $true)
                    if ($varRef) {
                        $varName = $varRef.VariablePath.UserPath
                        $refName = $varName -replace '^Script:', ''
                        if ($named.ContainsKey($refName)) {
                            $patternRegex = $named[$refName]
                        }
                    }
                }
                if (-not $patternRegex) {
                    throw "CompletionSignals entry '$signalName' has an unresolvable Pattern."
                }

                # IsTimestamped: variable expression $true / $false in the
                # source parses as a VariableExpressionAst whose VariablePath
                # is "true" or "false". Fall back to $true if absent (the
                # consumer's convention is to state it explicitly).
                $isTimestamped = $null
                if ($pairs.ContainsKey('IsTimestamped')) {
                    $tsVar = $pairs['IsTimestamped'].Find({
                            param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst]
                        }, $true)
                    if ($tsVar) {
                        $isTimestamped = ($tsVar.VariablePath.UserPath -eq 'true')
                    }
                }
                if ($null -eq $isTimestamped) {
                    throw "CompletionSignals entry '$signalName' is missing IsTimestamped."
                }

                $signals[$signalName] = [PSCustomObject]@{
                    Regex         = $patternRegex
                    IsTimestamped = $isTimestamped
                }
            }

            # BodyEvidenceMarkerRegexes: array of PSCustomObjects with
            # Kind / Pattern. Patterns are inline `[regex]::new(...)` calls.
            $bodyEvidence = @{}
            $bodyAssign = $assignments | Where-Object {
                $_.Left.Extent.Text -eq '$Script:BodyEvidenceMarkerRegexes'
            } | Select-Object -First 1
            if (-not $bodyAssign) { throw "Consumer does not define `$Script:BodyEvidenceMarkerRegexes." }
            $bodyTables = $bodyAssign.Right.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.HashtableAst]
                }, $true)
            foreach ($ht in $bodyTables) {
                $pairs = @{}
                foreach ($kv in $ht.KeyValuePairs) {
                    $keyNode = $kv.Item1.Find({
                            param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                        }, $true)
                    if (-not $keyNode) { continue }
                    $pairs[$keyNode.Value] = $kv.Item2
                }
                if (-not $pairs.ContainsKey('Kind') -or -not $pairs.ContainsKey('Pattern')) { continue }
                $kindNode = $pairs['Kind'].Find({
                        param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $true)
                if (-not $kindNode) { continue }
                $kind = $kindNode.Value
                $invoke = $pairs['Pattern'].Find({
                        param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
                    }, $true)
                $pattern = Get-PatternStringFromRegexCall $invoke
                if ($pattern) {
                    $bodyEvidence[$kind] = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::None)
                }
            }

            return [PSCustomObject]@{
                Named        = $named
                Signals      = $signals
                BodyEvidence = $bodyEvidence
            }
        }

        function Get-LoggedLine {
            # Simulates the first visible log line the HealthChecker logger
            # writes for a given Write-Verbose argument. The logger prefixes
            # every emission with `[<culture-timestamp>] :`; when the argument
            # begins with a newline the prefix lands on the leading blank line
            # and the visible content arrives without a timestamp on the next
            # non-empty physical line.
            #
            # SCOPE BOUNDARY: This simulator is faithful to the DOCUMENTED
            # contract between the logger's emitted form and the skill's
            # regexes (`[<ts>] : <message>` for timestamped, first non-empty
            # line for multi-line-with-leading-newlines). It does NOT invoke
            # `Write-LoggerInstance` directly. If the logger drifts from this
            # contract, a separate logger↔skill sync test would be needed —
            # that coupling is out of scope for this file, which guards only
            # producer↔skill sync.
            param([Parameter(Mandatory)][string]$RawWriteVerbose)
            if ($RawWriteVerbose.StartsWith("`r`n") -or $RawWriteVerbose.StartsWith("`n")) {
                # `@(...)` prevents a single-element result from collapsing to
                # a scalar string; without it `$lines[0]` would return the
                # first character of the string, not the first element.
                $lines = @(($RawWriteVerbose -split "`r?`n") | Where-Object { $_ -ne '' })
                if ($lines.Count -eq 0) { return '' }
                return $lines[0]
            }
            return "[09/12/2026 18:11:22.1234567] : $RawWriteVerbose"
        }

        $Script:consumer = Get-ConsumerRegexTables -Path $Script:consumerPath
        $Script:errorsRecords = Get-WriteVerboseRecords -Path $Script:errorsPath
        $Script:monitorRecords = Get-WriteVerboseRecords -Path $Script:monitorPath
        $Script:remoteLiteralRecords = Get-StringLiteralRecords -Path $Script:remotePath
    }

    Context "HealthChecker Get-ErrorsThatOccurred.ps1 -> skill regexes" {

        It "Write-Errors emits `-----Errors that were handled----- banner and HandledSummaryHeaderRegex matches its logged line" {
            $expected = "`r`n`r`n-----Errors that were handled-----"
            $records = @($Script:errorsRecords | Where-Object { $_.Function -eq 'Write-Errors' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Write-Errors should emit exactly one handled-banner Write-Verbose (leading blank lines + '-----Errors that were handled-----')"
            $logged = Get-LoggedLine -RawWriteVerbose $records[0].Value
            $Script:consumer.Named['HandledSummaryHeaderRegex'].IsMatch($logged) | Should -BeTrue -Because "skill's HandledSummaryHeaderRegex must match the logged banner line '$logged'"
        }

        It "Write-Errors emits ----Errors that occurred that wasn't handled---- banner and UnhandledSummaryHeaderRegex matches its logged line" {
            $expected = "`r`n`r`n----Errors that occurred that wasn't handled----"
            $records = @($Script:errorsRecords | Where-Object { $_.Function -eq 'Write-Errors' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Write-Errors should emit exactly one unhandled-banner Write-Verbose"
            $logged = Get-LoggedLine -RawWriteVerbose $records[0].Value
            $Script:consumer.Named['UnhandledSummaryHeaderRegex'].IsMatch($logged) | Should -BeTrue -Because "skill's UnhandledSummaryHeaderRegex must match the logged banner line '$logged'"
        }

        It "Write-Errors emits the remote-unhandled banner and UnhandledRemoteSummaryHeaderRegex matches its logged line" {
            $expected = "`r`n`r`n----Errors that occurred that was not handled remotely----"
            $records = @($Script:errorsRecords | Where-Object { $_.Function -eq 'Write-Errors' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Write-Errors should emit exactly one remote-unhandled-banner Write-Verbose"
            $logged = Get-LoggedLine -RawWriteVerbose $records[0].Value
            $Script:consumer.Named['UnhandledRemoteSummaryHeaderRegex'].IsMatch($logged) | Should -BeTrue -Because "skill's UnhandledRemoteSummaryHeaderRegex must match the logged banner line '$logged'"
        }

        It "Write-Errors emits the dashed footer exactly three times (one per section) and SummaryFooterRegex matches its timestamped log line" {
            # Write-Errors closes each of the three summary sections with a
            # dashed footer: handled, unhandled, and — when
            # Test-HiddenJobUnhandledErrors is true — remote-unhandled. All
            # three must be present. Requiring exactly 3 prevents a silent
            # removal of one section's footer (which would leave the section
            # open in the state machine).
            $expected = '----------------------------------'
            $records = @($Script:errorsRecords | Where-Object { $_.Function -eq 'Write-Errors' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 3 -Because "Write-Errors emits the dashed footer three times — once for handled, once for unhandled, and once for remote-unhandled sections"
            $logged = Get-LoggedLine -RawWriteVerbose $records[0].Value
            $Script:consumer.Named['SummaryFooterRegex'].IsMatch($logged) | Should -BeTrue -Because "skill's SummaryFooterRegex must match the logged footer line '$logged'"
        }

        It "Write-Errors emits Error Index: markers in both handled and unhandled sections and ErrorIndexRegex matches a resolved instance" {
            # Producer arg is an expandable string `Error Index: $($_.Index)`;
            # `.Value` preserves the interpolation token literally. Two
            # emissions are expected — one per non-remote section. Remote-
            # unhandled errors go through WriteRemoteErrorInformation and do
            # NOT emit Error Index: (they emit the Remote Error Information
            # banner instead). Requiring exactly 2 catches removal of the
            # marker from either section.
            $expected = 'Error Index: $($_.Index)'
            $records = @($Script:errorsRecords | Where-Object { $_.Function -eq 'Write-Errors' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 2 -Because "Write-Errors emits 'Error Index: <n>' once per Get-HandledErrors iteration and once per Get-UnhandledErrors iteration"
            $sampleLogged = Get-LoggedLine -RawWriteVerbose 'Error Index: 0'
            $Script:consumer.Named['ErrorIndexRegex'].IsMatch($sampleLogged) | Should -BeTrue -Because "skill's ErrorIndexRegex must match a resolved '[<ts>] : Error Index: 0' log line"
        }

        It "Get-ErrorsThatOccurred emits 'No errors occurred in the script.' and the NoErrorsMessage signal matches the timestamped line" {
            $expected = 'No errors occurred in the script.'
            $records = @($Script:errorsRecords | Where-Object { $_.Function -eq 'Get-ErrorsThatOccurred' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Get-ErrorsThatOccurred should emit exactly one '$expected' Write-Verbose (the no-errors early-return path)"
            $logged = Get-LoggedLine -RawWriteVerbose $records[0].Value
            $Script:consumer.Signals['NoErrorsMessage'].Regex.IsMatch($logged) | Should -BeTrue -Because "NoErrorsMessage signal must match the logged line"
            $Script:consumer.Signals['NoErrorsMessage'].IsTimestamped | Should -BeTrue -Because "the no-errors message is emitted on a timestamped line; flipping this to `$false would let a crafted log line forge the signal"
        }

        It "Get-ErrorsThatOccurred emits the 'All errors ... handled correctly.' message and AllErrorsHandledMessage signal + HandledMarkerRegex both match" {
            $expected = 'All errors that occurred were in try catch blocks and was handled correctly.'
            $records = @($Script:errorsRecords | Where-Object { $_.Function -eq 'Get-ErrorsThatOccurred' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Get-ErrorsThatOccurred should emit exactly one '$expected' Write-Verbose"
            $logged = Get-LoggedLine -RawWriteVerbose $records[0].Value
            $Script:consumer.Signals['AllErrorsHandledMessage'].Regex.IsMatch($logged) | Should -BeTrue -Because "AllErrorsHandledMessage signal must match the logged line"
            $Script:consumer.Signals['AllErrorsHandledMessage'].IsTimestamped | Should -BeTrue
            $Script:consumer.Named['HandledMarkerRegex'].IsMatch($logged) | Should -BeTrue -Because "HandledMarkerRegex has an alternative for the 'All errors ... try catch' phrase; it must still match"
        }

        It "Write-ScriptDebugObject emits 'Writing out the script debug objects' and WritingScriptDebugObjects signal matches" {
            $expected = 'Writing out the script debug objects'
            $records = @($Script:errorsRecords | Where-Object { $_.Function -eq 'Write-ScriptDebugObject' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Write-ScriptDebugObject should emit exactly one '$expected' Write-Verbose"
            $logged = Get-LoggedLine -RawWriteVerbose $records[0].Value
            $Script:consumer.Signals['WritingScriptDebugObjects'].Regex.IsMatch($logged) | Should -BeTrue
            $Script:consumer.Signals['WritingScriptDebugObjects'].IsTimestamped | Should -BeTrue
        }
    }

    Context "HealthChecker HiddenJobUnhandledErrorFunctions.ps1 -> skill regexes" {

        It "WriteRemoteErrorInformation assigns the remote-banner literal to `$errorInformation, passes it to Write-Verbose, and RemoteErrorInformationHeaderRegex matches" {
            $expected = '----------------Remote Error Information----------------'
            $records = @($Script:remoteLiteralRecords | Where-Object { $_.Function -eq 'WriteRemoteErrorInformation' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "WriteRemoteErrorInformation should still contain exactly one '$expected' literal"
            # Prove the literal actually flows into a Write-Verbose call.
            # Two independent AST checks are required — either alone leaves a
            # silent-pass hole:
            #   (a) The literal appears in an assignment RHS whose LHS names
            #       $errorInformation. Without (a), a producer could write
            #       `$unused = '<banner>'; $errorInformation = 'different';
            #       Write-Verbose $errorInformation` and (b) would still pass.
            #   (b) Write-Verbose is called with $errorInformation. Without
            #       (b), the assigned banner never reaches the log.
            (Test-StringLiteralAssignedToVariable -Path $Script:remotePath -FunctionName 'WriteRemoteErrorInformation' -VariableName 'errorInformation' -StringLiteral $expected) | Should -BeTrue -Because "the '$expected' banner literal must be assigned into `$errorInformation (the sink that Write-Verbose consumes); a detached literal elsewhere in the function does not satisfy this check"
            (Test-FunctionHasWriteVerboseWithVariable -Path $Script:remotePath -FunctionName 'WriteRemoteErrorInformation' -VariableName 'errorInformation') | Should -BeTrue -Because "WriteRemoteErrorInformation must pass `$errorInformation to Write-Verbose so the concatenated banner reaches the log"
            $logged = Get-LoggedLine -RawWriteVerbose "`r`n`r`n$expected"
            $Script:consumer.Named['RemoteErrorInformationHeaderRegex'].IsMatch($logged) | Should -BeTrue
        }
    }

    Context "Shared/ErrorMonitorFunctions.ps1 -> skill HandledMarkerRegex + BodyEvidenceMarkerRegexes" {

        It "Invoke-CatchActions emits 'Calling: `$(`$MyInvocation.MyCommand)' and both HandledMarkerRegex and body-evidence InvokeCatchActions regex match the resolved line" {
            $expected = 'Calling: $($MyInvocation.MyCommand)'
            $records = @($Script:monitorRecords | Where-Object { $_.Function -eq 'Invoke-CatchActions' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Invoke-CatchActions must still emit exactly one '$expected' Write-Verbose; a copy in another function does not satisfy this check because \$MyInvocation resolves to that other function's name"
            $logged = Get-LoggedLine -RawWriteVerbose 'Calling: Invoke-CatchActions'
            $Script:consumer.Named['HandledMarkerRegex'].IsMatch($logged) | Should -BeTrue -Because "HandledMarkerRegex specifically anchors on 'Calling:\\s*Invoke-CatchActions'"
            $Script:consumer.BodyEvidence['InvokeCatchActions'].IsMatch($logged) | Should -BeTrue -Because "body-evidence InvokeCatchActions regex must match the same line"
        }

        It "Invoke-CatchActions emits 'Error Excluded Count:' and both HandledMarkerRegex and body-evidence ErrorExcludedCount regex match" {
            $expected = 'Error Excluded Count: $($Script:ErrorsExcluded.Count)'
            $records = @($Script:monitorRecords | Where-Object { $_.Function -eq 'Invoke-CatchActions' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Invoke-CatchActions must still emit exactly one '$expected' Write-Verbose"
            $logged = Get-LoggedLine -RawWriteVerbose 'Error Excluded Count: 0'
            $Script:consumer.Named['HandledMarkerRegex'].IsMatch($logged) | Should -BeTrue
            $Script:consumer.BodyEvidence['ErrorExcludedCount'].IsMatch($logged) | Should -BeTrue
        }

        It "Invoke-CatchActions emits 'Error Count:' and the body-evidence ErrorCount regex matches" {
            $expected = 'Error Count: $($Error.Count)'
            $records = @($Script:monitorRecords | Where-Object { $_.Function -eq 'Invoke-CatchActions' -and $_.Value -ceq $expected })
            $records.Count | Should -Be 1 -Because "Invoke-CatchActions must still emit exactly one '$expected' Write-Verbose"
            $logged = Get-LoggedLine -RawWriteVerbose 'Error Count: 0'
            $Script:consumer.BodyEvidence['ErrorCount'].IsMatch($logged) | Should -BeTrue
        }
    }

    Context "Consumer wiring: CompletionSignals header signals reference the correct named regexes" {

        It "HandledSummaryHeader signal's regex is the same pattern as HandledSummaryHeaderRegex and IsTimestamped is `$false" {
            $Script:consumer.Signals.ContainsKey('HandledSummaryHeader') | Should -BeTrue -Because "CompletionSignals must include HandledSummaryHeader; removing it would drop this end-of-run marker"
            $Script:consumer.Signals['HandledSummaryHeader'].Regex.ToString() | Should -Be $Script:consumer.Named['HandledSummaryHeaderRegex'].ToString()
            $Script:consumer.Signals['HandledSummaryHeader'].IsTimestamped | Should -BeFalse -Because "the handled-banner arrives without a timestamp; flipping this to `$true would break end-of-run detection"
        }

        It "UnhandledSummaryHeader signal's regex is the same pattern as UnhandledSummaryHeaderRegex and IsTimestamped is `$false" {
            $Script:consumer.Signals.ContainsKey('UnhandledSummaryHeader') | Should -BeTrue
            $Script:consumer.Signals['UnhandledSummaryHeader'].Regex.ToString() | Should -Be $Script:consumer.Named['UnhandledSummaryHeaderRegex'].ToString()
            $Script:consumer.Signals['UnhandledSummaryHeader'].IsTimestamped | Should -BeFalse
        }

        It "UnhandledRemoteSummaryHeader signal's regex is the same pattern as UnhandledRemoteSummaryHeaderRegex and IsTimestamped is `$false" {
            $Script:consumer.Signals.ContainsKey('UnhandledRemoteSummaryHeader') | Should -BeTrue
            $Script:consumer.Signals['UnhandledRemoteSummaryHeader'].Regex.ToString() | Should -Be $Script:consumer.Named['UnhandledRemoteSummaryHeaderRegex'].ToString()
            $Script:consumer.Signals['UnhandledRemoteSummaryHeader'].IsTimestamped | Should -BeFalse
        }
    }
}
