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

# cspell:ignore untimestamped

[CmdletBinding()]
param()

Describe "analyze-debug-files skill: producer/consumer string sync" {

    BeforeAll {
        $Script:repoRoot = (Get-Item "$PSScriptRoot\..\..\..\..").FullName
        $Script:consumerPath = Join-Path $Script:repoRoot '.github\skills\analyze-debug-files\Get-DebugFileMetadata.ps1'
        $Script:errorsPath = Join-Path $Script:repoRoot 'Diagnostics\HealthChecker\Helpers\Get-ErrorsThatOccurred.ps1'
        $Script:remotePath = Join-Path $Script:repoRoot 'Diagnostics\HealthChecker\Helpers\HiddenJobUnhandledErrorFunctions.ps1'
        $Script:monitorPath = Join-Path $Script:repoRoot 'Shared\ErrorMonitorFunctions.ps1'
        $Script:loggerPath = Join-Path $Script:repoRoot 'Shared\LoggerFunctions.ps1'
        $Script:healthCheckerPath = Join-Path $Script:repoRoot 'Diagnostics\HealthChecker\HealthChecker.ps1'
        $Script:mainReportPath = Join-Path $Script:repoRoot 'Diagnostics\HealthChecker\Features\Invoke-HealthCheckerMainReport.ps1'

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
            # StringConstantExpressionAst AND ExpandableStringExpressionAst in
            # the file. Useful for producers
            # that build their emitted string via concatenation (e.g.
            # WriteRemoteErrorInformation in HiddenJobUnhandledErrorFunctions.ps1
            # concatenates the banner into a local variable that is later
            # passed to Write-Verbose).
            #
            # Expandable strings MUST be included: the remote emitter writes its
            # label lines as `"Exception Message: $($CurrentError...)"`, which is
            # an ExpandableStringExpressionAst, not a constant. Collecting only
            # constants silently skipped every remote label and left them
            # unguarded. `.Value` keeps the `$(...)` tokens unresolved so
            # assertions match the producer's source form.
            param([Parameter(Mandatory)][string]$Path)
            $ast = Get-AstFromFile -Path $Path
            $nodes = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst]
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
                'CompletionTailRegex',
                'SummaryFooterRegex',
                'ErrorIndexRegex',
                'TimestampRegex',
                'VersionRegex',
                'TimestampedVersionRegex',
                'CanonicalVersionRegex'
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

        function Get-ConcatenatedRegexPattern {
            # Extracts a `$Script:<Name> = [regex]::new('a' + '|' + 'b', ...)`
            # pattern where the first argument is a STRING CONCATENATION rather
            # than a single literal. `Get-ConsumerRegexTables` deliberately only
            # understands single-literal patterns; CriticalFrameRegex is built
            # by folding alternatives together, so it needs its own reader.
            # Folds BinaryExpressionAst(+) trees left-to-right over string
            # literals and returns the assembled pattern.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$Name
            )
            $ast = Get-AstFromFile -Path $Path
            $target = "`$Script:$Name"
            $assign = $ast.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]
                }, $true) | Where-Object { $_.Left.Extent.Text -eq $target } | Select-Object -First 1
            if (-not $assign) { throw "Consumer does not define $target." }
            $invoke = $assign.Right.Find({
                    param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
                }, $true)
            if (-not $invoke -or $invoke.Arguments.Count -lt 1) {
                throw "$target is not a [regex]::new(...) call."
            }
            $literals = $invoke.Arguments[0].FindAll({
                    param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                }, $true)
            if (-not $literals -or @($literals).Count -eq 0) {
                throw "Could not extract any string literal from $target's pattern argument."
            }
            return (@($literals | ForEach-Object { $_.Value }) -join '')
        }

        function Get-FunctionInlineMatchPattern {
            # Returns the right-hand string literal of the FIRST `-match`
            # binary expression inside the named function. Used for regexes
            # that live inline in a function body (the debug-filename shape)
            # rather than in a `$Script:` table, so they can be exercised
            # without dot-sourcing the whole 2000-line consumer.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$FunctionName
            )
            $ast = Get-AstFromFile -Path $Path
            $fn = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $n.Name -eq $FunctionName
                }, $true) | Select-Object -First 1
            if (-not $fn) { throw "Consumer does not define function $FunctionName." }
            $match = $fn.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and
                    $n.Operator -in @(
                        [System.Management.Automation.Language.TokenKind]::Imatch,
                        [System.Management.Automation.Language.TokenKind]::Cmatch
                    )
                }, $true) | Select-Object -First 1
            if (-not $match) { throw "Function $FunctionName contains no -match expression." }
            $literal = $match.Right.Find({
                    param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                }, $true)
            if (-not $literal) { throw "Function $FunctionName's -match right-hand side is not a string literal." }
            return $literal.Value
        }

        function Test-FileHasAssignmentLiteral {
            # Asserts that $FunctionName in $Path contains an assignment whose
            # right-hand side contains a string literal (or expandable-string
            # source text) exactly equal to $Literal. Used to pin producer
            # format strings that are assigned rather than emitted directly.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$FunctionName,
                [Parameter(Mandatory)][string]$Literal
            )
            $ast = Get-AstFromFile -Path $Path
            $fn = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $n.Name -eq $FunctionName
                }, $true) | Select-Object -First 1
            if (-not $fn) { return $false }
            $hit = $fn.Find({
                    param($n)
                    ($n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and
                    $n.Value -ceq $Literal
                }, $true)
            return ($null -ne $hit)
        }

        function Get-CommandArgumentValues {
            # Returns the verbatim first-argument Value of every call to
            # $CommandName in $Path whose first argument is a string literal
            # or expandable string. Expandable strings keep their `$Var`
            # tokens, matching the producer's source form.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$CommandName
            )
            $ast = Get-AstFromFile -Path $Path
            $calls = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.CommandAst] -and
                    $n.CommandElements.Count -ge 2 -and
                    $n.CommandElements[0].Value -eq $CommandName
                }, $true)
            $out = New-Object System.Collections.Generic.List[string]
            foreach ($c in $calls) {
                $arg = $c.CommandElements[1]
                if ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    $arg -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                    $out.Add($arg.Value)
                }
            }
            return , $out.ToArray()
        }

        function Get-LoggedLine {
            # Simulates the first visible log line the HealthChecker logger
            # writes for a given Write-Verbose argument. The logger prefixes
            # every emission with `[<timestamp>] :`; when the argument
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
        $Script:criticalFrameRegex = [regex]::new(
            (Get-ConcatenatedRegexPattern -Path $Script:consumerPath -Name 'CriticalFrameRegex'))
        $Script:debugFilenamePattern = Get-FunctionInlineMatchPattern `
            -Path $Script:consumerPath -FunctionName 'Get-ScriptIdentityFromFilename'
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

        It "HealthChecker's runtime trailer matches the permitted completion tail" {
            $expected = 'The total script time took $($mainStopWatch.Elapsed.TotalSeconds) seconds'
            $values = Get-CommandArgumentValues -Path $Script:healthCheckerPath -CommandName 'Write-Verbose'
            @($values | Where-Object { $_ -ceq $expected }).Count | Should -Be 1
            $logged = Get-LoggedLine -RawWriteVerbose 'The total script time took 1.25 seconds'
            $Script:consumer.Named['CompletionTailRegex'].IsMatch($logged) | Should -BeTrue
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

    Context "Consumer wiring: BodyEvidenceMarkerRegexes complete Kind set is present" {

        # Sync-guards `InvokeCatchActions`, `ErrorExcludedCount`, and
        # `ErrorCount` above assert one representative marker line per
        # kind against the actual producer emission. The remaining four
        # kinds (`TryingTo`, `FailedTo`, `InnerException`,
        # `CompletedNarrative`) match generic runtime phrases that are
        # not attributable to a single producer function, so a
        # producer-anchored assertion is not meaningful. Step 7 of the
        # skill still relies on all seven kinds being present during
        # body-evidence correlation: removing any kind — including a
        # generic one — would silently drop that class of narrative
        # from the evidence pipeline. This test freezes the complete
        # expected set so a removal fails loudly, and asserts a
        # representative match for each generic kind to catch a
        # pattern-only edit that leaves the Kind entry but breaks
        # matching.

        It "BodyEvidenceMarkerRegexes exposes exactly the seven expected Kind values" {
            $expected = @('InvokeCatchActions', 'ErrorExcludedCount', 'ErrorCount', 'TryingTo', 'FailedTo', 'InnerException', 'CompletedNarrative')
            $actual = @($Script:consumer.BodyEvidence.Keys) | Sort-Object
            $actualSorted = ($actual -join ',')
            $expectedSorted = (($expected | Sort-Object) -join ',')
            $actualSorted | Should -Be $expectedSorted -Because "Step 7 of the analyze-debug-files skill correlates on all seven MarkerKind values; adding or removing a kind changes the evidence contract and must land in a single explicit change with the skill's Step 7 documentation"
        }

        It "TryingTo regex matches a representative 'Trying to <verb>' body line" {
            $logged = Get-LoggedLine -RawWriteVerbose 'Trying to open the debug log.'
            $Script:consumer.BodyEvidence['TryingTo'].IsMatch($logged) | Should -BeTrue -Because "TryingTo is a generic narrative marker; a pattern edit that anchors it too strictly would silently drop legitimate matches"
        }

        It "FailedTo regex matches a representative 'Failed to <verb>' body line" {
            $logged = Get-LoggedLine -RawWriteVerbose 'Failed to open the file.'
            $Script:consumer.BodyEvidence['FailedTo'].IsMatch($logged) | Should -BeTrue
        }

        It "InnerException regex matches a representative 'Inner Exception:' body line" {
            # Matches the local error emission from Shared/Write-ErrorInformation.ps1.
            # The remote emitter uses 'Exception Inner Exception:' (see
            # Diagnostics/HealthChecker/Helpers/HiddenJobUnhandledErrorFunctions.ps1)
            # — the InnerException marker's `(?i)Inner\s+Exception\s*[:=]` matches
            # both variants because it does not anchor the start.
            $logged = Get-LoggedLine -RawWriteVerbose 'Inner Exception: System.InvalidOperationException'
            $Script:consumer.BodyEvidence['InnerException'].IsMatch($logged) | Should -BeTrue
        }

        It "InnerException regex also matches the remote 'Exception Inner Exception:' body line" {
            # Guards against a future edit that anchors the InnerException
            # pattern to the start of the line — that would silently drop
            # the remote-form label the runner relies on when reporting
            # remote failures.
            $logged = Get-LoggedLine -RawWriteVerbose 'Exception Inner Exception: System.Net.WebException'
            $Script:consumer.BodyEvidence['InnerException'].IsMatch($logged) | Should -BeTrue -Because "the remote emitter writes 'Exception Inner Exception:' and the InnerException marker must match both label forms"
        }

        It "CompletedNarrative regex matches a representative timestamped 'Completed'/'Finished'/'Starting' line" {
            # CompletedNarrative anchors on the `[<timestamp>] :` framing
            # to distinguish narrative markers from exception message
            # bodies that quote the same verb. The logger prefix must
            # therefore actually appear in the tested line.
            $logged = Get-LoggedLine -RawWriteVerbose 'Completed the operation.'
            $Script:consumer.BodyEvidence['CompletedNarrative'].IsMatch($logged) | Should -BeTrue
        }

        It "CompletedNarrative regex matches a timestamped 'Finished' line" {
            # The pattern lists three interchangeable verbs
            # (Completed|Finished|Starting); dropping any one of them
            # would silently drop a class of narrative marker. A test
            # per verb catches an alternation edit.
            $logged = Get-LoggedLine -RawWriteVerbose 'Finished the task.'
            $Script:consumer.BodyEvidence['CompletedNarrative'].IsMatch($logged) | Should -BeTrue
        }

        It "CompletedNarrative regex matches a timestamped 'Starting' line" {
            $logged = Get-LoggedLine -RawWriteVerbose 'Starting the operation.'
            $Script:consumer.BodyEvidence['CompletedNarrative'].IsMatch($logged) | Should -BeTrue
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

    Context "Shared/LoggerFunctions.ps1 -> skill TimestampRegex (log-line prefix contract)" {

        # This closes the gap `Get-LoggedLine` documents as out of scope. EVERY
        # timestamped feature of the skill -- StartTime/EndTime, summary
        # framing, version-candidate collection, body-evidence correlation --
        # keys on the prefix shape written here. It is the single highest
        # blast-radius producer coupling in the skill and previously had no
        # assertion against the live logger.

        It "Write-LoggerInstance prefixes string objects with the exact `[<timestamp>] : ` form the skill parses" {
            $expected = '[$([System.DateTime]::Now)] : $Object'
            $found = Test-FileHasAssignmentLiteral -Path $Script:loggerPath `
                -FunctionName 'Write-LoggerInstance' -Literal $expected
            $found | Should -BeTrue -Because "the skill's TimestampRegex requires the literal prefix form '[<ts>] : '; changing the separator, the brackets, or switching to an explicit .ToString(<format>) breaks every timestamped feature"
        }

        It "TimestampRegex matches the line the logger actually renders, and the rendered form is culture-INVARIANT" {
            # PowerShell's string interpolation of a DateTime converts via
            # LanguagePrimitives, which uses InvariantCulture -- NOT the
            # thread culture. So the producer always emits `MM/dd/yyyy
            # HH:mm:ss`, regardless of the operator's locale. Pin that,
            # because a "fix" that switches the producer to
            # `.ToString()` WOULD become culture-dependent and would start
            # emitting forms (e.g. ko-KR `2026. 9. 12. PM 6:11:22`) that the
            # skill cannot parse.
            $sample = [datetime]'2026-09-12T18:11:22'
            $rendered = $null
            $originalCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
            try {
                foreach ($cultureName in @('en-US', 'en-GB', 'de-DE', 'fr-FR', 'ja-JP', 'ko-KR', 'zh-CN')) {
                    [System.Threading.Thread]::CurrentThread.CurrentCulture =
                    [System.Globalization.CultureInfo]::GetCultureInfo($cultureName)
                    $line = "[$sample] : Starting Logger Instance"
                    $Script:consumer.Named['TimestampRegex'].IsMatch($line) |
                        Should -BeTrue -Because "TimestampRegex must match the logger's rendered prefix under culture '$cultureName' (line was '$line')"
                    if ($null -eq $rendered) { $rendered = $line } else {
                        $line | Should -Be $rendered -Because "the logger's rendered timestamp must stay culture-invariant; culture '$cultureName' produced a different form"
                    }
                }
            } finally {
                [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
            }
            $rendered | Should -Match '^\[09/12/2026 18:11:22\] : ' -Because "the invariant render is MM/dd/yyyy HH:mm:ss; a change here means the logger contract moved"
        }

        It "Get-NewLoggerInstance appends the _yyyyMMddHHmmss stamp the skill's debug-filename regex expects" {
            $hasFormat = Test-FileHasAssignmentLiteral -Path $Script:loggerPath `
                -FunctionName 'Get-NewLoggerInstance' -Literal '{0}_{1}.txt'
            $hasFormat | Should -BeTrue -Because "the skill's filename regex expects `<name>-Debug_<14 digits>`; changing the `_` join or the extension breaks run-ID grouping"
            $hasStamp = Test-FileHasAssignmentLiteral -Path $Script:loggerPath `
                -FunctionName 'Get-NewLoggerInstance' -Literal 'yyyyMMddHHmmss'
            $hasStamp | Should -BeTrue -Because "the skill's filename regex matches exactly 14 digits for the timestamp segment"
        }

        It "Write-LoggerInstance's rollover filename keeps the -<N> suffix the skill parses as RolloverOrdinal" {
            $hasRollover = Test-FileHasAssignmentLiteral -Path $Script:loggerPath `
                -FunctionName 'Write-LoggerInstance' `
                -Literal '$($LoggerInstance.BaseInstanceFileName)-$($LoggerInstance.Instance).txt'
            $hasRollover | Should -BeTrue -Because "the skill treats `-<N>` on a TIMESTAMPED debug filename as the rollover ordinal; changing this separator silently breaks multi-segment run grouping in Step 6"
        }
    }

    Context "HealthChecker version banners -> skill version regexes" {

        It "HealthChecker.ps1 emits 'Script Version: `$BuildVersion' and all three version regexes accept it" {
            $values = Get-CommandArgumentValues -Path $Script:healthCheckerPath -CommandName 'Write-Grey'
            $banner = @($values | Where-Object { $_ -ceq 'Script Version: $BuildVersion' })
            $banner.Count | Should -BeGreaterThan 0 -Because "HealthChecker.ps1 must keep emitting the canonical 'Script Version: ' preamble banner; the skill rejects every other version-shaped string"

            $resolved = 'Script Version: 26.10.02.1907'
            $Script:consumer.Named['CanonicalVersionRegex'].IsMatch($resolved) | Should -BeTrue -Because "the untimestamped preamble path uses CanonicalVersionRegex"
            $Script:consumer.Named['VersionRegex'].IsMatch($resolved) | Should -BeTrue -Because "the general scan path uses VersionRegex"
            $Script:consumer.Named['TimestampedVersionRegex'].IsMatch("[09/12/2026 18:11:22] : $resolved") | Should -BeTrue -Because "the timestamped log-line path uses TimestampedVersionRegex"
        }

        It "Invoke-HealthCheckerMainReport.ps1 emits 'Exchange Health Checker version `$BuildVersion' and all three version regexes accept it" {
            $values = Get-CommandArgumentValues -Path $Script:mainReportPath -CommandName 'Write-Green'
            $banner = @($values | Where-Object { $_ -ceq 'Exchange Health Checker version $BuildVersion' })
            $banner.Count | Should -BeGreaterThan 0 -Because "the in-report banner is the second repository-controlled version marker the skill allowlists"

            $resolved = 'Exchange Health Checker version 26.10.02.1907'
            $Script:consumer.Named['CanonicalVersionRegex'].IsMatch($resolved) | Should -BeTrue
            $Script:consumer.Named['VersionRegex'].IsMatch($resolved) | Should -BeTrue
            $Script:consumer.Named['TimestampedVersionRegex'].IsMatch("[09/12/2026 18:11:22] : $resolved") | Should -BeTrue
        }

        It "Invoke-HealthCheckerMainReport.ps1's Write-HostLog 'Version' capitalization is still accepted" {
            $values = Get-CommandArgumentValues -Path $Script:mainReportPath -CommandName 'Write-HostLog'
            $banner = @($values | Where-Object { $_ -ceq 'Exchange Health Checker Version $Script:BuildVersion' })
            $banner.Count | Should -BeGreaterThan 0 -Because "this capital-V variant is why the consumer scopes its label alternation case-insensitive"
            $Script:consumer.Named['CanonicalVersionRegex'].IsMatch('Exchange Health Checker Version 26.10.02.1907') | Should -BeTrue
        }
    }

    Context "HealthChecker debug filename -> skill Get-ScriptIdentityFromFilename regex" {

        It "HealthChecker.ps1 still names its debug log 'HealthChecker-Debug'" {
            $ast = Get-AstFromFile -Path $Script:healthCheckerPath
            $hit = $ast.Find({
                    param($n)
                    $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $n.Value -ceq 'HealthChecker-Debug'
                }, $true)
            $hit | Should -Not -BeNullOrEmpty -Because "the skill derives ScriptName/Confidence from the `<name>-Debug` filename shape; renaming the log makes ScriptName null and triggers the Step 1a early stop"
        }

        It "the skill's filename regex resolves a real timestamped HealthChecker debug filename to name + 14-digit stamp" {
            $base = 'HealthChecker-Debug_20260912181122'
            ($base -match $Script:debugFilenamePattern) | Should -BeTrue -Because "this is the exact base name produced by Get-NewLoggerInstance for LogName 'HealthChecker-Debug'"
            $Matches['name'] | Should -BeExactly 'HealthChecker'
            $Matches['ts'] | Should -BeExactly '20260912181122'
        }

        It "the skill's filename regex resolves a rolled-over segment to its ordinal" {
            $base = 'HealthChecker-Debug_20260912181122-3'
            ($base -match $Script:debugFilenamePattern) | Should -BeTrue
            $Matches['name'] | Should -BeExactly 'HealthChecker'
            $Matches['ord'] | Should -BeExactly '3'
        }

        It "the skill's filename regex rejects a numeric suffix on an UNTIMESTAMPED debug name" {
            # `HealthChecker-Debug-2` is not a rollover segment; grouping it
            # with `HealthChecker-Debug` would merge unrelated runs.
            ('HealthChecker-Debug-2' -match $Script:debugFilenamePattern) | Should -BeFalse
        }
    }

    Context "HiddenJobUnhandledErrorFunctions.ps1 remote labels -> skill CriticalFrameRegex" {

        # Remote records never go through the body-evidence pipeline, so these
        # label lines ARE the entire failure narrative for a remote failure.
        # They must survive the Context character budget. The remote emitter
        # uses labels that differ from local `$Error` formatting -- `Exception
        # Inner Exception:` not `Inner Exception:`, `Error Details Script Stack
        # Trace:` not `Script Stack:` -- which is exactly how they were being
        # silently dropped.

        It "every label literal WriteRemoteErrorInformation emits is retained by CriticalFrameRegex" {
            $labels = @(
                'Exception Message:',
                'Exception Inner Exception:',
                'Position Message:',
                'Error Category Activity:',
                'Error Category Reason:',
                'Error Category TargetName:',
                'Error Category TargetType:',
                'Error Category Message:',
                'Error Details Script Stack Trace:'
            )
            foreach ($label in $labels) {
                $producer = @($Script:remoteLiteralRecords | Where-Object {
                        $_.Function -eq 'WriteRemoteErrorInformation' -and $_.Value -clike "$label *"
                    })
                $producer.Count | Should -BeGreaterThan 0 -Because "WriteRemoteErrorInformation must still emit the '$label' label; Step 7's remote carve-out quotes these by name"
                $Script:criticalFrameRegex.IsMatch("$label some value") |
                    Should -BeTrue -Because "CriticalFrameRegex must retain the '$label' line under budget pressure, or the remote failure narrative is dropped from the report"
            }
        }

        It "CriticalFrameRegex retains the remote banner as well as the local one" {
            $Script:criticalFrameRegex.IsMatch('----------------Remote Error Information----------------') |
                Should -BeTrue -Because "the remote banner is only 16 dashes, so the generic -{20,} alternative does not cover it"
            $Script:criticalFrameRegex.IsMatch('----------------Error Information----------------') |
                Should -BeTrue -Because "the local banner must keep matching too"
        }

        It "CriticalFrameRegex still retains the local-error label forms" {
            # Guard against a resync that widens the remote labels but drops
            # the bare local ones.
            $Script:criticalFrameRegex.IsMatch('Inner Exception: System.Exception') | Should -BeTrue
            $Script:criticalFrameRegex.IsMatch('Script Stack:') | Should -BeTrue
            $Script:criticalFrameRegex.IsMatch('Position Message:') | Should -BeTrue
            $Script:criticalFrameRegex.IsMatch('FullyQualifiedErrorId : SomeId') | Should -BeTrue
        }
    }
}
