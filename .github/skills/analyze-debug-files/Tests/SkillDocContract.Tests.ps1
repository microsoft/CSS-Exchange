# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore Inotin

# Doc/code contract guard for the `.github/skills/analyze-debug-files/` skill.
#
# SKILL.md and reference/*.md instruct the agent to read specific property
# names off the objects returned by the skill's helpers. Those names are the
# skill's real API surface, and nothing else verifies them: markdown is not
# compiled, and the helpers are invoked by an LLM rather than by typed code.
#
# This guard caught a live bug on introduction -- SKILL.md documented
# `TerminationReason` while the parser emits `TerminationKind`, telling the
# agent to apply boundary inclusion rules keyed on a field that does not
# exist.
#
# Exercise the parser with a small log and check each returned object's own
# properties. Internal working objects cannot satisfy a missing output field.
# Graph and wrapper literals also have reverse-direction AST guards so a
# newly emitted-but-undocumented field fails.
#
# Scope limits, stated plainly so nobody over-trusts this file:
#   * The per-file / SummaryEvents documented-field list below is a curated
#     allowlist, NOT an extraction of every back-quoted token in the docs.
#     Prose contains plenty of back-quoted things that are not fields
#     (cmdlets, paths, literals), so a blind extraction would be unusable.
#     This guards producer-side drift and does NOT catch a brand-new field
#     being invented in the docs. The graph-result and inventory-wrapper
#     guards do not share this limitation -- they read the live AST shape of
#     one specific literal, anchored on a key it must always carry.
#   * Value-level guards (TerminationKind / ScriptNameConfidence /
#     MaterializationSource / Status) match the BACK-QUOTED form on purpose.
#     A bare substring match is vacuous for short values -- 'Ok' occurs inside
#     "Invoke", "token", and "lookup".
#   * Cross-skill guards cover only the contract analyze-debug-files actually
#     consumes from find-release-tag-for-script-version (the Status
#     vocabulary). The sibling skills' own output shapes are their own
#     suites' responsibility.

[CmdletBinding()]
param()

Describe "analyze-debug-files skill: documented fields exist on the helper contracts" {

    BeforeAll {
        $Script:repoRoot = (Get-Item "$PSScriptRoot\..\..\..\..").FullName
        $Script:skillDir = Join-Path $Script:repoRoot '.github\skills\analyze-debug-files'
        $Script:metadataPath = Join-Path $Script:skillDir 'Get-DebugFileMetadata.ps1'
        $Script:graphPath = Join-Path $Script:skillDir 'Get-BaselineDependencyGraph.ps1'
        $Script:skillMd = Join-Path $Script:skillDir 'SKILL.md'
        $Script:referenceDir = Join-Path $Script:skillDir 'reference'

        function Get-AstFromFile {
            param([Parameter(Mandatory)][string]$Path)
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$parseErrors)
            if ($parseErrors -and $parseErrors.Count -gt 0) {
                throw "Parse errors in ${Path}: $($parseErrors[0].Message)"
            }
            return $ast
        }

        function Get-DocText {
            # SKILL.md plus every reference file, concatenated. Drift can be
            # introduced in either place, so both are checked as one corpus.
            $files = @($Script:skillMd) + @(Get-ChildItem -LiteralPath $Script:referenceDir -Filter *.md |
                    ForEach-Object { $_.FullName })
            return (($files | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n")
        }

        function Get-PSCustomObjectLiteralKeys {
            # LIVE extraction of the keys on the `[PSCustomObject]@{...}`
            # literal(s) carrying a given anchor key. Isolating one object's
            # shape keeps unrelated internal objects out of the contract.
            #
            # Multiple matches are ALLOWED as long as they agree: a helper may
            # legitimately return the same shape from two branches. They are
            # only rejected when the shapes DIVERGE, which is the actual
            # defect -- a caller reading a field that exists on one branch and
            # not the other fails under Set-StrictMode.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$AnchorKey
            )
            $ast = Get-AstFromFile -Path $Path
            $converts = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.ConvertExpressionAst] -and
                    $n.Type.TypeName.Name -in @('PSCustomObject') -and
                    $n.Child -is [System.Management.Automation.Language.HashtableAst]
                }, $true)
            $matching = New-Object 'System.Collections.Generic.List[string[]]'
            foreach ($c in $converts) {
                $keys = New-Object 'System.Collections.Generic.List[string]'
                foreach ($kv in $c.Child.KeyValuePairs) {
                    $keyNode = $kv.Item1.Find({
                            param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                        }, $true)
                    if ($keyNode) { $keys.Add($keyNode.Value) }
                }
                if ($keys -ccontains $AnchorKey) { $matching.Add($keys.ToArray()) }
            }
            if ($matching.Count -eq 0) {
                throw "Found no [PSCustomObject] literal in $Path carrying key '$AnchorKey'."
            }
            $shapes = @($matching | ForEach-Object { ($_ | Sort-Object) -join ',' } | Sort-Object -Unique)
            if ($shapes.Count -gt 1) {
                throw ("The $($matching.Count) [PSCustomObject] literals in $Path carrying '$AnchorKey' " +
                    "have DIVERGENT shapes, so a caller cannot read the same fields off both: " +
                    ($shapes -join ' || '))
            }
            return $matching[0]
        }

        function Get-DocSection {
            # The text of one markdown section, from a heading matching
            # $HeadingPattern up to the next heading at the same-or-higher
            # level. Guards that claim to check a specific table must look at
            # THAT table -- checking the whole document lets an unrelated
            # passage elsewhere satisfy them.
            param(
                [Parameter(Mandatory)][string]$Text,
                [Parameter(Mandatory)][string]$HeadingPattern
            )
            $lines = $Text -split "`r?`n"
            $start = -1
            $level = 0
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match "^(#{1,6})\s+.*$HeadingPattern") {
                    $start = $i
                    $level = $Matches[1].Length
                    break
                }
            }
            if ($start -lt 0) { return '' }
            $out = New-Object System.Collections.Generic.List[string]
            for ($i = $start + 1; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^(#{1,6})\s' -and $Matches[1].Length -le $level) { break }
                $out.Add($lines[$i])
            }
            return ($out -join "`n")
        }

        function Get-StatusValuesFromReturnedObjects {
            # Every string literal assigned to a `Status` key on a returned
            # [PSCustomObject] literal, PLUS the literals of any variable that
            # a `Status` key references. This reads the actual emitted
            # contract rather than trusting a variable NAME, so a future
            # `Status = 'match-new'` written inline is still captured.
            param([Parameter(Mandatory)][string]$Path)
            $ast = Get-AstFromFile -Path $Path
            $values = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            $varNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $tables = $ast.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.HashtableAst]
                }, $true)
            foreach ($t in $tables) {
                foreach ($kv in $t.KeyValuePairs) {
                    $keyNode = $kv.Item1.Find({
                            param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                        }, $true)
                    if (-not $keyNode -or $keyNode.Value -cne 'Status') { continue }
                    foreach ($lit in $kv.Item2.FindAll({
                                param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                            }, $true)) {
                        [void]$values.Add($lit.Value)
                    }
                    foreach ($v in $kv.Item2.FindAll({
                                param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst]
                            }, $true)) {
                        [void]$varNames.Add($v.VariablePath.UserPath)
                    }
                }
            }
            foreach ($name in $varNames) {
                foreach ($v in (Get-AssignedStringLiterals -Path $Path -VariableName $name)) {
                    [void]$values.Add($v)
                }
            }
            return @($values | Sort-Object)
        }

        function Get-NotInAllowlist {
            # AST-extract the right-hand array literal of a
            # `<Left> -notin @('a','b')` expression, selected by the text of
            # its left operand. A raw source regex cannot tell code from a
            # comment, cannot survive reformatting, and cannot handle nesting.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$LeftOperandText
            )
            $ast = Get-AstFromFile -Path $Path
            $expr = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and
                    $n.Operator -eq [System.Management.Automation.Language.TokenKind]::Inotin -and
                    $n.Left.Extent.Text -eq $LeftOperandText
                }, $true) | Select-Object -First 1
            if (-not $expr) {
                throw "Found no '-notin' expression in $Path whose left operand is '$LeftOperandText'."
            }
            $literals = $expr.Right.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                }, $true)
            return @(@($literals | ForEach-Object { $_.Value }) | Sort-Object)
        }

        function Get-FunctionReturnedKeyValues {
            # String literals assigned to $KeyName on any hashtable literal
            # inside the named function. Scoping to the function stops an
            # unrelated same-named key elsewhere in the file from widening or
            # masking the value domain.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$FunctionName,
                [Parameter(Mandatory)][string]$KeyName
            )
            $ast = Get-AstFromFile -Path $Path
            $fn = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $n.Name -eq $FunctionName
                }, $true) | Select-Object -First 1
            if (-not $fn) { throw "$Path does not define function $FunctionName." }
            $values = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($t in $fn.FindAll({
                        param($n) $n -is [System.Management.Automation.Language.HashtableAst]
                    }, $true)) {
                foreach ($kv in $t.KeyValuePairs) {
                    $keyNode = $kv.Item1.Find({
                            param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                        }, $true)
                    if (-not $keyNode -or $keyNode.Value -cne $KeyName) { continue }
                    foreach ($lit in $kv.Item2.FindAll({
                                param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                            }, $true)) {
                        [void]$values.Add($lit.Value)
                    }
                }
            }
            return @($values | Sort-Object)
        }

        function Get-AssignedStringLiterals {
            # Every string literal assigned to $VariableName anywhere in the
            # file, including inside `if (...) { 'a' } else { 'b' }` value
            # expressions. Used to pin a producer's emitted value vocabulary.
            param(
                [Parameter(Mandatory)][string]$Path,
                [Parameter(Mandatory)][string]$VariableName
            )
            $ast = Get-AstFromFile -Path $Path
            $assigns = $ast.FindAll({
                    param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst]
                }, $true)
            $values = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($a in $assigns) {
                $lhs = $a.Left.Find({
                        param($n)
                        $n -is [System.Management.Automation.Language.VariableExpressionAst] -and
                        $n.VariablePath.UserPath -eq $VariableName
                    }, $true)
                if (-not $lhs) { continue }
                $literals = $a.Right.FindAll({
                        param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $true)
                foreach ($l in $literals) { [void]$values.Add($l.Value) }
            }
            return [string[]]$values
        }

        $Script:fixtureRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("SkillContractTests-" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $Script:fixtureRoot -ItemType Directory | Out-Null
        $logPath = Join-Path -Path $Script:fixtureRoot -ChildPath 'HealthChecker-Debug_20261028064600.txt'
        $lines = @(
            '[10/28/2026 06:46:00] : Script Version: 26.09.14.1957'
            '[10/28/2026 06:46:01] : Trying to inspect the server'
            '[10/28/2026 06:46:02] : Failed to inspect: System.InvalidOperationException'
            '[10/28/2026 06:46:02] : Calling: Invoke-CatchActions'
            '-----Errors that were handled-----'
            '[10/28/2026 06:46:03] : Error Index: 0'
            'Inner Exception: System.InvalidOperationException'
            '[10/28/2026 06:46:03] : ----------------------------------'
            "----Errors that occurred that wasn't handled----"
            '[10/28/2026 06:46:04] : Error Index: 1'
            'Script Stack: at Get-Example, C:\scripts\HealthChecker.ps1: line 123'
            '[10/28/2026 06:46:04] : ----------------------------------'
        )
        [System.IO.File]::WriteAllLines($logPath, $lines, [System.Text.UTF8Encoding]::new($true))
        $emptyPath = Join-Path -Path $Script:fixtureRoot -ChildPath 'HealthChecker-Debug_20261028064601.txt'
        [System.IO.File]::WriteAllBytes($emptyPath, [byte[]]@())
        $inventory = & $Script:metadataPath -DebugDirectory $Script:fixtureRoot
        $parsedFile = @($inventory.Files | Where-Object -Property Status -EQ -Value 'Parsed')
        $skippedFile = @($inventory.Files | Where-Object -Property Status -EQ -Value 'Empty')
        if ($parsedFile.Count -ne 1 -or $skippedFile.Count -ne 1) {
            throw 'The contract fixture must produce one parsed file and one skipped file.'
        }
        $Script:metadataContracts = @{
            File                = @($parsedFile[0].PSObject.Properties.Name)
            SkippedFile         = @($skippedFile[0].PSObject.Properties.Name)
            Summary             = @($parsedFile[0].Summary.PSObject.Properties.Name)
            SummaryEvents       = @($parsedFile[0].SummaryEvents[0].PSObject.Properties.Name)
            InlineEvents        = @($parsedFile[0].InlineEvents[0].PSObject.Properties.Name)
            BodyEvidenceMarkers = @($parsedFile[0].BodyEvidenceMarkers[0].PSObject.Properties.Name)
            CompletionSignals   = @($parsedFile[0].CompletionSignals[0].PSObject.Properties.Name)
        }
        $Script:graphFields = @(Get-PSCustomObjectLiteralKeys -Path $Script:graphPath -AnchorKey 'MaterializationSource')
        $Script:docText = Get-DocText
        # SKILL.md alone. The Get-BaselineDependencyGraph contract is documented
        # in SKILL.md Step 5 and nowhere else, so its guards must be scoped to
        # that file. Checking the whole corpus lets an unrelated passage satisfy
        # them -- `reference/step7_5-related-context.md` discusses the SIBLING
        # skills' `Ok` / non-`Ok` statuses, which would mask the removal of the
        # graph helper's own Status documentation.
        $Script:skillText = Get-Content -LiteralPath $Script:skillMd -Raw
    }

    AfterAll {
        Remove-Item -LiteralPath $Script:fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Context "Get-DebugFileMetadata.ps1 documented fields" {

        It "emits the documented fields on the returned <Contract> object" -ForEach @(
            @{
                Contract = 'File'
                Fields   = @(
                    'File', 'Status', 'StatusDetail', 'ScriptName', 'ScriptNameConfidence',
                    'RunId', 'RolloverOrdinal', 'VersionCandidates', 'StartTime', 'EndTime',
                    'Summary', 'SummaryEvents', 'SummaryEventsTruncated',
                    'HandledEventsTruncated', 'UnhandledEventsTruncated',
                    'CompletionSignals', 'InlineEvents', 'InlineEventsTruncated', 'BodyEvidenceMarkers',
                    'BodyEvidenceMarkersTruncated', 'AnyLineTruncated',
                    'MultipleSummaryBlocksDetected', 'MultipleRunsDetected', 'DetectedEncoding', 'SizeBytes', 'LineCount'
                )
            }
            @{
                Contract = 'Summary'
                Fields   = @(
                    'HandledCount', 'UnhandledCount', 'StartLine',
                    'HandledHeaderLine', 'HandledFooterLine',
                    'UnhandledHeaderLine', 'UnhandledFooterLine',
                    'RemoteUnhandledSectionSeen', 'RemoteUnhandledFooterLine',
                    'SummaryComplete', 'FooterSeen'
                )
            }
            @{
                Contract = 'SummaryEvents'
                Fields   = @(
                    'LineNumber', 'Timestamp', 'HeadLine', 'Context', 'ContextLineNumbers',
                    'IsHandled', 'IsRemoteRecord', 'ContextTruncated',
                    'OriginalStartLine', 'OriginalEndLine', 'OmittedLineCount',
                    'TruncatedLineNumbers', 'LinesCharacterTruncated',
                    'TerminationLineNumber', 'TerminationLineText', 'TerminationKind',
                    'RequiredFenceLength'
                )
            }
            @{
                Contract = 'InlineEvents'
                Fields   = @('LineNumber', 'Timestamp', 'HeadLine', 'Context', 'IsHandled', 'RequiredFenceLength')
            }
            @{
                Contract = 'BodyEvidenceMarkers'
                Fields   = @('LineNumber', 'Timestamp', 'Text', 'MarkerKind', 'Truncated')
            }
            @{
                Contract = 'CompletionSignals'
                Fields   = @('Name', 'LineNumber')
            }
        ) {
            $missing = @($Fields | Where-Object { $Script:metadataContracts[$Contract] -cnotcontains $_ })
            $missing -join ', ' | Should -BeExactly '' -Because "the agent reads these fields from this returned object, not from an internal working object"
        }

        It "returns the same per-file properties for parsed and skipped files" {
            ($Script:metadataContracts.File | Sort-Object) -join ',' |
                Should -BeExactly (($Script:metadataContracts.SkippedFile | Sort-Object) -join ',')
        }

        It "emits an identical shape from both per-file result literals" {
            # `Read-DebugFile` (parsed files) and `Get-EmptyFileResult`
            # (Empty / Oversize / Unreadable / UnsupportedFormat files) both
            # produce entries for `$inventory.Files`, and the runner reads the
            # same properties off either. If one grows or renames a field
            # without the other, a skipped file is missing a property the
            # runner dereferences -- which under `Set-StrictMode -Version 3.0`
            # is a terminating error mid-analysis rather than a quiet $null.
            #
            # Check every per-file literal in addition to the exercised paths.
            $ast = Get-AstFromFile -Path $Script:metadataPath
            $converts = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.ConvertExpressionAst] -and
                    $n.Type.TypeName.Name -in @('PSCustomObject') -and
                    $n.Child -is [System.Management.Automation.Language.HashtableAst]
                }, $true)
            $perFile = @()
            foreach ($c in $converts) {
                $keys = New-Object 'System.Collections.Generic.List[string]'
                foreach ($kv in $c.Child.KeyValuePairs) {
                    $keyNode = $kv.Item1.Find({
                            param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
                        }, $true)
                    if ($keyNode) { $keys.Add($keyNode.Value) }
                }
                if ($keys -ccontains 'MultipleSummaryBlocksDetected') {
                    $perFile += , (($keys | Sort-Object) -join ',')
                }
            }
            $perFile.Count | Should -Be 2 -Because "exactly two literals build a per-file inventory entry: Read-DebugFile's success return and Get-EmptyFileResult's skip return"
            $perFile[0] | Should -BeExactly $perFile[1] -Because "a field present on one per-file result but not the other breaks the runner under Set-StrictMode when it reads that property off a skipped file"
        }

        It "does not document a TerminationReason field, because the parser emits TerminationKind" {
            # Regression guard for the exact bug this file was created to catch.
            ($Script:metadataContracts.SummaryEvents -ccontains 'TerminationKind') | Should -BeTrue
            ($Script:metadataContracts.SummaryEvents -ccontains 'TerminationReason') | Should -BeFalse
            $Script:docText | Should -Not -Match 'TerminationReason' -Because "the emitted field is TerminationKind; documenting TerminationReason makes the Step 6/7 boundary inclusion rules unresolvable"
        }

        It "documents the TerminationKind values the parser can actually assign" {
            $assigned = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($m in [regex]::Matches((Get-Content -LiteralPath $Script:metadataPath -Raw),
                    "TerminationKind\s*=\s*'([A-Za-z]+)'")) {
                [void]$assigned.Add($m.Groups[1].Value)
            }
            $assigned.Count | Should -BeGreaterThan 0
            foreach ($value in $assigned) {
                # Back-quoted match: 'Footer' and 'EOF' both occur in ordinary
                # prose ("unhandled footer", "ran to EOF"), so a bare substring
                # match would pass even if the value were undocumented.
                $Script:docText | Should -Match ('`' + [regex]::Escape($value) + '`') -Because "TerminationKind value '$value' is reachable in the parser, so the inclusive/exclusive rules in reference/inventory-fields.md must account for it"
            }
        }

        It "documents the ScriptNameConfidence values the parser can actually assign, and no others" {
            # Step 1a's early-stop predicate keys on this value domain, so a
            # documented-but-unreachable level (the docs carried `Medium` for
            # several iterations while the parser only ever emitted High/None)
            # sends the agent looking for a state that cannot occur, and an
            # undocumented new level silently falls through the predicate.
            #
            # AST-scoped to the producing function: a raw source regex would
            # miss a double-quoted or computed value while the existing
            # single-quoted matches kept the exact-domain assertion green.
            $assigned = @(Get-FunctionReturnedKeyValues -Path $Script:metadataPath `
                    -FunctionName 'Get-ScriptIdentityFromFilename' -KeyName 'Confidence')
            ($assigned -join ',') | Should -BeExactly 'High,None' -Because "SKILL.md Step 1a and reference/inventory-fields.md both state the domain is exactly High|None; adding or removing a level must land in the same change as the docs"
            $Script:docText | Should -Not -Match '`Medium`' -Because "the parser never emits a Medium confidence; documenting one makes the Step 1a early-stop predicate test for an unreachable state"
            $Script:docText | Should -Not -Match 'High \| Medium' -Because "the same unreachable level must not survive in prose form either"
        }

        It "documents every field on the inventory wrapper object" {
            # Live AST shape of the wrapper -- `$inventory.DebugDirectory` is
            # Step 8's write target and `$inventory.Files` is the whole
            # per-file surface, so a silent rename here breaks the workflow at
            # its two widest joints.
            $emitted = @(Get-PSCustomObjectLiteralKeys -Path $Script:metadataPath -AnchorKey 'EnumerationSucceeded')
            $undocumented = @($emitted |
                    Where-Object { $_ -ne 'PSTypeName' } |
                    Where-Object { $Script:skillText -notmatch ('`\.?' + [regex]::Escape($_) + '`') })
            $undocumented -join ', ' | Should -BeExactly '' -Because "SKILL.md Step 1 lists the wrapper's fields; a rename must update both sides"
        }
    }

    Context "Get-BaselineDependencyGraph.ps1 documented fields" {

        It "emits every field SKILL.md Step 5 documents" {
            $documented = @(
                'Entry', 'AllDeps', 'HasErrorHelper', 'MaterializationSource',
                'BaselineSha', 'BaselineTag', 'Status', 'StatusDetail'
            )
            $missing = @($documented | Where-Object { $Script:graphFields -cnotcontains $_ })
            $missing -join ', ' | Should -BeExactly '' -Because "Step 5 tells the agent to read these off the returned object"
        }

        It "documents every field the helper actually returns" {
            # Reverse direction: an emitted-but-UNdocumented field means the
            # agent never learns about data it may need.
            #
            # This MUST read the live AST shape of the returned object. An
            # earlier version intersected the AST set with a hardcoded list,
            # which meant a brand-new field was filtered out before the
            # assertion ever saw it -- the guard could only re-check fields
            # someone had already thought of, which is the opposite of a drift
            # guard. `Get-PSCustomObjectLiteralKeys` reconstructs the exact
            # returned object instead, anchored on a key it must always carry.
            $emitted = @(Get-PSCustomObjectLiteralKeys -Path $Script:graphPath -AnchorKey 'MaterializationSource')
            $emitted.Count | Should -BeGreaterThan 0 -Because "the AST extraction must actually see the returned object's properties"
            # Scope to the Step 5 section. Checking the whole document lets an
            # unrelated mention elsewhere (Step 8 also names
            # `MaterializationSource`) satisfy a guard that claims to protect
            # Step 5's returned-fields table.
            $step5 = Get-DocSection -Text $Script:skillText -HeadingPattern 'Step 5'
            $step5 | Should -Not -BeNullOrEmpty -Because "the Step 5 section must be findable for this guard to mean anything"
            $undocumented = @($emitted | Where-Object { $step5 -notmatch ('`' + [regex]::Escape($_) + '`') })
            $undocumented -join ', ' | Should -BeExactly '' -Because "SKILL.md Step 5's returned-fields table must stay complete"
        }

        It "documents every MaterializationSource value the helper can return" {
            $raw = Get-Content -LiteralPath $Script:graphPath -Raw
            $values = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($m in [regex]::Matches($raw, "materializationSource\s*=\s*'([A-Za-z]+)'")) {
                [void]$values.Add($m.Groups[1].Value)
            }
            $values.Count | Should -BeGreaterThan 0
            foreach ($value in $values) {
                # Match the BACK-QUOTED form. A bare substring match is vacuous
                # for short values -- e.g. 'Ok' occurs inside "Invoke", "token",
                # and "lookup", so the guard would pass even if the value were
                # removed from the docs entirely.
                $Script:skillText | Should -Match ('`' + [regex]::Escape($value) + '`') -Because "'$value' is stamped on the report header, so SKILL.md must name it"
            }
        }

        It "documents every Status value the helper can return" {
            $raw = Get-Content -LiteralPath $Script:graphPath -Raw
            $values = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($m in [regex]::Matches($raw, "\`$status\s*=\s*'([A-Za-z]+)'")) {
                [void]$values.Add($m.Groups[1].Value)
            }
            $values.Count | Should -BeGreaterThan 0
            foreach ($value in $values) {
                $Script:skillText | Should -Match ('`' + [regex]::Escape($value) + '`') -Because "Status value '$value' changes what the agent must disclose"
            }
        }
    }

    Context "Documented helper parameters exist" {

        It "every -Max* parameter named in the docs exists on Get-DebugFileMetadata.ps1" {
            $ast = Get-AstFromFile -Path $Script:metadataPath
            $actual = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($p in $ast.ParamBlock.Parameters) {
                [void]$actual.Add($p.Name.VariablePath.UserPath)
            }
            $referenced = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($m in [regex]::Matches($Script:docText, '`-(Max[A-Za-z]+)`')) {
                [void]$referenced.Add($m.Groups[1].Value)
            }
            $missing = @($referenced | Where-Object { -not $actual.Contains($_) })
            $missing -join ', ' | Should -BeExactly '' -Because "the docs tell the operator to re-run the helper with these switches"
        }

        It "names every executable helper in the skill directory in SKILL.md" {
            # The helper table is how the agent discovers what it may run. A
            # new .ps1 that nothing links to is dead weight; a renamed one
            # leaves the agent invoking a path that does not exist.
            $helpers = @(Get-ChildItem -LiteralPath $Script:skillDir -Filter *.ps1 -File |
                    ForEach-Object { $_.Name })
            $helpers.Count | Should -BeGreaterThan 0
            $unlisted = @($helpers | Where-Object { $Script:skillText -notmatch ('`' + [regex]::Escape($_) + '`') })
            $unlisted -join ', ' | Should -BeExactly '' -Because "SKILL.md's executable-helpers table must list every .ps1 beside it"
        }
    }

    Context "Reference-file integrity" {

        # SKILL.md's reference table is the only index of the on-demand
        # material. Neither direction was previously guarded: a renamed file
        # left a row pointing at a dead path, and a new file nothing linked to
        # was never read.

        It "every reference/*.md path cited anywhere in the docs exists on disk" {
            $cited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($m in [regex]::Matches($Script:docText, 'reference/([A-Za-z0-9._\-]+\.md)')) {
                [void]$cited.Add($m.Groups[1].Value)
            }
            $cited.Count | Should -BeGreaterThan 0 -Because "the extraction must actually find the citations"
            $missing = @($cited | Where-Object {
                    -not (Test-Path -LiteralPath (Join-Path $Script:referenceDir $_) -PathType Leaf)
                })
            $missing -join ', ' | Should -BeExactly '' -Because "a cited reference file that does not exist sends the agent to a dead path mid-run"
        }

        It "every reference/*.md on disk is linked from SKILL.md" {
            $onDisk = @(Get-ChildItem -LiteralPath $Script:referenceDir -Filter *.md -File |
                    ForEach-Object { $_.Name })
            $onDisk.Count | Should -BeGreaterThan 0
            $orphans = @($onDisk | Where-Object { $Script:skillText -notmatch ('reference/' + [regex]::Escape($_)) })
            $orphans -join ', ' | Should -BeExactly '' -Because "an unlinked reference file is never loaded, so its content silently stops applying"
        }
    }

    Context "Report evidence rendering contracts" {

        It "groups operation markers into invocation candidates before counting" {
            $correlation = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'step7-source-correlation.md') -Raw
            $grouping = [regex]::Match($correlation, '(?s)\*\*Invocation grouping.*?\*\*Local summary records').Value -replace '\s+', ' '

            $grouping | Should -Match 'Count invocation candidates, not individual markers'
            $grouping | Should -Match 'A `TryingTo` and its paired `FailedTo` count as one invocation candidate'
            $grouping | Should -Match 'An unpaired `TryingTo` or `FailedTo` remains a partial invocation candidate'
            $grouping | Should -Match 'Do not merge markers based only on proximity'
            $grouping | Should -Match 'before applying either the local-summary rules or inline-event windows'
        }

        It "does not treat summary reporting time as proof of the failing invocation" {
            $correlation = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'step7-source-correlation.md') -Raw
            $localRule = [regex]::Match($correlation, '(?s)\*\*Local summary records.*?\*\*Inline-only events').Value -replace '\s+', ' '

            $localRule | Should -Match 'Do NOT use it to exclude earlier operation candidates'
            $localRule | Should -Match 'require exception/stack identity'
            $localRule | Should -Match 'Missing or truncated context is NOT conflicting evidence'
            $localRule | Should -Match 'Unresolved — ambiguous correlation'
            $localRule | Should -Match 'do NOT run Phase A / Phase B on local summary records'
        }

        It "renders one summary seed only for resolved correlations" {
            $correlation = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'step7-source-correlation.md') -Raw
            $resolved = [regex]::Match($correlation, '(?s)\*\*Resolved case:\*\*(.*?)\*\*Ambiguous case:\*\*').Groups[1].Value -replace '\s+', ' '
            $ambiguous = [regex]::Match($correlation, '(?s)\*\*Ambiguous case:\*\*(.*?)\*\*Inline-only events').Groups[1].Value -replace '\s+', ' '

            $resolved | Should -Match 'only when the rules above select one invocation'
            $resolved | Should -Match 'render its seed and grouped operation markers'
            $resolved | Should -Match 'only when those lines were retained'
            $ambiguous | Should -Match 'disclose every remaining invocation candidate'
            $ambiguous | Should -Match 'without selecting a seed'
            $ambiguous | Should -Match 'Skip per-seed catch inference in step 5'
        }

        It "allows missing marker neighborhoods without inventing log evidence" {
            $directory = Join-Path -Path $Script:fixtureRoot -ChildPath 'marker-context'
            New-Item -Path $directory -ItemType Directory | Out-Null
            $path = Join-Path -Path $directory -ChildPath 'HealthChecker-Debug_20261028064605.txt'
            $lines = @(
                '[10/28/2026 06:46:05] : Trying to collect operation information'
                '[10/28/2026 06:46:05] : uncollected neighbor text'
            ) + @(1..35 | ForEach-Object { '[10/28/2026 06:46:06] : diagnostic detail ' + $_ }) + @(
                '[10/28/2026 06:46:07] : Exception: synthetic failure'
            )
            [System.IO.File]::WriteAllLines($path, $lines, [System.Text.UTF8Encoding]::new($true))
            $inventory = & $Script:metadataPath -DebugDirectory $directory -SnippetContextLines 3
            $file = $inventory.Files[0]
            $retained = @($file.BodyEvidenceMarkers.Text) + @($file.InlineEvents | ForEach-Object { $_.Context })

            @($file.BodyEvidenceMarkers | Where-Object -Property MarkerKind -EQ -Value 'TryingTo').Count | Should -Be 1
            $file.InlineEvents | Should -Not -BeNullOrEmpty
            ($retained -join "`n") | Should -Not -Match 'uncollected neighbor text'
            $file.BodyEvidenceMarkersTruncated | Should -BeFalse
            $file.InlineEventsTruncated | Should -BeFalse
            $file.AnyLineTruncated | Should -BeFalse

            $correlation = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'step7-source-correlation.md') -Raw
            $correlation | Should -Match 'Context unavailable — not retained by inventory'
            $correlation | Should -Not -Match '5 lines before through|10 lines after each marker'
            $correlation | Should -Match 'same retained-lines-only rule'
        }

        It "does not infer incomplete finalization from a trailer-only rollover segment: <TerminalKind>" -ForEach @(
            @{ TerminalKind = 'Summary' }
            @{ TerminalKind = 'NoErrorsMessage' }
        ) {
            $directory = Join-Path -Path $Script:fixtureRoot -ChildPath ("rollover-" + $TerminalKind)
            New-Item -Path $directory -ItemType Directory | Out-Null
            $firstPath = Join-Path -Path $directory -ChildPath 'HealthChecker-Debug_20261028064605.txt'
            $lastPath = Join-Path -Path $directory -ChildPath 'HealthChecker-Debug_20261028064605-1.txt'
            $lines = if ($TerminalKind -eq 'Summary') {
                @(
                    '-----Errors that were handled-----'
                    '[10/28/2026 06:46:05] : ----------------------------------'
                    "----Errors that occurred that wasn't handled----"
                    '[10/28/2026 06:46:05] : ----------------------------------'
                )
            } else {
                @('[10/28/2026 06:46:05] : No errors occurred in the script.')
            }
            $lines += '[10/28/2026 06:46:05] : Max file size reached rolling over'
            [System.IO.File]::WriteAllLines($firstPath, $lines, [System.Text.UTF8Encoding]::new($true))
            [System.IO.File]::WriteAllLines($lastPath, @('[10/28/2026 06:46:06] : The total script time took 1 seconds'), [System.Text.UTF8Encoding]::new($true))
            $inventory = & $Script:metadataPath -DebugDirectory $directory
            $files = @($inventory.Files | Sort-Object -Property RolloverOrdinal)

            $files.Count | Should -Be 2
            $files[0].RunId | Should -BeExactly $files[1].RunId
            $files[1].Summary | Should -BeNullOrEmpty
            $files[1].CompletionSignals | Should -BeNullOrEmpty
            if ($TerminalKind -eq 'Summary') {
                $files[0].Summary.HandledFooterLine | Should -BeGreaterThan 0
                $files[0].Summary.UnhandledFooterLine | Should -BeGreaterThan 0
                $files[0].Summary.SummaryComplete | Should -BeFalse
            } else {
                @($files[0].CompletionSignals | Where-Object -Property Name -EQ -Value 'NoErrorsMessage').Count | Should -Be 0
            }

            $completion = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'step6-completion.md') -Raw
            $rollover = [regex]::Match($completion, '(?s)\*\*Rollover grouping\.\*\*(.*?)\*\*Remote-section rollover caveat').Groups[1].Value -replace '\s+', ' '
            $rollover | Should -Match 'Unknown — finalization may span rollover segments'
            $rollover | Should -Match 'Do not infer CRITICAL or DID NOT COMPLETE merely because'
            $rollover | Should -Not -Match 'earlier segments never carry'
        }

        It "offers a clean-completion banner without claiming summary footers on the no-errors path" {
            $template = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'report-format.md') -Raw
            $banner = @($template -split "`r?`n" | Where-Object {
                    $_ -match '^>.*\*\*Completed cleanly\*\*' -and $_ -match 'NoErrorsMessage'
                })

            $banner.Count | Should -Be 1
            $banner[0] | Should -Match 'no summary block is expected'
            $banner[0] | Should -Not -Match 'footer|Summary block complete'
        }

        It "separates redaction from the inline and multiline encoding paths" {
            $authoring = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'step8-report-authoring.md') -Raw
            $rule = [regex]::Match($authoring, '(?s)\*\*Redaction pre-encoding\.\*\*(.*?)\*\*Trust banner').Groups[1].Value -replace '\s+', ' '

            $rule | Should -Match 'before either encoding path'
            $rule | Should -Match 'ConvertTo-DebugReportScalar'
            $rule | Should -Match 'do not wrap or encode its returned element again'
            $rule | Should -Match 'HTML-encode the redacted text and place it in `<pre><code>`'
            $rule | Should -Match 'do not pass multiline evidence through the scalar renderer'
            $rule | Should -Not -Match 'renderer BEFORE HTML/Markdown encoding'
        }

        It "can compile every documented post-render redaction pattern and detect an encoded profile path" {
            $authoring = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'step8-report-authoring.md') -Raw
            $assertions = [regex]::Match($authoring, '(?s)\*\*Redaction assertion \(post-render\)\.\*\*(.*)').Groups[1].Value
            $patterns = @([regex]::Matches($assertions, '(?m)^\s+- `([^`\r\n]+)`') |
                    ForEach-Object { $_.Groups[1].Value })
            $patterns | Should -Not -BeNullOrEmpty
            foreach ($pattern in $patterns) {
                { [regex]::new($pattern) } | Should -Not -Throw
            }
            . (Join-Path -Path $Script:skillDir -ChildPath 'ConvertTo-DebugReportScalar.ps1')
            $rendered = ConvertTo-DebugReportScalar -RedactedText 'C:\Users\sample\log.txt'
            $decoded = [System.Net.WebUtility]::HtmlDecode($rendered)

            $decoded | Should -Match $patterns[0]
            'c:\users\sample\log.txt' | Should -Match $patterns[0]
            'C:\Scripts\HealthChecker.ps1' | Should -Not -Match $patterns[0]
        }

        It "sorts a new unmarked cache entry ahead of an older marked entry" {
            $cacheDoc = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'dependency-cache.md') -Raw
            $cleanup = [regex]::Matches($cacheDoc, '(?s)```powershell\s+(.*?)```')[1].Groups[1].Value
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($cleanup, [ref]$null, [ref]$parseErrors)
            $parseErrors | Should -BeNullOrEmpty
            $sort = $ast.Find({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName() -eq 'Sort-Object'
                }, $true)
            $sort | Should -Not -BeNullOrEmpty
            $sortEntries = [ScriptBlock]::Create('param($Entries) $Entries | ' + $sort.Extent.Text)
            $newEntry = New-Item -Path (Join-Path -Path $Script:fixtureRoot -ChildPath 'new-cache') -ItemType Directory
            $oldEntry = New-Item -Path (Join-Path -Path $Script:fixtureRoot -ChildPath 'old-cache') -ItemType Directory
            $marker = New-Item -Path (Join-Path -Path $oldEntry.FullName -ChildPath '.last-accessed') -ItemType File
            $marker.LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(-1)

            $sorted = @(& $sortEntries -Entries @($oldEntry, $newEntry))

            $sorted[0].Name | Should -BeExactly 'new-cache'
            $sorted[1].Name | Should -BeExactly 'old-cache'
        }

        It "uses code elements instead of backtick spans for untrusted filename placeholders" {
            $template = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'report-format.md') -Raw

            $template | Should -Not -Match '`<(?:name(?:-2\.txt)?|RunId\d*|file|filename)>`'
        }

        It "places inline body evidence in an HTML block rather than a fixed Markdown fence" {
            $template = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'report-format.md') -Raw
            $body = [regex]::Match($template, '(?s)\*\*Inline body evidence\*\*(.*?)\*\*Full exception record\*\*').Groups[1].Value

            $body | Should -Match '<pre><code>'
            $body | Should -Match '</code></pre>'
            $body | Should -Not -Match '(?m)^```'
        }

        It "carries remote record boundaries into the report authoring instructions" {
            $authoring = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'step8-report-authoring.md') -Raw
            $fidelity = [regex]::Match($authoring, '(?s)\*\*Exception fidelity\.\*\*(.*?)\*\*Filename fidelity\.\*\*').Groups[1].Value

            $fidelity | Should -Match 'Remote Error Information'
            $fidelity | Should -Match 'NextRemoteRecord'
            $fidelity | Should -Match 'EXCLUSIVE'
        }
    }

    Context "Related-context report integration" {

        It "requires context confirmation before closing an exception-phrase match as a duplicate" {
            $relatedSkillPath = Join-Path -Path $Script:repoRoot -ChildPath '.github\skills\find-related-github-issues\SKILL.md'
            $relatedSkill = Get-Content -LiteralPath $relatedSkillPath -Raw
            $classification = Get-DocSection -Text $relatedSkill -HeadingPattern 'Classification$'
            $classification = $classification -replace '\s+', ' '

            $classification | Should -Match 'candidate duplicate'
            $classification | Should -Match 'confirm the same failure context or root cause'
            $classification | Should -Match 'Phrase matches alone never justify closure'
            $classification | Should -Not -Match 'without further discussion'
        }

        It "places both sibling-skill outputs and their failure rules under Cause" {
            $template = Get-Content -LiteralPath (Join-Path -Path $Script:referenceDir -ChildPath 'report-format.md') -Raw
            $cause = Get-DocSection -Text $template -HeadingPattern 'Cause$'

            $cause | Should -Match ([regex]::Escape('**Related issues**'))
            $cause | Should -Match ([regex]::Escape('**When this code was introduced**'))
            $cause | Should -Match 'PartialLookup'
            $cause | Should -Match 'Lookup unavailable'
            $cause | Should -Match ([regex]::Escape('Provenance.Availability'))
            $cause | Should -Match ([regex]::Escape('RegressionAssessment.Verdict'))
        }
    }

    Context "Cross-skill contract: find-release-tag-for-script-version" {

        # `Assert-BaselineTrusted.ps1` hard-refuses any baseline whose Status
        # is not in its allowlist. Those literals are produced by a DIFFERENT
        # skill. Nothing previously tied the two together, so renaming the
        # producer's values would make the gate reject every baseline and kill
        # the workflow silently -- both skills' own test suites would stay
        # green.

        BeforeAll {
            $Script:releaseSkillDir = Join-Path $Script:repoRoot '.github\skills\find-release-tag-for-script-version'
            $Script:releaseScript = Join-Path $Script:releaseSkillDir 'Find-ReleaseTagForScriptVersion.ps1'
            $Script:releaseSkillMd = Join-Path $Script:releaseSkillDir 'SKILL.md'
            $Script:assertScript = Join-Path $Script:skillDir 'Assert-BaselineTrusted.ps1'
        }

        It "Assert-BaselineTrusted's accepted Status allowlist equals the producer's match-* values" {
            # Both sides are read structurally. The producer's values come
            # from the `Status` key on its returned objects (not from a
            # variable NAME, which a refactor could rename), and the
            # consumer's allowlist comes from the AST of the `-notin`
            # expression itself (not a source regex, which cannot tell code
            # from a comment and breaks on reformatting).
            $produced = @((Get-StatusValuesFromReturnedObjects -Path $Script:releaseScript) |
                    Where-Object { $_ -like 'match-*' })
            $produced.Count | Should -BeGreaterThan 0 -Because "the producer must still emit at least one match status"

            $accepted = @(Get-NotInAllowlist -Path $Script:assertScript -LeftOperandText '$Baseline.Status')

            ($accepted -join ',') | Should -BeExactly ($produced -join ',') -Because "every match-* status the release-tag skill can return must be accepted by the Step 4 gate, and no invented value may be; a rename on either side must land in one change"
        }

        It "every Status value the release-tag skill emits is documented in its own SKILL.md" {
            $produced = @((Get-StatusValuesFromReturnedObjects -Path $Script:releaseScript) |
                    Where-Object { $_ -like 'match-*' -or $_ -like 'not-found-*' })
            $produced.Count | Should -BeGreaterThan 0

            $releaseDoc = Get-Content -LiteralPath $Script:releaseSkillMd -Raw
            $undocumented = @($produced | Where-Object { $releaseDoc -notmatch ('`' + [regex]::Escape($_) + '`') })
            $undocumented -join ', ' | Should -BeExactly '' -Because "analyze-debug-files Step 4 tells the agent to interpret Status via the sibling skill's SKILL.md, so that table must stay complete"
        }
    }
}
