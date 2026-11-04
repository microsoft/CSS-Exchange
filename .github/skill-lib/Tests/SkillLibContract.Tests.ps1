# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Contract guard for `.github/skill-lib/`.
#
# The helpers in this directory are dot-sourced by skills that live OUTSIDE it,
# and each helper's `.DESCRIPTION` carries a `Consumed by:` list naming those
# callers. `README.md` separately enumerates which skills depend on the
# directory at all -- that list is what tells a future contributor the skills
# are repository-scoped and cannot be distributed standalone.
#
# Both lists are hand-maintained prose about code that lives elsewhere, which
# is the textbook setup for silent drift. This guard caught a live instance on
# introduction: adding `Write-DebugAnalysisReport.ps1` (a fourth consumer in
# analyze-debug-files) left BOTH helper headers and the README stale within a
# single round of edits.
#
# Strategy: derive the real consumer set from the filesystem by scanning for
# dot-source statements, then assert the prose matches it exactly in both
# directions.

[CmdletBinding()]
param()

Describe "skill-lib: documented consumers match the real ones" {

    BeforeAll {
        $Script:repoRoot = (Get-Item "$PSScriptRoot\..\..\..").FullName
        $Script:libDir = Join-Path $Script:repoRoot '.github\skill-lib'
        $Script:skillsDir = Join-Path $Script:repoRoot '.github\skills'
        $Script:readmePath = Join-Path $Script:libDir 'README.md'

        function Get-RealConsumers {
            # Repo-relative, forward-slash paths of every .ps1 under
            # `.github/skills/` or the library that dot-sources the helper.
            param([Parameter(Mandatory)][string]$HelperBaseName)
            $needle = "\skill-lib\$HelperBaseName.ps1"
            $candidates = @(Get-ChildItem -LiteralPath $Script:skillsDir -Recurse -Filter *.ps1 -File) +
            @(Get-ChildItem -LiteralPath $Script:libDir -Filter *.ps1 -File)
            $hits = @($candidates |
                    Where-Object {
                        $callerDirectory = $_.DirectoryName
                        $parseErrors = $null
                        $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$parseErrors)
                        if ($parseErrors.Count -gt 0) {
                            throw "Could not parse $($_.FullName): $($parseErrors[0].Message)"
                        }
                        $null -ne $ast.Find({
                                param($node)
                                if ($node -isnot [System.Management.Automation.Language.CommandAst] -or
                                    $node.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Dot) {
                                    return $false
                                }
                                $target = $node.CommandElements[0]
                                if ($target -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                                    $target -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                                    $value = $target.Value.Replace('/', '\')
                                    return ('\' + $value).EndsWith($needle, [System.StringComparison]::OrdinalIgnoreCase) -or
                                    ($callerDirectory -eq $Script:libDir -and $value -eq "`$PSScriptRoot\$HelperBaseName.ps1")
                                }
                                return $false
                            }, $true)
                    } |
                    ForEach-Object {
                        $_.FullName.Substring($Script:repoRoot.Length + 1).Replace('\', '/')
                    })
            return @($hits | Sort-Object)
        }

        function Get-DocumentedConsumers {
            # The `Consumed by:` bullet list from a helper's comment-based help.
            param([Parameter(Mandatory)][string]$HelperPath)
            $lines = Get-Content -LiteralPath $HelperPath
            $start = -1
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s*Consumed by:\s*$') { $start = $i; break }
            }
            if ($start -lt 0) { return @() }
            $out = New-Object System.Collections.Generic.List[string]
            for ($i = $start + 1; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s*-\s*(\S+)\s*$') { $out.Add($Matches[1]) } else { break }
            }
            return @($out | Sort-Object)
        }

        function Get-RealDependingSkills {
            $skills = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($h in (Get-ChildItem -LiteralPath $Script:libDir -Filter *.ps1 -File)) {
                foreach ($c in (Get-RealConsumers -HelperBaseName $h.BaseName)) {
                    if ($c.StartsWith('.github/skills/', [System.StringComparison]::Ordinal)) {
                        [void]$skills.Add(($c -split '/')[2])
                    }
                }
            }
            return @($skills | Sort-Object)
        }

        $Script:helpers = @(Get-ChildItem -LiteralPath $Script:libDir -Filter *.ps1 -File)
    }

    It "has at least one helper to guard" {
        $Script:helpers.Count | Should -BeGreaterThan 0
    }

    It "lists exactly the real consumers in every helper's 'Consumed by:' block" {
        $problems = New-Object System.Collections.Generic.List[string]
        foreach ($h in $Script:helpers) {
            $real = @(Get-RealConsumers -HelperBaseName $h.BaseName)
            $documented = @(Get-DocumentedConsumers -HelperPath $h.FullName)
            $real.Count | Should -BeGreaterThan 0 -Because "$($h.Name) should have at least one caller; an unused helper does not belong in skill-lib"
            if (($documented -join "`n") -ne ($real -join "`n")) {
                $problems.Add("$($h.Name): documented [$($documented -join '; ')] but real [$($real -join '; ')]")
            }
        }
        $problems -join ' || ' | Should -BeExactly '' -Because "each helper's 'Consumed by:' list must name every .ps1 that dot-sources it, and nothing else"
    }

    It "lists every depending skill in README.md's dependency section" {
        # README tells contributors which skill folders are NOT independently
        # distributable. A skill that starts consuming skill-lib without being
        # added here looks safe to copy out, and breaks at dot-source time.
        $readme = Get-Content -LiteralPath $Script:readmePath -Raw
        $realSkills = @(Get-RealDependingSkills)
        $realSkills.Count | Should -BeGreaterThan 0
        $missing = @($realSkills | Where-Object {
                $readme -notmatch ([regex]::Escape(".github/skills/$_/"))
            })
        $missing -join ', ' | Should -BeExactly '' -Because "README.md's 'Skills that depend on this directory' list must name every skill that dot-sources a helper here"
    }

    It "does not claim a dependency that no longer exists" {
        $readme = Get-Content -LiteralPath $Script:readmePath -Raw
        $claimed = @([regex]::Matches($readme, '`\.github/skills/([A-Za-z0-9._\-]+)/`') |
                ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $claimed.Count | Should -BeGreaterThan 0 -Because "the extraction must actually find the claimed dependency list"
        $realSkills = @(Get-RealDependingSkills)
        $stale = @($claimed | Where-Object { $realSkills -notcontains $_ })
        $stale -join ', ' | Should -BeExactly '' -Because "a skill listed as depending on skill-lib but no longer dot-sourcing anything here is stale documentation"
    }
}
