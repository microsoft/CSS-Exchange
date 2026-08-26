---
name: dependency-analysis
description: >
  Analyzes script dependencies and cascading impact using the build system XML
  files. Use this skill when modifying shared functions, reviewing changes to
  Shared/ code, writing tests for scripts with dependencies, or assessing the
  blast radius of any code change.
---

# Dependency Analysis

CSS-Exchange scripts dot-source shared functions. Changes to a shared function
cascade through multiple levels of dependents. The build system generates two
XML files that are the authoritative source (when generated fresh by `.build/Build.ps1`):

- `dist/dependencyHashtable.xml` — What each script imports (parent to child)
- `dist/dependentHashtable.xml` — What depends on each script (child to parent)

Generate fresh XML by running `.build/Build.ps1` first.

## When to Use This

- Before modifying any file in `Shared/` — understand what breaks
- During code review — verify callers handle changed shared function contracts
- When writing tests — identify which scripts need test coverage for a change
- When assessing risk — map the full blast radius of a proposed change

## Analysis Process

1. Identify the changed file(s)
2. Query the dependency XML to find direct callers
3. Walk the full cascade chain (all levels, not just direct callers)
4. Identify root/released scripts (entry points with no dependents)
5. Report the full impact scope

## Querying Dependencies

### Find direct callers of a script
```powershell
$dependentHashtable = Import-Clixml -Path "dist\dependentHashtable.xml"
$targetPath = (Resolve-Path "Shared\FunctionName.ps1").Path
$directCallers = $dependentHashtable[$targetPath]
```

### Find cascading dependents (all levels)

Use the `Get-DependencyCascade.ps1` script in this skill's directory, or
run the BFS traversal inline:

```powershell
$allDependents = [System.Collections.Generic.HashSet[string]]::new()
$queue = [System.Collections.Generic.Queue[string]]::new()
$directCallers | ForEach-Object { $queue.Enqueue($_); $null = $allDependents.Add($_) }
while ($queue.Count -gt 0) {
    $current = $queue.Dequeue()
    if ($dependentHashtable.ContainsKey($current)) {
        foreach ($dep in $dependentHashtable[$current]) {
            if ($allDependents.Add($dep)) {
                $queue.Enqueue($dep)
            }
        }
    }
}
```

### Find root/released scripts
```powershell
$dependencyHashtable = Import-Clixml -Path "dist\dependencyHashtable.xml"
$rootCandidates = @($dependencyHashtable.Keys) | Where-Object {
    -not $dependentHashtable.ContainsKey($_)
}
```

## Report Format

```
## Dependency Impact Analysis

**Changed File**: path/to/changed/file.ps1

### Level 1: Direct Callers (N scripts)
- Script1.ps1
- Script2.ps1

### Level 2+: Cascading Dependents (N scripts)
- Script3.ps1 (imports Script1)
- Script4.ps1 (imports Script2)

### Root Scripts Affected (N released scripts)
- HealthChecker.ps1
- SetupAssist.ps1

### Total Impact
- Direct: N scripts
- Cascading: N scripts
- Root/Released: N scripts
```

## Important Notes

- NEVER rely on manual grep to find dependencies. It misses cascading chains.
- Always run Build.ps1 first to ensure XML files are current.
- Changes to Shared/ functions have the widest blast radius.
