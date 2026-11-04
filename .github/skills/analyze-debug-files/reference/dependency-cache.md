# Dependency cache

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.

**Cache maintenance.** The cache lives at
`$env:LOCALAPPDATA\CSS-Exchange\dependency-cache\<sha>\`, keyed by commit SHA
(`.build/Build.ps1` output is deterministic per SHA). There is no auto-eviction.
To reclaim space:

```powershell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\CSS-Exchange\dependency-cache"
```

To keep only the five most-recently-accessed entries, using the `.last-accessed`
marker the helper writes on every cache hit. Newly built entries may not yet
have a marker; fall back to the entry directory's timestamp so they are not
sorted behind older entries merely because the marker is absent:

```powershell
Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\CSS-Exchange\dependency-cache" -Directory |
    Sort-Object -Property { (Get-Item -LiteralPath (Join-Path -Path $_.FullName -ChildPath '.last-accessed') -ErrorAction SilentlyContinue).LastWriteTimeUtc ?? $_.LastWriteTimeUtc } -Descending |
    Select-Object -Skip 5 |
    Remove-Item -Recurse -Force
```

Both commands are operator-run, not skill-run.
