# Find-AmbiguousSids

Download the latest release: [Find-AmbiguousSids.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Find-AmbiguousSids.ps1)

Useful when Exchange throws `NonUniqueRecipientException`, but doesn't log the objects causing it.

## Syntax

```powershell
Find-AmbiguousSids.ps1
  [-GCName <string>]
  [-IgnoreWellKnown <bool>]
  [-Verbose]
```

## Examples

Find all ambiguous SIDs:
```powershell
.\Find-AmbiguousSids.ps1
```

Find all ambiguous SIDs while not ignoring the well-known ones, such as Everyone and other SIDs that always appear in multiple places:
```powershell
.\Find-AmbiguousSids.ps1 -IgnoreWellKnown $false
```

Show each object being checked:
```
.\Find-AmbiguousSids.ps1 -Verbose
```
