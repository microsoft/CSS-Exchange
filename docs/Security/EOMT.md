# Exchange On-premises Mitigation Tool (EOMT)

Download the latest release: [EOMT.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/EOMT.ps1)

!!! warning "Mitigations are temporary"

      Installation of the applicable [Exchange Server Security Update](https://aka.ms/LatestExchangeServerUpdate) is the ***only way to fully protect your servers***. The mitigations applied by this tool are a temporary measure to reduce exposure until patching can be completed.

The Exchange On-premises Mitigation Tool (EOMT) applies IIS URL Rewrite mitigations for known Exchange Server CVEs. It replaces the legacy [EOMT.ps1](EOMT-Legacy.md) and [EOMTv2.ps1](EOMTv2-Legacy.md) scripts with a single, extensible tool that supports multiple CVEs from a unified interface.

## Features

- **Multi-CVE support** — Apply mitigations for any supported CVE from a single script
- **Interactive CVE selection** — When `-CVE` is not specified, an interactive prompt displays available mitigations sorted by priority
- **JSON-backed rollback** — Each mitigation creates a per-CVE JSON backup file for reliable restoration of original IIS settings
- **Remote execution** — Target multiple Exchange servers via pipeline input from `Get-ExchangeServer` or the `-ExchangeServerNames` parameter
- **WhatIf support** — Preview all IIS configuration changes before applying them
- **MSERT integration** — Optionally download and run the Microsoft Safety Scanner for malware detection
- **Auto-update** — Automatically checks for newer versions of the script from GitHub
- **Extensible** — Adding support for a new CVE requires only a definition file — no changes to the core script

## Supported CVEs

CVE | Description
---|---
CVE-2026-42897 | OWA XSS — Outbound URL Rewrite adding Content-Security-Policy header to OWA HTML responses
CVE-2022-41040 | ProxyNotShell — Autodiscover SSRF (URL Rewrite mitigation on Default Web Site)
CVE-2021-26855 | ProxyLogon — OWA cookie deserialization SSRF (URL Rewrite mitigation on Default Web Site)

## Requirements

- PowerShell 3 or later
- Must be run as Administrator
- IIS 7.5 and later
- Exchange Server SE (Subscription Edition)
- Supported Windows Server versions (Server 2019, Server 2022, Server 2025)
- [Optional] External Internet connection (required for auto-update and MSERT download)
- [Optional] For remote execution: Exchange Management Shell must be loaded

## Parameters

Parameter | Description
---|---
`-ExchangeServerNames` | One or more Exchange server names to target. Accepts pipeline input from `Get-ExchangeServer`. If omitted, targets the local server only.
`-SkipExchangeServerNames` | Exchange server names to exclude when processing multiple servers.
`-CVE` | The CVE to mitigate. If omitted, an interactive prompt allows selection. Must match a supported CVE ID.
`-RollbackMitigation` | Roll back the mitigation for the specified CVE using the JSON backup created during apply.
`-ShowMitigationStatus` | Display the current Code Fix (security update) and Mitigation (IIS URL Rewrite rule) status for each target server. Detects six states including disabled rules and name conflicts. Read-only — no changes are made.
`-RunMSERT` | Download and run the Microsoft Safety Scanner in quick scan mode. Local execution only.
`-RunMSERTFullScan` | Run MSERT in full scan mode (may take hours or days). Implies `-RunMSERT`. Local execution only.
`-DoNotRunMitigation` | Skip applying the URL Rewrite mitigation. Useful with `-RunMSERT` to scan without modifying IIS.
`-DoNotRemediate` | MSERT detects but does not auto-remove threats.
`-SkipAutoUpdate` | Skip checking for a newer version of this script from GitHub.
`-SkipDisclaimer` | Bypass the interactive disclaimer prompt.
`-WhatIf` | Preview changes without applying them.

## Examples

### Apply the default mitigation to the local server

The recommended way to use EOMT. If `-CVE` is not specified, an interactive prompt displays available mitigations sorted by priority and allows selection.

```powershell
.\EOMT.ps1
```

### Apply a specific CVE mitigation

```powershell
.\EOMT.ps1 -CVE "CVE-2026-42897"
```

### Apply mitigation to all Exchange servers

Requires Exchange Management Shell. Servers are checked for vulnerability before mitigations are applied. Servers that are already patched or unreachable are skipped automatically.

```powershell
Get-ExchangeServer | .\EOMT.ps1 -CVE "CVE-2026-42897"
```

### Apply mitigation to specific servers

```powershell
.\EOMT.ps1 -ExchangeServerNames "EX01", "EX02" -CVE "CVE-2026-42897"
```

### Roll back a mitigation

Restores the original IIS configuration from the JSON backup file created during apply.

```powershell
.\EOMT.ps1 -RollbackMitigation -CVE "CVE-2026-42897"
```

### Roll back on all Exchange servers

```powershell
Get-ExchangeServer | .\EOMT.ps1 -RollbackMitigation -CVE "CVE-2026-42897"
```

### Check vulnerability status

Checks each target server and reports vulnerability status using four properties: **Code Fix** (whether the Exchange security update is installed), **Mitigation** (whether an enabled IIS URL Rewrite rule is present), **Disabled Rules** (rules matching behavior but currently disabled), and **Rule Name Match** (whether the expected rule name exists with different behavior). No changes are made.

The output uses color-coded status messages:

- **Code Fix installed, mitigation present** — `"True (can be safely rolled back)"` (Yellow) — the mitigation is redundant and can be removed.
- **Code Fix installed, no mitigation** — `"N/A (protected by security update)"` (Green) — the server is fully protected; no mitigation needed.
- **No code fix, mitigation present** — `"True"` (Green) — the server is temporarily protected by the IIS rule.
- **No code fix, rule name conflict** — `"CONFLICT — rollback then re-apply"` (Red) — the expected rule name exists but with different behavior. Roll back the conflicting rule and re-apply EOMT.
- **No code fix, matching rule disabled** — `"DISABLED — rollback then re-apply"` (Red) — a rule with the expected name is disabled; or `"False — matching rule disabled under different name. Run EOMT to apply."` (Red) — a behaviorally-matching rule exists under a different name but is disabled.
- **No code fix, no mitigation** — `"False — ACTION REQUIRED"` (Red) — the server is unprotected.

```powershell
.\EOMT.ps1 -ShowMitigationStatus -CVE "CVE-2026-42897"
```

### Run MSERT scan only (no mitigation)

```powershell
.\EOMT.ps1 -RunMSERT -DoNotRunMitigation
```

### Run MSERT full scan in detect-only mode

```powershell
.\EOMT.ps1 -RunMSERTFullScan -DoNotRemediate -DoNotRunMitigation
```

### Preview changes with WhatIf

```powershell
.\EOMT.ps1 -WhatIf -CVE "CVE-2026-42897"
```

### Skip specific servers during remote execution

```powershell
Get-ExchangeServer | .\EOMT.ps1 -CVE "CVE-2026-42897" -SkipExchangeServerNames "EX03"
```

## How It Works

1. **CVE selection** — If `-CVE` is not provided, the script displays an interactive menu of available mitigations sorted by priority and prompts for selection.
2. **Prerequisite check** — Each target server is checked remotely for two conditions: whether the Exchange security update (code fix) is installed and whether the IIS URL Rewrite mitigation rule is already present. Servers where either the code fix or the mitigation is already applied are skipped. Servers that are unreachable or missing prerequisites (e.g., IIS URL Rewrite Module) are reported and skipped.
3. **Mitigation apply** — IIS URL Rewrite rules are added using the IIS configuration management pipeline. Before any changes are made, the current IIS state is captured and saved to a per-CVE JSON backup file at `%WINDIR%\System32\inetsrv\config\`.
4. **Rollback** — When `-RollbackMitigation` is specified, the JSON backup file is read and each original setting is restored. The backup file is then renamed to `.bak`.

## Remote Execution Notes

- Remote execution requires Exchange Management Shell to be loaded for server resolution.
- Each target server must have PowerShell remoting enabled (WinRM).
- MSERT scanning is only supported on the local server — it is skipped for remote targets.
- If a remote server is missing the IIS URL Rewrite Module, it is skipped with a warning. Install the module manually or run the script locally on that server.

## FAQ

**Q: What happens if I run the script without any parameters?**

A: The script prompts you to select a CVE from the available mitigations. It then checks if your local server needs protection (by verifying both the security update and mitigation status) and applies the mitigation if needed.

**Q: Can I apply mitigations for multiple CVEs at once?**

A: Run the script once per CVE. Each CVE creates its own JSON backup file and can be rolled back independently.

**Q: What if the mitigation was previously applied by the legacy EOMT.ps1 or EOMTv2.ps1?**

A: The new EOMT applies the same IIS URL Rewrite rules as the legacy scripts. If the rule already exists, the apply operation completes without duplicating it. To roll back a mitigation applied by a legacy script, use that same legacy script's rollback mechanism, as the JSON backup file format differs.

**Q: What if the mitigation rule is disabled or has a name conflict?**

A: If a mitigation rule exists but is disabled, `-ShowMitigationStatus` reports it in red. If the expected rule name is in use by a different rule (name conflict), it is also flagged. In both cases, run `-RollbackMitigation` to remove the conflicting or disabled rule first, then re-run EOMT to apply a clean mitigation.

**Q: Does this script make changes that affect Exchange functionality?**

A: The URL Rewrite mitigations do not disable Exchange features. They add request filtering rules that block known attack patterns while allowing normal traffic.

**Q: What if I don't have an internet connection?**

A: The IIS URL Rewrite Module must be installed manually if not already present. Use `-SkipAutoUpdate` to skip the version check. MSERT requires internet access to download.

## Privacy

Use of the Exchange On-premises Mitigation Tool and the Microsoft Safety Scanner are subject to the terms of the [Microsoft Privacy Statement](https://aka.ms/privacy).
