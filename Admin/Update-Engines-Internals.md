<!-- cspell:ignore Kaspersky Cloudmark failovers engineinfo scanengineupdate fullpkg mpasbase mpavbase mpengine mpavdlta mpasdlta mpgear avemicrosoft engineinterface OCSP canonicalizer redownload redownloaded redownloading writtenFileHashes TOCTOU chash -->

# Update-Engines — Internals, Trust Model, and Test Matrix

> **Audience.** Developers modifying `Update-Engines.ps1`, reviewers (human or
> automated) assessing its security posture, and QA engineers validating a
> change before merge. This is a companion to the customer-facing
> [Update-Engines.md](../docs/Admin/Update-Engines.md), which covers only how
> to run it.

## Table of contents

1. [What the script actually does](#what-the-script-actually-does)
2. [The endpoints](#the-endpoints)
3. [Download flow, end to end](#download-flow-end-to-end)
4. [The trust and integrity model](#the-trust-and-integrity-model)
5. [Why the model is sufficient](#why-the-model-is-sufficient)
6. [Manual test matrix](#manual-test-matrix)
7. [Automated test suite](#automated-test-suite)

---

## What the script actually does

`Update-Engines.ps1` mirrors the anti-malware scan engine payloads that
Forefront Protection / EOP use on Exchange Server. In one run it:

1. Downloads a small **Universal Manifest** CAB from a Microsoft endpoint.
   This is the "table of contents" listing every engine (Microsoft, Kaspersky,
   Symantec, etc.) the catalog has ever advertised across every platform
   (`amd64`, historically `x86`). The endpoint today only serves `Microsoft`
   and `Command` on `amd64`; all other engines and the `x86` platform return
   404 (see [The endpoints](#the-endpoints)). The `-Engines` parameter is
   locked to `Microsoft` and `Command`, and the platform is hardcoded to
   `amd64` — the script only ever attempts to download what the endpoints
   actually serve.
2. Downloads a small **Engine License Info** CAB whose version is named by the
   Universal Manifest.
3. For each engine the caller requested, downloads a small **per-engine
   manifest** CAB on the `amd64` platform, extracts it, then downloads the
   **actual engine payload** — a large CAB (often 200 MB or more) containing
   the DLLs and signature files.
4. Extracts the payload into a versioned directory under `-EngineDirPath` and
   copies the per-engine manifest next to it so the Exchange scan hosts on
   other machines can consume it from that share.

No Exchange cmdlet is called; nothing is installed. The script is purely an
HTTP-and-CAB mirroring tool.

---

## The endpoints

The script defaults to three well-known Microsoft update hosts. Only the first
is used by default; the other two are documented as manual failovers you can
pass on the command line.

| Purpose | Default URL |
|---|---|
| Primary | `http://forefrontdl.microsoft.com/server/scanengineupdate/` |
| Failover | `https://amupdatedl.microsoft.com/server/scanengineupdate/` |
| Alternate | `http://amupdatedl.microsoft.com/server/amupdate/` |

The primary is HTTP by default. HTTP is safe **for content integrity and
authenticity** — every artifact the script consumes is either
Authenticode-signed or hash-bound to a signed manifest, and Microsoft holds
the signing keys, so an on-path attacker cannot substitute a validly-signed
tampered artifact. See
[The trust and integrity model](#the-trust-and-integrity-model).

HTTP does **not** provide freshness. An on-path attacker who can serve
responses at the update endpoint can replay a validly-signed but older
release: the signatures remain valid (Microsoft signed those artifacts too),
the manifest→CAB hash chain still verifies, and every check individually
passes. The effect is a downgrade: an operator running the script gets AV
definitions from an earlier date. This condition is discussed in
[Signed-artifact replay and content-freshness](#signed-artifact-replay-and-content-freshness).

Prefer the HTTPS failover URL where the environment allows it: TLS blocks
ordinary on-path replay without any change to the artifact trust model.
If a customer's environment blocks plain HTTP, either failover URL can be
passed via `-UpdatePathUrl`. The `-FailoverPathUrl` and `-EngineDownloadUrlV2`
parameters are declared for documentation but the script does not fall
over between them automatically; an operator picks the URL they want.

### `-EngineDirPath` must be on local storage

The script rejects `-EngineDirPath` values that are UNC paths (`\\server\share\...`)
or mapped network drives. The check is implemented as `Test-EngineDirPathIsLocal`
and runs immediately after the `-EngineDirPath` presence check, before any
manifest is downloaded or trusted.

Every download, signature check, hash check, and extraction reads and writes
the same predictable pathname. If that path lives on a network share, any
principal with write access to the share can swap the file between the
check and the extract, defeating the integrity checks even when they
individually pass.

For a drive letter, both `Get-PSDrive.DisplayRoot` (populated for persistent
mappings created via `net use` / `New-PSDrive -Persist`) and
`Get-PSDrive.Root` (populated for a plain `New-PSDrive -Root '\\...'` in the
current session) are inspected, so either flavor of mapping is caught.

Operators who need engines available on a share should:

1. Run this script against a local path (for example, `C:\Engines\`).
2. Verify the run completed successfully.
3. Copy the completed engine folder to the network share.

Copying to the share happens after the verify-then-consume boundary is
already closed on trusted local disk.

---

## Download flow, end to end

There are three logical **rounds** of downloading. Rounds 2 and 3 depend on
data parsed from round 1. Round 3 repeats once per `(platform, engine)` the
caller asked for.

```text
Round 1: Universal Manifest       ← 1 download,  ~11 KB
Round 2: Engine License Info      ← 1 download,  ~11 KB
Round 3: Per-engine update loop   ← 2 downloads per engine
                                    (manifest ~12 KB + payload ~200 MB)
```

Every file you fetch is a Microsoft CAB. You never receive a raw XML or DLL
directly — always a CAB that you must `expand.exe` to get either metadata or
binaries.

### Round 1 — Universal Manifest (the "table of contents")

```text
        ┌─────────────────────────────────────────────────────────────────┐
        │  GET  <UpdatePathUrl>/metadata/UniversalManifest.cab             │
        └─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                        ┌──────────────────────┐
                        │  UM.cab  (~11 KB)    │  Authenticode: CN=Microsoft
                        └──────────────────────┘  Corporation
                                    │
                                    │  expand.exe -F:*
                                    ▼
                    ┌──────────────────────────────┐
                    │  UniversalManifest.xml       │
                    │  (in <EngineDirPath>\temp\)  │
                    └──────────────────────────────┘
                                    │
                                    │  parse (as [xml])
                                    ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │  What we pull out:                                              │
    │   • licenseInfoVersion       "201910170001"    → Round 2 URL    │
    │   • LicenseInfo.hash.hash    <base64 SHA256>   → verifies R2    │
    │   • EngineVersions/Platform[id]/Category/Engine[name/default]   │
    │       → inventory: what engines exist for which platforms       │
    │       → Engine.default is a GUID like "{8B26BC7D-…}"            │
    └─────────────────────────────────────────────────────────────────┘
```

**Trust anchor.** The Universal Manifest CAB is Authenticode-signed by
Microsoft Corporation. Everything downstream inherits its trust from what
this signed manifest publishes.

### Round 2 — Engine License Info

The URL is built from the `licenseInfoVersion` we just parsed. This CAB is a
CAB inside a CAB, which caused confusion during the review and is worth
calling out.

```text
        ┌─────────────────────────────────────────────────────────────────┐
        │  GET  <UpdatePathUrl>/metadata/<licenseInfoVersion>/EngineInfo.cab
        └─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                        ┌──────────────────────┐
                        │  EngineInfo.cab      │  Authenticode: CN=Microsoft
                        │  (outer, ~11 KB)     │  Corporation
                        └──────────────────────┘
                                    │
                                    │  expand.exe -F:*
                                    ▼
                        ┌──────────────────────┐
                        │  engineinfo.cab      │  ← INNER CAB, same base name
                        │  (inner, ~14 KB)     │
                        │                      │
                        │  SHA256 matches      │
                        │  UM.LicenseInfo.hash │
                        └──────────────────────┘
```

Do not confuse the outer CAB with the inner one. `UM.LicenseInfo.hash.hash`
is the SHA256 of the **inner** file, not the outer one we download. The
inner CAB is extracted only into a randomized per-invocation scratch
directory long enough to be hashed and is deleted in a `finally` block; it
is never persisted. The **outer** CAB (`EngineInfo.cab`) is what the script
stages persistently at
`<EngineDirPath>\metadata\<licenseInfoVersion>\EngineInfo.cab` for the
downstream scan host to consume.

### Round 3 — Per-engine update loop

For every engine the user passed (`-Engines`), the script performs two
downloads on the hardcoded `amd64` platform.

#### 3a. Per-engine manifest CAB

```text
    ┌───────────────────────────────────────────────────────────────────────┐
    │  URL built from data parsed out of the signed UM:                     │
    │    engineUrl   = <UpdatePathUrl><Platform.id>/<Engine.name>/Package/  │
    │    manifestUrl = <engineUrl>manifest.<Engine.default>.cab             │
    │                                                                       │
    │  Concrete example (amd64, Microsoft engine):                          │
    │    .../scanengineupdate/amd64/Microsoft/Package/                      │
    │       manifest.{8B26BC7D-829D-4354-8635-3FA6D6F5B1CB}.cab             │
    └───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────┐
                    │  manifest.{GUID}.cab       │  Authenticode: CN=Microsoft
                    │  (~12 KB)                  │  Corporation
                    └────────────────────────────┘
                                    │
                                    │  expand.exe -F:*
                                    ▼
                    ┌────────────────────────────┐
                    │  manifest.xml              │
                    │  (in <EngineDirPath>\temp\)│
                    └────────────────────────────┘
                                    │
                                    │  parse
                                    ▼
    ┌──────────────────────────────────────────────────────────────────────┐
    │  What we pull out:                                                   │
    │   • Package.version                  "2112342168"                    │
    │   • Package.FullPackage.name         "microsoft_fullpkg.cab"         │
    │   • Package.FullPackage.size         216080941                       │
    │   • Package.FullPackage.hash.hash    <base64 SHA256>  ← trusted      │
    │   • Package.Files.Dir[]              subdirectories to create        │
    │   • Package.Files.File[]             per-file inventory + hashes     │
    └──────────────────────────────────────────────────────────────────────┘
```

The per-engine manifest CAB is Authenticode-signed too, so the SHA256 it
publishes for the payload is trustworthy.

#### 3b. The actual engine payload

URL is built from the manifest we just parsed:

```text
    ┌───────────────────────────────────────────────────────────────────────┐
    │  GET  <engineUrl><Package.version>/<Package.FullPackage.name>         │
    │                                                                       │
    │  Concrete:                                                            │
    │    .../scanengineupdate/amd64/Microsoft/Package/2112342168/           │
    │       microsoft_fullpkg.cab                                           │
    └───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │  microsoft_fullpkg.cab (~206 MB)                  │
        │                                                   │
        │  NOT Authenticode-signed                          │
        │  SHA256 matches signed manifest's FullPackage.hash│
        │                                                   │
        │  This is a "CAB of CABs" — 13 nested per-file CABs│
        └───────────────────────────────────────────────────┘
                                    │
                                    │  expand.exe -F:*
                                    ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │  Inner CABs, one per component (also not Authenticode-signed):       │
    │                                                                      │
    │    mpasbase.vdm.cab       ~139 MB   ← spam signatures (base)         │
    │    mpavbase.vdm.cab        ~62 MB   ← AV signatures (base)           │
    │    mpengine.dll.cab          ~8 MB  ← the scan engine DLL            │
    │    mpavdlta.vdm.cab          ~3 MB  ← AV signatures (delta)          │
    │    mpasdlta.vdm.cab          ~3 MB  ← spam signatures (delta)        │
    │    mpgear.staging.dll.cab                                            │
    │    mpgear.prod.dll.cab                                               │
    │    mpgear.dll.cab                                                    │
    │    avemicrosoft.dll.cab                                              │
    │    engineinterface.cab.cab                                           │
    │    MpEngineMockMetadata.xml.cab                                      │
    │    EngineMetaData.xml.cab                                            │
    │    update.ini.cab                                                    │
    └───────────────────────────────────────────────────────────────────────┘
                                    │
                                    │  the individual .dll / .vdm files inside
                                    │  those inner CABs are Authenticode-signed
                                    │  at the PE-file level and enforced by the
                                    │  OS when the engine host loads them.
                                    ▼
                            (consumed by the scan host)
```

**Why the payload itself isn't CAB-signed.** Signing a 206 MB blob every time
an engine ships costs a lot. Microsoft's design puts the crypto weight on the
tiny per-engine manifest CAB (Authenticode) and lets trust flow through a
published SHA256 down to the huge payload. Once extracted, the individual
DLLs are Authenticode-signed at the PE-file level — that's where the OS
enforces integrity again when the code actually runs.

### Where files end up on disk

```text
<EngineDirPath>\
├── metadata\
│   ├── UniversalManifest.cab                       ← R1 outer
│   └── 201910170001\
│       └── EngineInfo.cab                          ← R2 outer (contains inner CAB)
├── amd64\
│   └── Microsoft\
│       └── Package\
│           ├── manifest.{8B26BC7D-…}.cab           ← R3a outer
│           └── 2112342168\
│               ├── microsoft_fullpkg.cab           ← R3b payload
│               ├── mpengine.dll.cab                ← extracted inner
│               ├── mpasbase.vdm.cab                ← extracted inner
│               ├── … (11 more inner CABs)
│               └── manifest.{8B26BC7D-…}.cab       ← copy of R3a
└── temp\                                           ← scratch, wiped between runs
    ├── UniversalManifest.xml                       ← R1 parsed
    └── manifest.xml                                ← R3a parsed
```

---

## The trust and integrity model

The script talks to update endpoints over **plain HTTP** by default. The
content-integrity and authenticity model does not depend on TLS — every
artifact the script consumes is cryptographically verified against a
Microsoft-signed anchor after it lands on disk. Freshness is a separate
property and is *not* provided; see
[Signed-artifact replay and content-freshness](#signed-artifact-replay-and-content-freshness).

### Two defenses, in layers

**Defense 1: path containment.** Every filesystem path built from a value
that comes out of a downloaded manifest — or is otherwise influenced by
data an external party could substitute — is composed through
`Get-ContainedPath`, which:

1. Rejects null or empty segments.
2. Joins the segment onto a trusted root.
3. Canonicalizes the result with `[System.IO.Path]::GetFullPath`, which
   collapses `..` and `.` components and normalizes separators.
4. Verifies the resolved path is still under the resolved root using a case-
   insensitive `StartsWith` check.

Purely local paths built from operator-supplied arguments (for example
`$tempFilePath`, `$umFilePath`, `$metaDataDir`) are constructed with plain
string concatenation because those inputs are trusted; the containment
helper applies specifically at the trust boundary where a manifest field
becomes a filesystem name.

Any segment that resolves outside the intended root throws before the path
reaches `WebClient.DownloadFile`, `New-Item`, `Copy-Item`, or the
`Shell.Application` COM API used to extract CABs. This closes the class of
path-traversal findings in which an attacker-controlled manifest field
escapes the target directory, without depending on the correctness of the
manifest fields themselves.

**Precondition — local storage with admin-only ACLs.** `GetFullPath` is a
lexical canonicalizer; it does not resolve NTFS junctions, symbolic links,
or mount points. A reparse point placed inside `-EngineDirPath` or its
descendants by a lower-privileged principal can redirect I/O outside the
intended root without `Get-ContainedPath` firing. Two preconditions close
that gap:

- The script rejects UNC paths and mapped network drives for
  `-EngineDirPath` (see [`-EngineDirPath` must be on local storage](#-enginedirpath-must-be-on-local-storage)).
- `-EngineDirPath` and every descendant it creates must be writable only by
  the identity running this script and by trusted administrators. Standard
  practice for a machine hosting a mirror.

The per-invocation ELI scratch directory (`<TempFilePath>\eli-<GUID>`) uses
a random name so that a reparse point pre-planted at a predictable name
cannot redirect the extraction of the outer `EngineInfo.cab`.

Fields also pass through `Test-ManifestFieldShape` before being used in URL
or path construction. The allowed shapes are deliberately narrow:

| Field | Pattern | Rationale |
|---|---|---|
| `licenseInfoVersion` | `^\d+$` | version stamp is always all-digits |
| `Platform.id` | `^[A-Za-z0-9]+$` | shape check only; `amd64` is the only value the script will actually consume, but a well-formed UM can legally advertise other platforms |
| `Engine.Name` | `^[A-Za-z0-9_\-]+$` | shape check only; `-Engines` is `ValidateSet`-locked to `Microsoft` and `Command`, but a well-formed UM can legally advertise other engines (`Kaspersky`, `Symantec`, etc.) |
| `Engine.Default` | `^\{[0-9A-Fa-f\-]+\}$` | braced GUID |
| `Package.version` | `^\d+$` | version stamp is always all-digits |
| `Package.FullPackage.name` | `^[A-Za-z0-9_\-]+\.cab$` | simple CAB filename |
| `Files.Dir[i].name` | `^[A-Za-z0-9_\-]+$` | simple directory name |

**Defense 2: cryptographic verification.** After each download, before the
file is trusted or extracted:

1. **Authenticode signature** on every CAB that Microsoft signs (UM CAB,
   Engine License Info CAB, per-engine manifest CAB). `Test-AuthenticodeSignature`
   requires:
    - `Status = Valid` from `Get-AuthenticodeSignature`, and
    - `SignerCertificate.Subject` matches the RDN component
      `O=Microsoft Corporation` as a complete component
      (`(?:^|,\s*)O=Microsoft Corporation(?:,|$)`). A subject like
      `O=Microsoft Corporation Evil` or `O=Not Microsoft Corporation` fails
      the check. Covers both `CN=Microsoft Corporation` and
      `CN=Microsoft Windows` signing chains, which both carry
      `O=Microsoft Corporation`.
    - Explicit `X509Chain.Build` with `RevocationMode = Online` and
      `RevocationFlag = ExcludeRoot`. A `Revoked`/`NotSignatureValid`/
      `Untrusted` chain status is a hard failure; a `RevocationStatusUnknown`
      or `OfflineRevocation` status is logged as a warning so a transient
      CRL/OCSP outage does not block engine updates on a host that already
      passed the base Authenticode "Valid" check. `NotTimeValid` and
      `CtlNotTimeValid` are intentionally masked via
      `X509VerificationFlags.IgnoreNotTimeValid` /
      `IgnoreCtlNotTimeValid` — `Get-AuthenticodeSignature` already checked
      time validity using the Authenticode countersignature timestamp, which
      is the correct signing-time reference. Re-checking time at "now" would
      spuriously fail legitimate signatures whose signing certificate has
      since expired (the normal case for old signed artifacts).
2. **SHA256 hash** on any artifact whose expected hash is published in an
   already-signed CAB:
    - The **inner** `engineinfo.cab` (extracted from the outer
      `EngineInfo.cab`) is compared against `UM.LicenseInfo.hash.hash`, which
      lives in the Authenticode-signed Universal Manifest.
    - The **full engine payload** CAB is compared against
      `Package.FullPackage.hash.hash`, which lives in the Authenticode-signed
      per-engine manifest.
3. **Identity binding** on the per-engine manifest. Before any field from
   the per-engine manifest is used, the script requires the manifest's
   `Package.name`, `Package.platform`, and `Package.version` attributes to
   equal the engine name, platform id, and package version selected from the
   (Authenticode-verified) Universal Manifest. A validly-signed but
   substituted manifest for a different engine, platform, or version is
   rejected here. Uses `XmlElement.GetAttribute` explicitly so that a
   missing attribute reports as `$null` and not as the element's LocalName
   (a PowerShell XML dynamic-property fallback that would otherwise silently
   accept `Package` as the name).

`Test-FileHash` accepts a base64-encoded SHA256 (the format the manifests
use), converts it to uppercase hex, and compares against `Get-FileHash`. Any
mismatch throws.

### The chain of custody

```text
HTTP (untrusted transport)
   │
   ▼
UM.cab  ── Authenticode ✅ ────────────────────────────┐
   │ says "ELI hash = X, engine {name,default,version}"│
   ▼                                                   │
EngineInfo.cab (outer)  ── Authenticode ✅             │
   │  extract inner engineinfo.cab                     │
   │  SHA256 == UM.LicenseInfo.hash.hash  ✅  ─────────┤
   ▼                                                   │
                                                       │  trust flows from
manifest.{GUID}.cab  ── Authenticode ✅                │  the signed UM into
   │                                                   │  each downstream
   │  identity binding ✅                              │  artifact
   │   Package.name     == UM.Engine.Name              │
   │   Package.platform == UM.Platform.id              │
   │   Package.version  == UM.Engine.Package.version   │
   │                                                   │
   │ says "full package hash = Y"                      │
   ▼                                                   │
microsoft_fullpkg.cab (206 MB)                         │
   │ SHA256 == signed manifest's FullPackage.hash ✅ ──┘
   ▼
Individual .dll / .vdm files
   │  Authenticode ✅ per-PE, enforced by the OS when the
   │  engine host loads them
   ▼
scan engine running on Exchange
```

Every hop is guarded — either by an Authenticode signature on the CAB
itself, or by a SHA256 that a **previously Authenticode-verified** CAB
vouches for. This protects **integrity and authenticity**: no hop lets an
on-path attacker substitute *forged* content without the script rejecting
it. It does not protect **freshness**: an on-path attacker who serves
validly-signed but older releases can force a downgrade; see
[Signed-artifact replay and content-freshness](#signed-artifact-replay-and-content-freshness).

### Cross-run and on-disk defenses layered on top of the trust model

The signature/hash chain above assumes the artifacts the script hashes at
verification time are the same bytes it later expands. Four defenses
protect that assumption across runs, across TOCTOU windows, and against
lower-privileged writers into the staging tree:

- **Fail-open cache pattern (B2).** Cached artifacts (ELI outer CAB and
  the full package CAB) are re-verified on every run. If the cached
  file's Authenticode signature or SHA256 fails to match the current
  Universal Manifest / per-engine manifest anchor, the script deletes
  the cached file and re-downloads it once from the anchored endpoint
  before failing. A single corrupt cached file cannot permanently pin
  the pipeline. If the fresh download also fails verification, the
  script throws immediately — there is no infinite loop.
- **Scratch-dir extraction (B3).** The full package CAB is expanded
  into a per-invocation randomized scratch subdirectory under
  `<EngineDirPath>\temp\` (`pkg-<guid>\`) and the resulting files are
  moved into `<EngineDirPath>\amd64\<Engine>\Package\<version>\`
  one at a time. The versioned directory itself is never purged, so
  customer files or operator artifacts placed under it survive
  updates. Only files the script actually produced this run are
  touched. The ELI outer CAB is expanded to `eli-<guid>\` under the
  same temp dir and the scratch directory is cleaned via `try/finally`.
  The extract loop uses `-ErrorAction Stop` on the `New-Item`,
  `Move-Item`, and marker `Copy-Item` calls so a non-terminating
  error at commit time surfaces before the completion marker is
  written; the retry on the next run then observes the missing
  marker and re-extracts. On a redownload triggered by the fail-open
  cache pattern above, the pre-existing completion marker is
  invalidated (deleted and unregistered) before the new extraction
  begins, so a stale marker cannot mask a partial re-extract.
- **Manifest inventory validation (B3).** After extraction — on both
  the fresh-extract path and the cached-fast-path — the script walks
  `Package.Files.File[]` from the Authenticode-verified per-engine
  manifest and verifies that every declared entry produced a
  corresponding `<name>.cab` under the versioned package directory
  (or, on the extract path, under the scratch directory before the
  move). If any declared file is missing the script aborts with an
  aggregated count and does not write the completion marker. This
  catches partial extractions and AV quarantine of individual
  extracted files that would otherwise leave the mirror silently
  incomplete. It does **not** verify the *content* of the extracted
  files — only their presence. See
  ["You should verify per-file hashes for every file inside the payload."](#you-should-verify-per-file-hashes-for-every-file-inside-the-payload)
  for why per-file content hashing is out of scope.
- **End-of-run integrity sanity check.** Every file the script writes
  (Universal Manifest CAB, ELI CAB, per-engine manifest CAB, full
  package CAB, every file moved out of the scratch dir, and the
  extraction-completed marker) is registered in an in-memory ledger
  keyed by absolute path. Exactly one artifact — the full engine
  payload CAB — anchors to a manifest-published SHA256
  (`Package.FullPackage.hash.hash`), which is available at
  registration time because it comes from the same signed per-engine
  manifest the script just verified. Every other entry — the outer
  UM CAB, the ELI outer CAB, the per-engine manifest CAB, each
  `.cab` file the extractor produces under the versioned package
  directory, and the extraction-completed marker — captures its
  **runtime** SHA256 at write time (or, on the cached fast path, at
  ledger-registration time). The UM CAB is trust-anchored by
  Authenticode; that is distinct from storing a manifest-published
  hash in the ledger. The per-engine manifest's per-file
  `hash`/`chash` values reference the compressed inner-CAB bytes,
  not the expanded on-disk form the script produces, so they are
  not usable as ledger anchors for the extracted files without an
  additional decompression stage. Just before the script cleans up
  its temp directory, `Test-WrittenFileHashes` re-hashes every
  ledger entry and throws an aggregated error listing every file
  that is now missing, unreadable, or hashes to a different value
  than we recorded. This catches AV quarantine, admin scripts that
  touch the staging tree mid-run, and lower-privileged
  post-verification mutation. It does **not** catch tampering that
  occurred *before* ledger registration on the cached fast path —
  for the extracted per-file `.cab` entries, the ledger anchor is
  only as fresh as the current run's extraction (fresh extract) or
  the current run's on-disk read (cached fast path).

---

## Why the model is sufficient

Automated reviewers (and humans skimming the code) sometimes flag the
absence of a check they expect to see. This section preempts the common
objections.

### "The endpoint URL is HTTP, not HTTPS."

**Not a defect for content integrity or authenticity, but see the freshness
caveat.** The Microsoft download infrastructure serves these artifacts over
both HTTP and HTTPS. Authenticode signatures and SHA256 hashes bind us to
Microsoft's signing key regardless of the transport, so an on-path attacker
cannot substitute *forged* content over either channel.

Freshness is a separate property. TLS on the transport does add value here:
it blocks ordinary on-path replay of validly-signed older releases (the
attacker cannot rewrite responses the client is going to accept). Where
network policy allows it, prefer the HTTPS endpoint. See
[Signed-artifact replay and content-freshness](#signed-artifact-replay-and-content-freshness)
for the current freshness posture.

The `-UpdatePathUrl` and `-FailoverPathUrl` parameters let a customer point
at the HTTPS host if their network policy forbids outbound HTTP.

### "You should Authenticode-verify the 200 MB payload CAB."

**Not possible — it's not signed.** The full-package CAB is a
"CAB of CABs" containing 13 per-file inner CABs, and neither the outer nor
the inner CABs carry an Authenticode signature. Microsoft's design signs
the small per-engine manifest CAB and puts a SHA256 of the payload inside
it. That hash is the payload's trust anchor. We verify it. Attempting
`Get-AuthenticodeSignature` on the payload CAB will always return
`NotSigned`, so adding such a check would guarantee a failure on every
real run.

### "You should hash the outer EngineInfo.cab against UM.LicenseInfo.hash.hash."

**No — that field hashes the inner CAB, not the outer one.** The Universal
Manifest publishes the SHA256 of the inner `engineinfo.cab` that appears
after you extract the outer `EngineInfo.cab`. Hashing the outer file
against that field always fails. This was one of the findings during the
live probe of the endpoints, and the script now extracts first and hashes
the inner file.

### "You should pin the signing certificate thumbprint."

**Would break the updater the first time Microsoft rotates the certificate.**
The Windows Authenticode chain terminates at the Microsoft root already
trusted by the OS. If the OS trust store trusts the signer, we trust it too.
The check requires an exact-RDN match on `O=Microsoft Corporation` (not a
substring match) and runs the certificate chain with online revocation
explicitly enabled. Pinning a thumbprint would require shipping an updated
`Update-Engines.ps1` every time Microsoft rotates their code-signing
certificate — a significant availability risk with no realistic security
payoff, because an attacker capable of forging a Microsoft-chain certificate
could also forge one matching any thumbprint we pin.

### "You should reject older versions to prevent downgrade attacks."

**Deferred as an accepted limitation with a real attacker impact.** The
product design supports mirroring an older engine build on purpose
(rollback for compat issues, staging environments). Adding a version floor
without a corresponding rollback mechanism (for example an
`-AllowDowngrade` switch) would break the intentional-rollback use case,
and neither the floor nor the switch is implemented today.

The attacker impact of this deferral is real and should not be minimized.
An on-path attacker who can serve responses at the update endpoint over
HTTP can replay a validly-signed but *older* release. Every
Authenticode/hash/identity check still passes because Microsoft did sign
those older artifacts. The customer runs stale AV definitions from an
earlier date — the effective difference between "up-to-date engines" and
"three-month-old engines" against active malware, imposed by an external
attacker, is not equivalent to an operator's own deliberate rollback.

Mitigations available today without a version floor:

- Use the HTTPS `-UpdatePathUrl` where policy allows: TLS terminates the
  easy on-path replay vector without changing the artifact trust model.
- Monitor the versions actually staged (the per-engine manifests record
  `Package.version`), and alert if they stop advancing.

A proper fix requires the version-floor + operator-opt-in design and is
tracked as a follow-up.

Note that identity binding does close the related "different engine
altogether" substitution: an MITM cannot combine a valid current Universal
Manifest with a validly-signed per-engine manifest for a different engine,
platform, or version, because the identity check requires equality against
the UM's selection.

### "You should verify per-file hashes for every file inside the payload."

**Content hashes are out of scope; presence is verified.** The per-file
hashes in the per-engine manifest (`Files.File[].hash`, `Files.File[].chash`)
reference the compressed inner-CAB bytes that ship inside the outer
`microsoft_fullpkg.cab`. `expand.exe` produces a `<name>.cab` on disk per
`<File name="X">` entry, which is not the byte form the manifest hash
covers directly, so wiring `Files.File[].hash` to `Test-FileHash` on the
extracted output would fail without an additional decompression stage.

What the script *does* enforce on the individual files is presence, not
content: `Get-ExpectedFileInventory` walks `Package.Files.File[]` and
requires every declared file to be present in the versioned package
directory after extraction (and on the cached fast path — see the
"Manifest inventory validation (B3)" defense in
[Cross-run and on-disk defenses layered on top of the trust model](#cross-run-and-on-disk-defenses-layered-on-top-of-the-trust-model)).
A missing file — because `expand.exe` failed mid-way, an operator deleted
an inner cab, or AV quarantined it — aborts the run.

Downstream, the scan host loading DLLs from the mirror validates each
loadable DLL at load time via the OS Authenticode chain. Signature-data
files (`.vdm`) are not PE files and are not Authenticode-verified at load,
but the mirror only serves them to the scan engine host that already
established the trust chain up to the payload CAB — the same trust
boundary as any other Microsoft-published data file consumed by an
already-trusted signed binary. Duplicating per-file content verification
inside the mirror script would require an additional decompression stage
against a hash form the manifest does not directly publish; the returns
do not justify the cost given the mirror's scope.

### "You should reject malformed manifest XML earlier."

**Already done.** Every field pulled out of a manifest is validated by
`Test-ManifestFieldShape` against a narrow regex before it is used in
URL construction, path construction, or a file operation. Structurally
malformed XML fails at the `[xml]` cast during parsing.

---

## Signed-artifact replay and content-freshness

Authenticode signatures and SHA256 hashes prove **integrity** ("the bytes
have not been altered") and **authenticity** ("Microsoft signed them").
They do not prove **freshness** ("this is the current release"). The
distinction matters because a validly-signed *older* release is not
distinguishable from a validly-signed *current* release using signatures
and hashes alone — Microsoft signed both.

### The condition

The script fetches artifacts over plain HTTP by default and does not
persist any state about the highest version it has seen. Given both,
an on-path attacker who can serve responses at the update endpoint can:

1. Capture the current Universal Manifest, per-engine manifests, and full
   package CABs for a legitimate release.
2. Replay those artifacts later — a week, a month, or longer — at the
   same endpoint URL.

Every check the script performs still passes:

- The Universal Manifest is Authenticode-signed by Microsoft. ✅
- Each per-engine manifest CAB is Authenticode-signed by Microsoft. ✅
- Each payload CAB's SHA256 matches the hash in the (signed) manifest. ✅
- Identity binding matches (attacker replays a self-consistent triple). ✅

The customer runs the script and gets AV definitions from an earlier
date. This is a downgrade attack — not a code-injection attack, but not
a benign one either: current malware is precisely what stale AV
definitions miss.

### Deferred fix

A proper fix persists a per-engine version floor and refuses to install a
version below it, with an operator-controlled `-AllowDowngrade` (or
similar) opt-out for the legitimate rollback use case. This is deferred
because the design touches operator ergonomics and error paths beyond the
scope of the current hardening batch.

### Interim recommendations

Operators concerned about replay/downgrade in their environment can
apply either mitigation today without any script change:

- Pass one of the HTTPS `-UpdatePathUrl` values (documented in
  [The endpoints](#the-endpoints)) instead of the HTTP default. TLS blocks
  ordinary on-path replay under the standard trust model; it does not
  add anything to the artifact-content trust chain.
- Monitor the versions actually staged. The per-engine manifests record
  `Package.version` in the on-disk mirror; a stalled or regressing
  version number is a signal to investigate.

---

## Manual test matrix

For a QA engineer with no prior knowledge of this script. Each row includes
setup, exact commands, and expected observable behavior.

### Prerequisites

- Windows Server or Windows 10/11 with **PowerShell 5.1 or PowerShell 7**.
- Network access to `http://forefrontdl.microsoft.com/` (or one of the
  documented failover URLs).
- Local administrator on the test host (needed to create arbitrary
  directories, not needed by the script itself once the directory exists).
- Disk space: **at least 5 GB free** for a full multi-engine run. A single
  engine on a single platform needs about 300 MB.
- **Time budget:** a single `-Engines Microsoft` run
  downloads ~200 MB and can take 5–30 minutes depending on network
  throughput. Full-catalog runs can take an hour.

### Baseline setup steps (do these once)

```powershell
# 1. Create a working directory
$root = 'C:\ScanEngineUpdates\'
New-Item -ItemType Directory -Path $root -Force

# 2. Get the script (whichever way your team gets internal scripts;
#    for this test matrix, assume the script under test is at C:\Test\Update-Engines.ps1)
Set-Location C:\Test
```

### Test cases

| # | Scenario | Command | Expected result |
|---|---|---|---|
| 1 | **Happy path — default engine, default platform.** Smallest end-to-end run. | `.\Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\` | Exits 0. Console shows "Update Path:", "Engine Directory:", one engine downloaded ("Download Complete: Microsoft"), and "Engine Update processing completed." `C:\ScanEngineUpdates\metadata\UniversalManifest.cab`, `C:\ScanEngineUpdates\metadata\<version>\EngineInfo.cab`, and `C:\ScanEngineUpdates\amd64\Microsoft\Package\<version>\microsoft_fullpkg.cab` all exist. |
| 2 | **Re-run on already-current directory.** Verifies the "already up to date" fast path. | Repeat command from test 1 without deleting the directory. | Exits 0. Console shows "Engine already up to date: Microsoft". Total run time under 30 seconds. Payload CAB is not re-downloaded (verify with `Get-Item ...\microsoft_fullpkg.cab` — `LastWriteTime` matches the first run). |
| 3 | **Both live engines together.** Real catalog run against the currently-served matrix. | `.\Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\ -Engines Microsoft,Command` | Exits 0. Each requested engine either downloads or skips as up-to-date on the `amd64` platform. Directory tree contains a `Package\<version>\` subdirectory under `amd64\Microsoft\` and `amd64\Command\`. Note: the Universal Manifest still lists other engines (Kaspersky, Norman, Symantec, Cloudmark, WormList, Kaspersky5) and the `x86` platform, but their per-engine manifest URLs return 404 at all three documented endpoints and are no longer downloadable. Parameter validation (`ValidateSet` on `-Engines`, hardcoded `amd64` platform) prevents an operator from requesting those retired engines/platforms. |
| 4 | **Nonexistent engine name.** Should fail-fast at parameter binding. | `.\Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\ -Engines DoesNotExist` | Throws immediately with a PowerShell parameter-validation error: "Cannot validate argument on parameter 'Engines'. The argument 'DoesNotExist' does not belong to the set 'Microsoft,Command' specified by the ValidateSet attribute." Nothing is downloaded. |
| 5 | **`-EngineDirPath` pointing at a nonexistent directory.** Fail-fast validation. | `.\Update-Engines.ps1 -EngineDirPath C:\NoSuchDir\` | Throws. Error message includes "The directory specified to store the engines does not exist". No files created anywhere. |
| 6 | **Missing `-EngineDirPath` entirely.** | `.\Update-Engines.ps1` | Throws. Error message includes "The EngineDirPath is not set". |
| 7 | **`-EngineDirPath` without trailing slash.** Robustness check. | `.\Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates` (no trailing `\`) | Exits 0 exactly like test 1. Script appends the trailing slash internally. |
| 8 | **Explicit HTTPS failover URL.** | `.\Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\ -UpdatePathUrl https://amupdatedl.microsoft.com/server/scanengineupdate/` | Exits 0. All CABs pass Authenticode. Result identical to test 1. |
| 9 | **Unreachable `-UpdatePathUrl`.** Network failure. | `.\Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\ -UpdatePathUrl http://does-not-exist.invalid/scanengineupdate/` | Throws. Error is a `System.Net.WebException` or 404 wrapper. The temp directory is created but no manifest CAB is staged. |
| 10 | **`-CleanUp` with `-VersionsToKeep 1`.** Retention behavior. | Run test 3 twice (which will not change the version, but verifies cleanup is a no-op when only one version exists). Then, if you have access to an internal endpoint that serves an older version, point at that first, then re-run pointing at the current endpoint with `-CleanUp -VersionsToKeep 1`. | Second run keeps only the newest versioned directory under `amd64\Microsoft\Package\`; older versioned directories are deleted. Console shows the delete lines. |
| 11 | **`-ScriptUpdateOnly`.** Self-update check only. | `.\Update-Engines.ps1 -ScriptUpdateOnly` | Exits 0 without downloading engines. Console shows either "Script was successfully updated" or "No update of the script performed". Does not touch `-EngineDirPath` (not required in this mode). |
| 12 | **`-SkipVersionCheck` in a run.** Bypasses the self-updater. | `.\Update-Engines.ps1 -EngineDirPath C:\ScanEngineUpdates\ -SkipVersionCheck` | Exits 0. Does not print "Script was updated. Please re-run the command." Otherwise behaves like test 1. |
| 13 | **Path with a space.** Directory-name robustness. | Use `-EngineDirPath 'C:\Scan Engine Updates\'` (create it first). | Exits 0. Files land in the space-containing path. No error about quoting. |
| 14 | **Read-only `-EngineDirPath`.** Permission failure. | Create `C:\Readonly\`, apply an ACL denying Write to the current user, then run test 1 against it. | Throws a file-system access-denied error. Nothing is written. Undo the ACL after the test. |
| 15 | **Extremely low disk space.** Payload write failure. | On a small VM, fill the disk so less than 100 MB remains, then run test 1. | Throws a `System.IO.IOException` or "There is not enough space on the disk" error during payload download. The in-progress payload file may be truncated or missing; the size/hash check on the next run detects that and re-downloads. Fully-extracted engine content from prior successful runs is unaffected. |
| 16 | **Interrupted download (Ctrl+C).** Recovery behavior. | Start test 1, wait until you see `Begin download:` for the payload, press Ctrl+C. | Script exits non-zero. Partial `microsoft_fullpkg.cab` may remain on disk. Re-running the script detects the size mismatch on the partial file and re-downloads it. |
| 17 | **Help output.** | `.\Update-Engines.ps1 -?` | Exits 0. Prints the hard-coded usage block. Note: the hard-coded help enumerates only `-EngineDirPath`, `-UpdatePathUrl`, and `-Engines`; the remaining parameters (`-FailoverPathUrl`, `-EngineDownloadUrlV2`, `-ScriptUpdateOnly`, `-SkipVersionCheck`, `-CleanUp`, `-VersionsToKeep`) are documented in the Syntax block of `docs/Admin/Update-Engines.md` and via `Get-Help`. The platform is hardcoded to `amd64` and is not surfaced as a parameter. |
| 18 | **UNC `-EngineDirPath` rejected.** | `.\Update-Engines.ps1 -EngineDirPath \\localhost\c$\ScanEngineUpdates\ -SkipVersionCheck` | Throws. Error message includes "UNC path" and directs the operator to a local path plus a manual copy step. Nothing is downloaded. `-SkipVersionCheck` is used so the self-updater does not run first; without it, `Test-ScriptVersion -AutoUpdate` executes ahead of the path guard and may update the script and return before the UNC error surfaces. |
| 19 | **Mapped-network-drive `-EngineDirPath` rejected.** | `New-PSDrive -Name Z -PSProvider FileSystem -Root \\localhost\c$; .\Update-Engines.ps1 -EngineDirPath Z:\ScanEngineUpdates\ -SkipVersionCheck` | Throws. Error message includes "mapped network drive" and names the drive's `Root` (or `DisplayRoot` for a persistent mapping). Nothing is downloaded. Clean up with `Remove-PSDrive -Name Z`. See test 18 note about `-SkipVersionCheck`. |
| 20 | **Identity-mismatch resilience.** Cannot be exercised against the real endpoint (Microsoft's manifests always self-consistent), so this row is exercised via the automated Pester suite only. Read as "the automated suite covers this." | See `Admin\Tests\Update-Engines.Tests.ps1`, the three "throws when the per-engine manifest declares a different Package.{name,platform,version} than the UM selection" tests under "Invoke-EngineUpdate integrity verification". | All three tests pass. |

### Sign-off checklist

Before approving a change to `Update-Engines.ps1`:

- [ ] Tests 1, 2, 3, and 11 pass on a fresh machine.
- [ ] Tests 5, 6, 9, 17, 18, and 19 fail with the expected error messages.
- [ ] The automated Pester suite in `Admin\Tests\Update-Engines.Tests.ps1`
  passes (`Invoke-Pester .\Admin\Tests\Update-Engines.Tests.ps1`).
- [ ] `Invoke-CodeFormatterOnFiles` on the modified files reports zero
  changes.
- [ ] `.build\SpellCheck.ps1` reports zero issues.

---

## Automated test suite

The colocated Pester suite at `Admin\Tests\Update-Engines.Tests.ps1` covers:

- Each helper function (`Get-ContainedPath`, `Test-ManifestFieldShape`,
  `Test-EngineDirPathIsLocal`, `Test-AuthenticodeSignature`,
  `Test-FileHash`, `Read-Manifest`, `Get-PlatformElement`,
  `Get-EngineElement`, `Get-ExpectedFileInventory`, cleanup and download
  helpers) in isolation, with edge cases: null and empty inputs,
  traversal segments, malformed regex candidates, base64 padding, hash
  format mismatch, UNC paths, and mapped network drives with UNC targets
  exposed via both `DisplayRoot` and `Root`.
- Each `Invoke-*Download` function against fixture XML in
  `Admin\Tests\Data\`, with mocks for `Invoke-WebClientDownload`,
  `Test-AuthenticodeSignature`, `Test-FileHash`, and `ExtractCab`. These
  cover the happy path, the "signature fails," "hash fails," and
  "field shape fails" paths, plus the cache-recovery redownload
  paths for the ELI outer CAB and the full package CAB (fail-open on
  cached corruption, no retry on fresh-download failure, and the
  cached file is deleted before the recovery download runs).
- Manifest inventory validation on both the fresh-extract path
  (missing declared file after `ExtractCab` aborts before commit) and
  the cached fast path (missing declared file under the versioned
  package directory aborts before the "already up to date" success
  message).

Run just this file:

```powershell
Invoke-Pester -Path .\Admin\Tests\Update-Engines.Tests.ps1 -Output Detailed
```

Run the full repo suite:

```powershell
.build\Pester.ps1 -Branch main
```
