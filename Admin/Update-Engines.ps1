# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# cspell:ignore OCSP Kaspersky Cloudmark redownload redownloads redownloaded redownloading

<#
    TRUST MODEL — quick reference

    | # | Artifact                                | Anchor
    | - | --------------------------------------- | ---------------------------------------
    | 1 | UniversalManifest.cab                   | Authenticode-signed (Microsoft)
    | 2 | EngineInfo.cab (outer ELI wrapper)      | Authenticode-signed (Microsoft)
    | 3 | Inner ELI archive (extracted from 2)    | SHA256 from (1)
    | 4 | manifest.{GUID}.cab (per-engine)        | Authenticode-signed + identity-bound to (1)
    | 5 | Full package CAB (~206 MB payload)      | SHA256 from (4), checked on cached runs too
    | 6 | Inner component CABs                    | Transitive — trust inherits from (5)'s hash

    UNC paths and mapped network drives for -EngineDirPath are rejected;
    stage locally, then copy to a share. Reparse points (junctions,
    symlinks) at the -EngineDirPath target or any of its ancestors are
    rejected to prevent redirection outside the staging tree.

    Cached artifacts (ELI outer CAB, full package CAB) that fail their
    integrity check are deleted and redownloaded once from the anchored
    endpoint before failure -- a single corrupt cached file cannot pin
    the pipeline. Payload extraction targets a per-invocation scratch
    subdirectory under <EngineDirPath>\temp\ and is moved into place
    file-by-file so that customer or sibling files under Package\<version>\
    are preserved.

    Every file this run writes is registered with a write-time SHA256 and
    re-verified at the very end of the run (Test-WrittenFileHashes). This
    detects AV interference, concurrent tampering, or disk corruption that
    happened between write time and end-of-run.

    After extraction into the scratch dir, every file the signed per-engine
    manifest declares (Package.Files.File[]) must be present before the
    completion marker is written. On cached runs, the same inventory is
    verified against $fullPackageDir before the fast-path is trusted --
    a file that AV quarantined between runs surfaces as a hard error
    with instructions to force re-extraction, not a silent miss.

    See Admin/Update-Engines-Internals.md for the threat model, rationale
    for each verification step, and the manual-test matrix.
#>

param(
    [string]$EngineDirPath,
    [string]$UpdatePathUrl = "http://forefrontdl.microsoft.com/server/scanengineupdate/",
    [string]$FailoverPathUrl = "https://amupdatedl.microsoft.com/server/scanengineupdate/",
    [string]$EngineDownloadUrlV2 = "http://amupdatedl.microsoft.com/server/amupdate/",
    [ValidateSet('Microsoft', 'Command')]
    [string[]]$Engines = ("Microsoft"),
    [switch]$ScriptUpdateOnly,
    [switch]$SkipVersionCheck,
    [switch]$CleanUp,
    [int]$VersionsToKeep = 10
)

begin {
    . $PSScriptRoot\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

    $BuildVersion = ""

    $Script:UmFileName = "UniversalManifest.cab"
    $Script:EliFileName = "EngineInfo.cab"

    # Checks if the specified path exists.
    # If not the directory is created.
    function CreatePath($path) {
        if ((Test-Path -Path $path) -ne $true) {
            New-Item -ItemType Directory -Path $path -ErrorAction Stop | Out-Null
            Write-Host "Created: " $path
        }
    }

    # Joins Segment onto Root, canonicalizes the result with
    # [System.IO.Path]::GetFullPath (which collapses '..' and '.' components and
    # normalizes separators), then verifies the resolved path is contained under
    # the resolved root. Throws if the segment escapes the root or is null/empty.
    # Returns the resolved joined path.
    #
    # This is the primary defense against path-traversal payloads in manifest
    # fields: any segment that resolves outside the intended root fails here
    # before the path reaches WebClient.DownloadFile, New-Item, Copy-Item, or
    # expand.exe.
    #
    # LIMITATION: this is a lexical containment check. GetFullPath does not
    # resolve NTFS junctions, symbolic links, or mount points. If an unprivileged
    # principal can create a reparse point somewhere along the resolved path,
    # I/O against the resolved path can be redirected outside the intended root
    # without this check firing. Preconditions the caller must ensure:
    #   1. -EngineDirPath resolves onto local storage (main script rejects UNC
    #      and mapped network drives).
    #   2. -EngineDirPath and every descendant it creates are writable only by
    #      the identity running this script and by trusted administrators.
    # Together, those preconditions prevent the reparse-point escape.
    function Get-ContainedPath {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Root,

            [Parameter(Mandatory = $true)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$Segment
        )

        if ([string]::IsNullOrEmpty($Segment)) {
            $(throw "Path segment is null or empty.")
        }

        $normalizedRoot = [System.IO.Path]::GetFullPath($Root)
        $sep = [System.IO.Path]::DirectorySeparatorChar
        if (-not $normalizedRoot.EndsWith($sep)) {
            $normalizedRoot += $sep
        }

        $combined = [System.IO.Path]::Combine($normalizedRoot, $Segment)
        $resolved = [System.IO.Path]::GetFullPath($combined)

        if (-not $resolved.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            $(throw "Path segment '$Segment' escapes root '$Root' (resolved to '$resolved').")
        }

        return $resolved
    }

    # Validates that a manifest-derived string matches an expected regex before
    # the value is used in path or URL construction. Throws with the field name
    # embedded in the error message so failures are attributable to a specific
    # manifest field. Belt-and-suspenders in front of Get-ContainedPath:
    # containment is the guarantee, shape checks reject bad input earlier and
    # with a clearer diagnostic.
    function Test-ManifestFieldShape {
        param(
            [Parameter(Mandatory = $true)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$Value,

            [Parameter(Mandatory = $true)]
            [string]$Pattern,

            [Parameter(Mandatory = $true)]
            [string]$FieldName
        )

        if ([string]::IsNullOrEmpty($Value)) {
            $(throw "Manifest field '$FieldName' is null or empty.")
        }

        if ($Value -notmatch $Pattern) {
            $(throw "Manifest field '$FieldName' value '$Value' does not match required pattern '$Pattern'.")
        }
    }

    # Rejects -EngineDirPath values that point to network-hosted storage
    # (UNC paths, mapped-drive PSDrives backed by a share, provider-qualified
    # UNC paths, relative paths against a remote current directory, or
    # reparse points that could redirect writes off the local disk). Every
    # download, signature check, hash check, and extraction reads the same
    # predictable pathname; if that pathname lives on a share where any
    # principal with write access can swap file contents between the verify
    # step and the extract step, the integrity checks are defeated even when
    # they individually pass.
    #
    # Operators who want engines on a share should stage locally, then copy
    # the completed engine folder to their share after the script exits.
    #
    # The check enforces the local-storage invariant against several bypasses:
    #
    # 1. Lexical UNC: '\\server\share', '//server/share', mixed-slash variants
    #    and the '\\?\', '\\.\' extended forms, rejected up front so callers
    #    get a friendly message before any resolution happens.
    #
    # 2. Provider-qualified paths: PowerShell also accepts input such as
    #    'Microsoft.PowerShell.Core\FileSystem::\\server\share\...'. The
    #    provider prefix is stripped and the underlying path is re-checked.
    #
    # 2b. Drive-letter-only inputs ('C:', 'Z:', 'Remote:') are rejected as
    #    ambiguous. Per the OS convention that predates PowerShell, a drive
    #    prefix without a trailing separator means "the current working
    #    directory on that drive," not the drive root. Downstream code appends
    #    '\' unconditionally, so 'C:' becomes 'C:\' -- a different path than
    #    the one this validator would inspect. Require the operator to be
    #    explicit ('C:\' or 'C:\Engines\') rather than pick one interpretation
    #    behind their back.
    #
    # 3. Relative paths against a network current directory: if the caller is
    #    in a PowerShell session whose current location is on a mapped
    #    network drive, a plain 'engines\' would resolve to that remote drive.
    #    We resolve to an absolute filesystem path first and check the result.
    #
    # 4. Mapped-network drives (both single-letter Windows drives and
    #    multi-character PSDrives): checked against Get-PSDrive.DisplayRoot
    #    (populated for persistent mappings created via 'net use' /
    #    'New-PSDrive -Persist') AND Get-PSDrive.Root (populated for a plain
    #    'New-PSDrive -Root \\...').
    #
    # 5. Reparse points (symbolic links, junctions) on the target directory or
    #    any of its ancestors: a link can redirect writes to remote storage,
    #    so any reparse point in the path is rejected. Following the link to
    #    verify its target is local is not safe -- an attacker with write
    #    access to the link could swap the target between check and use
    #    (time-of-check / time-of-use race). Callers who need to place
    #    engines under a specific location should use the true local path
    #    directly.
    #
    # Callers wanting to publish engines on a share should stage to a local
    # path, then copy the completed engine folder to their share after the
    # script exits. That preserves the verify-then-consume boundary on
    # trusted local disk.
    function Test-EngineDirPathIsLocal {
        param(
            [Parameter(Mandatory = $true)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$EngineDirPath
        )

        if ([string]::IsNullOrEmpty($EngineDirPath)) {
            return
        }

        # 1. Lexical UNC (both slash directions, mixed, extended-length forms).
        if ($EngineDirPath -match '^[\\/][\\/]') {
            $(throw "The EngineDirPath '$EngineDirPath' is a UNC path. This script must stage engines on local storage. Run against a local directory (for example, C:\Engines\), then copy the completed folder to your network share.")
        }

        # 2. Strip PowerShell provider qualifier if present, then re-check for
        # a UNC form hidden behind it.
        $probePath = $EngineDirPath
        if ($probePath -match '^[^:\\/]+\\FileSystem::(.+)$') {
            $probePath = $Matches[1]
            if ($probePath -match '^[\\/][\\/]') {
                $(throw "The EngineDirPath '$EngineDirPath' resolves to a UNC path behind a provider qualifier ($probePath). This script must stage engines on local storage.")
            }
        }

        # 2b. Reject drive-letter-only inputs ('C:', 'Z:', 'Remote:'). Per the
        # OS convention that predates PowerShell, a drive prefix without a
        # trailing separator means "the current working directory on that
        # drive," not the drive root. Downstream code, however, unconditionally
        # appends '\' to whatever the operator supplied, so 'C:' silently
        # becomes 'C:\'. That would leave this validator inspecting a different
        # path (the current working directory and its reparse-point history)
        # than the one actually used to stage engines (the drive root). Rather
        # than pick one interpretation and paper over the ambiguity, require
        # the operator to be explicit.
        if ($probePath -match '^[A-Za-z][A-Za-z0-9]*:$') {
            $(throw "The EngineDirPath '$EngineDirPath' is a drive prefix with no path. Specify the full path including a separator (for example, 'C:\Engines\' instead of 'C:').")
        }

        # 3. Resolve to an absolute filesystem path. This normalizes relative
        # paths against the current PowerShell location -- if that location is
        # on a mapped network drive, the resolved path will be too, and the
        # subsequent checks catch it. The directory does not need to exist
        # yet; GetUnresolvedProviderPathFromPSPath returns the target location
        # anyway.
        $absolutePath = $null
        try {
            $absolutePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($probePath)
        } catch {
            # Fall back to the raw input; downstream checks still apply.
            $absolutePath = $probePath
        }

        # 4a. Determine the drive name to inspect. .NET Path.GetPathRoot
        # understands classic single-letter Windows drives; multi-character
        # PowerShell drives ('Remote:\...') return an empty root from
        # GetPathRoot, so we extract them lexically from the probe path.
        $pathRoot = [System.IO.Path]::GetPathRoot($absolutePath)
        $driveName = $null
        if (-not [string]::IsNullOrEmpty($pathRoot)) {
            # .NET recognized a root. This handles the classic Windows drive
            # and the UNC case; a UNC root is rejected here regardless of
            # spelling that GetPathRoot normalized to backslashes.
            if ($pathRoot -match '^\\\\') {
                $(throw "The EngineDirPath '$EngineDirPath' resolves to a UNC root ($pathRoot). This script must stage engines on local storage. Run against a local directory, then copy the completed folder to your network share.")
            }
            $driveName = $pathRoot.TrimEnd('\', '/', ':')
        } elseif ($probePath -match '^(?<drive>[A-Za-z][A-Za-z0-9]*):[\\/]?') {
            # Multi-character PSDrive-style prefix (e.g. 'Remote:\'). .NET
            # did not recognize this as a root; check the PSDrive directly.
            $driveName = $Matches['drive']
        }

        # 4b. Mapped-network drives. Do NOT restrict to single-letter drives:
        # multi-character PSDrives created via 'New-PSDrive -Name Remote
        # -PSProvider FileSystem -Root \\server\share' are equally remote.
        if (-not [string]::IsNullOrEmpty($driveName)) {
            $psDrive = Get-PSDrive -Name $driveName -PSProvider FileSystem -ErrorAction SilentlyContinue
            if ($null -ne $psDrive) {
                $driveTargets = @($psDrive.DisplayRoot, $psDrive.Root) | Where-Object { $_ }
                $mappedTo = $driveTargets | Where-Object { $_ -match '^\\\\' } | Select-Object -First 1
                if ($mappedTo) {
                    $(throw "The EngineDirPath '$EngineDirPath' resolves to a mapped network drive '$driveName' ($mappedTo). This script must stage engines on local storage. Run against a local directory, then copy the completed folder to your network share.")
                }
            }
        }

        # Only the ancestor-walk in step 5 uses $pathRoot as a stop condition;
        # skip that walk entirely when there is no path root because we have
        # nothing to walk against.
        if ([string]::IsNullOrEmpty($pathRoot)) {
            return
        }

        # 5. Reparse points on the target and every ancestor up to the drive
        # root. Non-existent path segments are simply skipped -- only existing
        # links can redirect anything.
        $reparse = [System.IO.FileAttributes]::ReparsePoint
        $currentPath = $absolutePath
        $seen = @{}
        while (-not [string]::IsNullOrEmpty($currentPath) -and $currentPath -ne $pathRoot -and -not $seen.ContainsKey($currentPath)) {
            $seen[$currentPath] = $true
            if (Test-Path -LiteralPath $currentPath) {
                $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue
                if ($null -ne $item -and (($item.Attributes -band $reparse) -eq $reparse)) {
                    $(throw "The EngineDirPath '$EngineDirPath' or one of its ancestors ('$currentPath') is a reparse point (symbolic link or junction). Reparse points can redirect writes to remote storage; this script requires the entire path to be plain local directories.")
                }
            }
            $parent = Split-Path -Path $currentPath -Parent
            if ([string]::IsNullOrEmpty($parent) -or $parent -eq $currentPath) { break }
            $currentPath = $parent
        }
    }

    # Verifies the file is Authenticode-signed by Microsoft. Windows resolves the
    # signature against its built-in Microsoft root certificate chain, so the
    # signing key is out of reach for any external attacker (including one with a
    # MITM position). This is the primary content-integrity defense: a tampered
    # or attacker-substituted file cannot produce a Status='Valid' result with a
    # Microsoft signer subject.
    #
    # Both embedded Authenticode signatures and OS-catalog signatures are
    # accepted; both were observed across the engine update feed.
    #
    # The 'O=Microsoft Corporation' check uses a bounded RDN match so that a
    # subject value such as 'O=Microsoft Corporation Evil' or 'O=Not Microsoft
    # Corporation' does not satisfy it. Match either after start-of-string /
    # a preceding ', ' RDN separator, and before ',' / end-of-string.
    function Test-AuthenticodeSignature {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        $sig = Get-AuthenticodeSignature -FilePath $Path

        if ($sig.Status -ne 'Valid') {
            $(throw "Authenticode signature not Valid for '$Path' (Status: $($sig.Status), StatusMessage: $($sig.StatusMessage)).")
        }

        if ($null -eq $sig.SignerCertificate) {
            $(throw "Authenticode signature has no signer certificate for '$Path'.")
        }

        $subject = $sig.SignerCertificate.Subject
        if ($subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
            $(throw "Authenticode signer is not Microsoft for '$Path' (Subject: $subject).")
        }

        # Explicit chain validation with online revocation. Get-AuthenticodeSignature
        # already runs the OS trust policy, but this call makes the revocation
        # posture explicit and lets us distinguish 'chain broken' from 'revocation
        # status could not be reached' in local logs.
        Test-CertificateChain -Certificate $sig.SignerCertificate
    }

    # Partitions X509ChainStatus[] into hard failures (chain must be rejected)
    # and soft failures (chain construction succeeded but revocation could not
    # be checked). Extracted so it can be unit-tested with synthesized status
    # arrays; Test-CertificateChain calls it after building the real chain.
    #
    # X509ChainStatusFlags is a [Flags] enum: a single status entry can carry
    # multiple bits at once (for example RevocationStatusUnknown -bor
    # OfflineRevocation when the CRL endpoint is unreachable). A bit is
    # classified soft iff it is one of the two accepted revocation-lookup
    # transient conditions; a status is classified soft iff every set bit is
    # in the soft mask (and at least one bit is set). Any bit outside the mask
    # -- or a status with no bits set (NoError showing up on a failed build is
    # anomalous) -- is classified hard, i.e., fail-closed.
    function Get-CertificateChainStatusPartition {
        param(
            [Parameter(Mandatory = $true)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [System.Security.Cryptography.X509Certificates.X509ChainStatus[]]$ChainStatus
        )

        $hard = @()
        $soft = @()
        $softMask =
        [int]([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown) -bor
        [int]([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation)

        if ($null -ne $ChainStatus) {
            foreach ($status in $ChainStatus) {
                $flags = [int]$status.Status
                $nonSoftBits = $flags -band (-bnot $softMask)
                if ($flags -ne 0 -and $nonSoftBits -eq 0) {
                    $soft += $status
                } else {
                    $hard += $status
                }
            }
        }
        return @{ Hard = $hard; Soft = $soft }
    }

    # Builds and validates the certificate chain with online revocation.
    # Hard-fails on any chain problem other than transient revocation-lookup
    # failure (offline / unknown), which is logged as a warning so a temporary
    # CRL/OCSP outage does not block engine updates on a server that already
    # passed the base Authenticode 'Valid' check.
    #
    # Root revocation is excluded from the check (standard practice: trusted
    # roots are anchored by policy, not revocation).
    #
    # Time-validity (NotTimeValid, CtlNotTimeValid) is intentionally ignored:
    # Get-AuthenticodeSignature already verified time validity using the
    # Authenticode countersignature timestamp, which is the correct interpretation
    # for signed code (the artifact was signed while the cert was valid; the
    # cert can subsequently expire without invalidating the signature). Doing
    # a second time check here at "now" would spuriously fail on legitimate
    # signatures whose signing certificate has since expired.
    # Interprets an X509Chain.Build() result. Extracted so it can be tested
    # end-to-end without needing to build a real chain -- X509Chain.Build is
    # not virtual and X509Chain itself cannot be meaningfully mocked from
    # PowerShell. Callers pass in the Build() result and the ChainStatus
    # array; this decides whether to return, warn, or throw. Kept in a
    # dedicated function so the fail-closed invariant (Build()==false with
    # empty ChainStatus) has direct test coverage.
    function Assert-ChainBuildResult {
        param(
            [Parameter(Mandatory = $true)]
            [bool]$Built,

            [Parameter(Mandatory = $true)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [System.Security.Cryptography.X509Certificates.X509ChainStatus[]]$ChainStatus,

            [Parameter(Mandatory = $true)]
            [string]$SubjectForDiagnostics
        )

        if ($Built) {
            return
        }

        $partition = Get-CertificateChainStatusPartition -ChainStatus $ChainStatus

        if ($partition.Hard.Count -gt 0) {
            $details = ($partition.Hard | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }) -join '; '
            $(throw "Certificate chain validation failed for '$SubjectForDiagnostics': $details.")
        }

        if ($partition.Soft.Count -gt 0) {
            $softDetails = ($partition.Soft | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }) -join '; '
            Write-Warning "Certificate revocation status could not be verified for '$SubjectForDiagnostics' ($softDetails). Verify network connectivity to CRL/OCSP endpoints if this recurs."
            return
        }

        # Build() returned false but the classification produced neither a hard
        # nor a soft finding. Fail closed rather than accepting the certificate:
        # an unexplained failure is not a passing chain.
        $(throw "Certificate chain validation failed for '$SubjectForDiagnostics': X509Chain.Build returned false but reported no chain-status details.")
    }

    function Test-CertificateChain {
        param(
            [Parameter(Mandatory = $true)]
            $Certificate
        )

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags =
        [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid -bor
        [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreCtlNotTimeValid -bor
        [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeNested

        $built = $chain.Build($Certificate)
        Assert-ChainBuildResult -Built $built -ChainStatus $chain.ChainStatus -SubjectForDiagnostics $Certificate.Subject
    }

    # Verifies the SHA256 of a file matches the expected hash published in the
    # parent manifest. Manifests publish hashes as base64; this converts to
    # uppercase hex to compare against Get-FileHash. Trust flows from an
    # Authenticode-verified parent manifest into these hash fields, then from
    # those hashes into the referenced child files.
    function Test-FileHash {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [Parameter(Mandatory = $true)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$ExpectedSha256Base64,

            [Parameter(Mandatory = $true)]
            [string]$FieldName
        )

        Test-ManifestFieldShape -Value $ExpectedSha256Base64 -Pattern '^[A-Za-z0-9+/]+=*$' -FieldName $FieldName

        try {
            $expectedBytes = [System.Convert]::FromBase64String($ExpectedSha256Base64)
        } catch {
            $(throw "Manifest field '$FieldName' is not valid base64: $($_.Exception.Message).")
        }

        if ($expectedBytes.Length -ne 32) {
            $(throw "Manifest field '$FieldName' does not decode to a 32-byte SHA256 (got $($expectedBytes.Length) bytes).")
        }

        $expectedHex = -join ($expectedBytes | ForEach-Object { $_.ToString('X2') })
        $actualHex = (Get-FileHash -Path $Path -Algorithm SHA256).Hash

        if ($actualHex -ne $expectedHex) {
            $(throw "SHA256 mismatch for '$Path' ($FieldName). Expected: $expectedHex. Actual: $actualHex.")
        }
    }

    # End-of-run integrity ledger. Every file the script writes (downloaded
    # CAB, extracted content, copied marker) is registered here with a
    # SHA256 captured at write time. Test-WrittenFileHashes re-hashes the
    # entire ledger at the very end of the run to prove that nothing was
    # tampered with, corrupted, or removed between the moment we wrote it
    # and the moment we finished. Files with a manifest-published hash
    # (full-package CAB, ELI inner archive) reuse that manifest hash --
    # everything else stores a runtime-captured hash so AV interference,
    # concurrent tampering, or disk corruption after write is still
    # detected. Keyed by resolved absolute path to defeat mixed-case /
    # relative-path aliasing.
    $Script:writtenFileHashes = @{}

    function Register-WrittenFile {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [AllowNull()]
            [AllowEmptyString()]
            [string]$ExpectedSha256Base64,

            [Parameter(Mandatory = $true)]
            [string]$Source
        )

        if (-not (Test-Path -LiteralPath $Path)) {
            $(throw "Register-WrittenFile: cannot register '$Path' -- the file does not exist. Registration must happen after the file is written.")
        }

        $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath

        if ([string]::IsNullOrWhiteSpace($ExpectedSha256Base64)) {
            # No manifest hash for this artifact -- capture the on-disk
            # hash right now so end-of-run verification catches any later
            # mutation.
            $hex = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
            $anchor = "runtime"
        } else {
            # Reuse the manifest-published hash we just verified against.
            # Convert base64 to uppercase hex once so the end-of-run
            # comparison is a plain string equality check against
            # Get-FileHash output.
            try {
                $expectedBytes = [System.Convert]::FromBase64String($ExpectedSha256Base64)
            } catch {
                $(throw "Register-WrittenFile: invalid base64 for '$Path' ($Source): $($_.Exception.Message).")
            }
            if ($expectedBytes.Length -ne 32) {
                $(throw "Register-WrittenFile: SHA256 for '$Path' ($Source) did not decode to 32 bytes (got $($expectedBytes.Length)).")
            }
            $hex = -join ($expectedBytes | ForEach-Object { $_.ToString('X2') })
            $anchor = "manifest"
        }

        $Script:writtenFileHashes[$resolved] = @{
            Hex    = $hex
            Anchor = $anchor
            Source = $Source
        }
    }

    function Unregister-WrittenFile {
        # Remove a previously-registered file from the end-of-run ledger.
        # Used when the script intentionally deletes or supersedes a file
        # it wrote earlier in the run (e.g., invalidating a stale
        # extraction-completion marker before re-extraction). No-op if
        # the path was never registered. Path resolution mirrors
        # Register-WrittenFile so that ledger keys align.
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        if (-not (Test-Path -LiteralPath $Path)) {
            # If the file is gone we cannot resolve it. Fall back to a
            # best-effort case-insensitive match against the recorded
            # ledger keys so callers can invalidate entries whose file
            # they have already deleted.
            $normalized = try { [System.IO.Path]::GetFullPath($Path) } catch { $Path }
            $keysToRemove = @($Script:writtenFileHashes.Keys | Where-Object { $_ -ieq $normalized })
            foreach ($k in $keysToRemove) {
                $Script:writtenFileHashes.Remove($k) | Out-Null
            }
            return
        }

        $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
        if ($Script:writtenFileHashes.ContainsKey($resolved)) {
            $Script:writtenFileHashes.Remove($resolved) | Out-Null
        }
    }

    function Get-ExpectedFileInventory {
        # Read the per-engine manifest and return the ordered list of files
        # the CAB payload is expected to produce on disk. Each entry:
        #   RelPath   -- '<path>\<name>.cab' (or just '<name>.cab' when
        #                path is empty); the on-disk file the payload CAB
        #                extracts to. Every entry in Microsoft's engine
        #                payloads is stored as an inner CAB, so the .cab
        #                suffix is appended unconditionally.
        #   Name      -- the raw <File name> attribute (no .cab suffix).
        #                Kept for diagnostics/error messages.
        #   SubDir    -- the <path> attribute (may be empty).
        # Each name and path is shape-checked before it can influence any
        # filesystem operation.
        param(
            [Parameter(Mandatory = $true)]
            [System.Xml.XmlDocument]$Manifest
        )

        $files = $Manifest.ManifestFile.Package.Files.File
        if ($null -eq $files) {
            return @()
        }

        $inventory = New-Object System.Collections.Generic.List[hashtable]
        $i = 0
        foreach ($f in $files) {
            $name = $f.GetAttribute('name')
            $path = $f.GetAttribute('path')
            Test-ManifestFieldShape -Value $name -Pattern '^[A-Za-z0-9_\-\.]+$' -FieldName "Files.File[$i].name"
            if (-not [string]::IsNullOrEmpty($path)) {
                Test-ManifestFieldShape -Value $path -Pattern '^[A-Za-z0-9_\-]+(\\[A-Za-z0-9_\-]+)*$' -FieldName "Files.File[$i].path"
            }

            $rel = if ([string]::IsNullOrEmpty($path)) { $name + '.cab' } else { $path + '\' + $name + '.cab' }
            $inventory.Add(@{
                    RelPath = $rel
                    Name    = $name
                    SubDir  = $path
                }) | Out-Null
            $i++
        }

        return $inventory.ToArray()
    }

    function Test-WrittenFileHashes {
        if ($Script:writtenFileHashes.Count -eq 0) {
            return
        }

        $violations = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $Script:writtenFileHashes.GetEnumerator()) {
            $path = $entry.Key
            $expected = $entry.Value.Hex
            $meta = "$($entry.Value.Anchor):$($entry.Value.Source)"

            if (-not (Test-Path -LiteralPath $path)) {
                $violations.Add("MISSING: '$path' [$meta] -- expected SHA256=$expected -- file is gone at end of run (removed after we wrote it).") | Out-Null
                continue
            }

            try {
                $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            } catch {
                $violations.Add("UNREADABLE: '$path' [$meta] -- expected SHA256=$expected -- Get-FileHash failed: $($_.Exception.Message).") | Out-Null
                continue
            }

            if ($actual -ne $expected) {
                $violations.Add("CHANGED: '$path' [$meta] -- expected SHA256=$expected, actual SHA256=$actual.") | Out-Null
            }
        }

        if ($violations.Count -gt 0) {
            $(throw ("End-of-run integrity sanity check failed for $($violations.Count) file(s):`n" + ($violations -join "`n")))
        }

        Write-Host ("End-of-run integrity sanity check passed: {0} tracked file(s) verified." -f $Script:writtenFileHashes.Count) -ForegroundColor Green
    }

    function CleanUpFolder($path, $itemsToKeep) {
        Get-ChildItem -Path $path | Where-Object { $_.PSIsContainer } | Sort-Object -Property CreationTime -Descending | Select-Object -Skip $itemsToKeep | Remove-Item -Recurse
    }

    # Extract the contents of $sourceCabPath into $destinationDirectory using
    # expand.exe, preserving the CAB's internal directory structure. Throws on
    # non-zero exit so callers can react to partial or failed extractions.
    function ExtractCab($sourceCabPath, $destinationDirectory) {
        # expand.exe ships with every supported Exchange Server operating
        # system, including Server Core. Invoke it via its trusted absolute
        # path in System32 so a customized or restricted PATH cannot cause
        # a CommandNotFoundException here (and cannot be used to redirect
        # extraction to an untrusted binary). Redirect the utility's usage
        # banner and per-file "Adding..." progress to $null so a wrapping
        # function that ends with `return (Read-Manifest ...)` returns just
        # the intended XmlDocument, not an Object[] mixed with expand's text
        # output.
        $expandExePath = Join-Path $env:SystemRoot "System32\expand.exe"
        & $expandExePath "-R" $sourceCabPath "-F:*" $destinationDirectory | Out-Null
        if ($LASTEXITCODE -ne 0) {
            # expand.exe failed (corrupt CAB, disk full, permission denied,
            # etc.). Without this check, partial extractions could still be
            # copied into the persistent metadata/package directories, and
            # the next run would see the outer CAB's size and hash as
            # already-verified and skip re-extraction indefinitely.
            $(throw "expand.exe failed to extract '$sourceCabPath' to '$destinationDirectory' with exit code $LASTEXITCODE.")
        }
    }

    # Downloads a URI to a destination path using the supplied WebClient.
    # Extracted so tests can mock the network call without hitting the wire.
    function Invoke-WebClientDownload {
        param(
            [Parameter(Mandatory = $true)]
            [System.Net.WebClient]$WebClient,

            [Parameter(Mandatory = $true)]
            [string]$Uri,

            [Parameter(Mandatory = $true)]
            [string]$Destination
        )
        $WebClient.DownloadFile($Uri, $Destination)
    }

    # Reads an XML manifest from disk and returns the parsed document.
    # Extracted so tests can substitute synthetic XML fixtures.
    function Read-Manifest {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path
        )
        return [xml](Get-Content -Path $Path)
    }

    # Selects the <Platform> element matching PlatformName from the Universal Manifest.
    # Throws if no matching platform is found.
    function Get-PlatformElement {
        param(
            [Parameter(Mandatory = $true)]
            [xml]$UniversalManifest,

            [Parameter(Mandatory = $true)]
            [string]$PlatformName
        )
        $platform = $UniversalManifest.UniversalManifest.EngineVersions.SelectSingleNode(("Platform[@id='" + $PlatformName + "']"))
        if ($platform -isnot [System.Xml.XmlElement]) {
            $(throw "The Platform '" + $PlatformName + "' is not valid.")
        }
        return $platform
    }

    # Selects the <Engine> element matching EngineName from the supplied Platform.
    # Writes a non-terminating error and returns $null if no matching engine is found.
    function Get-EngineElement {
        param(
            [Parameter(Mandatory = $true)]
            [System.Xml.XmlElement]$PlatformElement,

            [Parameter(Mandatory = $true)]
            [string]$EngineName
        )
        $engine = $PlatformElement.SelectSingleNode(("Category/Engine[@name='" + $EngineName + "']"))
        if ($engine -isnot [System.Xml.XmlElement]) {
            $errMsg = "The engine name '" + $EngineName + "' is not valid."
            Write-Error $errMsg -Category InvalidArgument
            return $null
        }
        return $engine
    }

    # Downloads the Universal Manifest CAB, extracts it, and returns the parsed XML.
    # Also creates the metadata and temp directories and clears stale temp files.
    function Invoke-UniversalManifestDownload {
        param(
            [Parameter(Mandatory = $true)]
            [System.Net.WebClient]$WebClient,

            [Parameter(Mandatory = $true)]
            [string]$UpdatePathUrl,

            [Parameter(Mandatory = $true)]
            [string]$EngineDirPath,

            [Parameter(Mandatory = $true)]
            [string]$TempFilePath
        )

        $url = ($UpdatePathUrl + "metadata/$($Script:UmFileName)")
        $umFilePath = $EngineDirPath + "metadata\$($Script:UmFileName)"
        $metaDataDir = $EngineDirPath + "metadata\"

        CreatePath -path $metaDataDir

        Invoke-WebClientDownload -WebClient $WebClient -Uri $url -Destination $umFilePath

        # Verify the CAB is Microsoft-signed before extracting or trusting any
        # content it holds. This is the trust anchor for the entire update run:
        # every hash we later verify comes from the XML inside this CAB.
        Test-AuthenticodeSignature -Path $umFilePath

        # Track the UM CAB for end-of-run integrity verification. The UM is
        # freshly downloaded on every run (no cache), so no fail-open pattern
        # is needed here. The Authenticode check above is the trust anchor;
        # end-of-run just proves the file was not mutated after we accepted
        # it.
        Register-WrittenFile -Path $umFilePath -Source 'UniversalManifest.cab'

        CreatePath -path $TempFilePath

        # Delete any temporary files left over from
        # any previous runs of the script
        Remove-Item -Path ($TempFilePath + "*.*")

        # Extract the xml file from the cab
        # so we can parse and read the data
        ExtractCab -sourceCabPath $umFilePath -destinationDirectory $TempFilePath

        return (Read-Manifest -Path ($TempFilePath + "UniversalManifest.xml"))
    }

    # Downloads the Engine License Info CAB for the version reported by the Universal Manifest,
    # but only if the versioned metadata directory does not already contain it.
    function Invoke-EngineLicenseInfoDownload {
        param(
            [Parameter(Mandatory = $true)]
            [System.Net.WebClient]$WebClient,

            [Parameter(Mandatory = $true)]
            [string]$UpdatePathUrl,

            [Parameter(Mandatory = $true)]
            [string]$EngineDirPath,

            [Parameter(Mandatory = $true)]
            [string]$TempFilePath,

            [Parameter(Mandatory = $true)]
            [xml]$UniversalManifest
        )

        $engineInfoVersion = $UniversalManifest.UniversalManifest.licenseInfoVersion
        Test-ManifestFieldShape -Value $engineInfoVersion -Pattern '^\d+$' -FieldName 'licenseInfoVersion'

        if ($null -eq $UniversalManifest.UniversalManifest.LicenseInfo -or
            $null -eq $UniversalManifest.UniversalManifest.LicenseInfo.hash) {
            $(throw "The Universal Manifest is missing the LicenseInfo/hash element required to verify the Engine License Info CAB.")
        }

        # The Universal Manifest publishes the SHA256 of the archive inside
        # the outer EngineInfo.cab we download. Because the
        # Universal Manifest is Authenticode-verified upstream, this hash is
        # trusted and gates the extracted inner CAB.
        $expectedEliHash = $UniversalManifest.UniversalManifest.LicenseInfo.hash.hash

        Write-Host "The current Engine License Info version: " $engineInfoVersion

        $engineInfoFilePath = Get-ContainedPath -Root ($EngineDirPath + "metadata\") -Segment $engineInfoVersion

        CreatePath -path $engineInfoFilePath

        $engineInfoFilePath += "\" + $Script:EliFileName
        $engineInfoURL = ($UpdatePathUrl + "\metadata\" + $engineInfoVersion + "/" + $Script:EliFileName)

        # If the versioned directory does not exist
        # download the new version of the Engine License Info
        $freshlyDownloaded = $false
        if ((Test-Path -Path $engineInfoFilePath) -ne $true) {
            Write-Host "The current version of the Engine License Info needs to be downloaded."

            Invoke-WebClientDownload -WebClient $WebClient -Uri $engineInfoURL -Destination $engineInfoFilePath
            $freshlyDownloaded = $true

            Write-Host "The Engine License Info download is complete."
        }

        # Fail-open cache pattern for a persisted, versioned artifact.
        # A prior run wrote the ELI CAB to $engineInfoFilePath and everything
        # verified. Between that run and now, something on-disk may have
        # changed the file:
        #   - AV quarantine/restore replaced the bytes with a stub.
        #   - Disk corruption flipped bits.
        #   - A partial write from a killed prior run left a truncated file.
        #   - An operator or attacker with write access replaced the file
        #     (the ACL precondition is documented in Update-Engines-Internals.md;
        #     this is the safety net if that precondition is violated).
        # In all cases the correct response is to redownload the file once
        # from the Authenticode-anchored endpoint and re-verify. If the
        # fresh download ALSO fails verification, the endpoint is
        # compromised or Microsoft has published a bad artifact -- either
        # way we abort. This runs on every invocation (including when the
        # file was freshly downloaded above); the try/catch only redownloads
        # when the file was cached.
        $eliVerify = {
            Test-AuthenticodeSignature -Path $engineInfoFilePath

            $eliScratch = Join-Path -Path $TempFilePath -ChildPath ('eli-' + [guid]::NewGuid().ToString('N'))
            try {
                CreatePath -path $eliScratch
                ExtractCab -sourceCabPath $engineInfoFilePath -destinationDirectory $eliScratch

                $innerEli = Get-ChildItem -Path $eliScratch -File -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($null -eq $innerEli) {
                    $(throw "The Engine License Info CAB '$engineInfoFilePath' did not contain any files after extraction; cannot verify its hash.")
                }
                Test-FileHash -Path $innerEli.FullName -ExpectedSha256Base64 $expectedEliHash -FieldName 'LicenseInfo.hash.hash'
            } finally {
                if (Test-Path -LiteralPath $eliScratch) {
                    Remove-Item -LiteralPath $eliScratch -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        try {
            & $eliVerify
        } catch {
            if ($freshlyDownloaded) {
                throw
            }
            Write-Host ("Cached Engine License Info at '{0}' failed integrity check; redownloading. Original error: {1}" -f $engineInfoFilePath, $_.Exception.Message) -ForegroundColor Yellow
            Remove-Item -LiteralPath $engineInfoFilePath -Force -ErrorAction SilentlyContinue
            Invoke-WebClientDownload -WebClient $WebClient -Uri $engineInfoURL -Destination $engineInfoFilePath
            $freshlyDownloaded = $true
            & $eliVerify
        }

        # Track the outer ELI CAB for end-of-run integrity. The manifest's
        # LicenseInfo.hash.hash covers the INNER archive, not the outer CAB,
        # so we capture the outer-CAB hash at write time. The scratch dir
        # we extracted into is cleaned up per-invocation, so we do not
        # register anything under it.
        Register-WrittenFile -Path $engineInfoFilePath -Source 'EngineInfo.cab'
    }

    # Performs the full download flow for a single engine on a single platform:
    # downloads the per-engine manifest CAB, extracts it, reads the version and full
    # package name, downloads the full package if missing or size-mismatched,
    # creates any subdirectories the manifest declares, extracts the package, and
    # copies the manifest into the versioned package directory. Optionally prunes
    # older versioned directories when CleanUp is specified.
    function Invoke-EngineUpdate {
        param(
            [Parameter(Mandatory = $true)]
            [System.Net.WebClient]$WebClient,

            [Parameter(Mandatory = $true)]
            [string]$UpdatePathUrl,

            [Parameter(Mandatory = $true)]
            [string]$EngineDirPath,

            [Parameter(Mandatory = $true)]
            [string]$TempFilePath,

            [Parameter(Mandatory = $true)]
            [System.Xml.XmlElement]$Platform,

            [Parameter(Mandatory = $true)]
            [System.Xml.XmlElement]$Engine,

            [Parameter(Mandatory = $false)]
            [switch]$CleanUp,

            [Parameter(Mandatory = $false)]
            [int]$VersionsToKeep = 10
        )

        Write-Host "Engine: $($Engine.Name) UpdateVersion: $($Engine.Package.version)"

        Test-ManifestFieldShape -Value $Platform.id -Pattern '^[A-Za-z0-9]+$' -FieldName 'Platform.id'
        Test-ManifestFieldShape -Value $Engine.Name -Pattern '^[A-Za-z0-9_\-]+$' -FieldName 'Engine.Name'
        Test-ManifestFieldShape -Value $Engine.Default -Pattern '^\{[0-9A-Fa-f\-]+\}$' -FieldName 'Engine.Default'

        $manifestFileNameRoot = "manifest." + $Engine.Default
        $manifestFileName = $manifestFileNameRoot + ".cab"
        $engineUrl = $UpdatePathUrl + $Platform.id + "/" + $Engine.Name + "/" + "Package/"
        $manifestUrl = ($engineUrl + $manifestFileName)
        $enginePath = Get-ContainedPath -Root $EngineDirPath -Segment ($Platform.id + "\" + $Engine.Name + "\Package\")

        Write-Host "Begin download: $($Engine.Name) Url: $($manifestUrl)"

        CreatePath -path $enginePath

        $manifestPath = Get-ContainedPath -Root $enginePath -Segment $manifestFileName

        Invoke-WebClientDownload -WebClient $WebClient -Uri $manifestUrl -Destination $manifestPath

        # Verify the per-engine manifest CAB before extracting or trusting any
        # hash it publishes. Trust flows from this Authenticode check into the
        # Package.FullPackage.hash field the manifest declares. The per-engine
        # manifest CAB is always freshly downloaded (there is no
        # $manifestPath cache check above), so no fail-open pattern is needed
        # for THIS Authenticode check.
        Test-AuthenticodeSignature -Path $manifestPath

        # Register the per-engine manifest CAB for end-of-run integrity.
        # No manifest-published hash exists for it (Authenticode is the
        # anchor), so we capture the on-disk hash at write time.
        Register-WrittenFile -Path $manifestPath -Source ("PerEngineManifest.cab:{0}" -f $Engine.Name)

        # Delete any temporary files left over from
        # any previous runs of the script
        Remove-Item -Path ($TempFilePath + "*.*")

        ExtractCab -sourceCabPath $manifestPath -destinationDirectory $TempFilePath

        $manifest = Read-Manifest -Path ($TempFilePath + "manifest.xml")

        Test-ManifestFieldShape -Value $manifest.ManifestFile.Package.version -Pattern '^\d+$' -FieldName 'Package.version'
        Test-ManifestFieldShape -Value $manifest.ManifestFile.Package.FullPackage.name -Pattern '^[A-Za-z0-9_\-]+\.cab$' -FieldName 'Package.FullPackage.name'

        # Identity-bind the per-engine manifest to the selection we made from the
        # (Authenticode-verified) Universal Manifest. Without this check, a MITM
        # could combine a valid current Universal Manifest with a different but
        # still validly-Microsoft-signed per-engine manifest (older, wrong engine,
        # wrong platform); every subsequent signature/hash check would still pass
        # and the wrong package would stage under the identity we selected.
        # Signatures prove publisher; this binds a specific artifact to a specific
        # selection. Uses GetAttribute so that a missing attribute reports as
        # $null and not as the element's LocalName (a PowerShell XML dynamic
        # property fallback that would silently pass 'Package' as the name).
        $mfPackage = $manifest.ManifestFile.Package
        $manifestPackageName = $mfPackage.GetAttribute('name')
        $manifestPackagePlatform = $mfPackage.GetAttribute('platform')
        $manifestPackageVersion = $mfPackage.GetAttribute('version')
        if ($manifestPackageName -ne $Engine.Name) {
            $(throw "Engine manifest identity mismatch: Universal Manifest selected engine '$($Engine.Name)' but per-engine manifest declares Package.name '$manifestPackageName'.")
        }
        if ($manifestPackagePlatform -ne $Platform.id) {
            $(throw "Engine manifest identity mismatch: Universal Manifest selected platform '$($Platform.id)' but per-engine manifest declares Package.platform '$manifestPackagePlatform'.")
        }
        if ($manifestPackageVersion -ne $Engine.Package.version) {
            $(throw "Engine manifest identity mismatch: Universal Manifest selected version '$($Engine.Package.version)' but per-engine manifest declares Package.version '$manifestPackageVersion'.")
        }

        if ($null -eq $manifest.ManifestFile.Package.FullPackage.hash -or
            [string]::IsNullOrEmpty($manifest.ManifestFile.Package.FullPackage.hash.hash)) {
            $(throw "The engine manifest for '$($Engine.Name)' is missing the Package/FullPackage/hash element required to verify the payload CAB.")
        }

        # The signed per-engine manifest publishes the SHA256 of the full package
        # CAB. Captured before the download so it's available for verification.
        $expectedFullPackageHash = $manifest.ManifestFile.Package.FullPackage.hash.hash

        $fullPackageDir = Get-ContainedPath -Root $enginePath -Segment ($manifest.ManifestFile.Package.version + "\")

        CreatePath -path $fullPackageDir

        $fullPackageUrl = $engineUrl + $manifest.ManifestFile.Package.version + "/" + $manifest.ManifestFile.Package.FullPackage.name
        $fullPackagePath = Get-ContainedPath -Root $fullPackageDir -Segment $manifest.ManifestFile.Package.FullPackage.name

        # Extraction completion marker. The manifest CAB is copied into
        # $fullPackageDir as the last step of a successful extraction; its
        # presence proves the previous run completed extraction end-to-end.
        # If it is missing, either the previous run failed partway through
        # ExtractCab or no run has extracted yet. Either way we must
        # re-extract: without this marker check, a download that succeeded
        # but whose ExtractCab call then threw would leave $fullPackagePath
        # sized-and-hashed correctly, $needDownload would be $false forever
        # after, and the partial extracted mirror would persist indefinitely.
        $extractionCompleteMarker = Get-ContainedPath -Root $fullPackageDir -Segment $manifestFileName

        # Local helper: invalidate the extraction-complete marker BEFORE we
        # mutate $fullPackagePath. If a prior successful run wrote a marker
        # and this run is about to overwrite the payload CAB (initial size
        # drift or cache-recovery redownload), a crash between the CAB
        # write and the eventual marker rewrite must NOT leave the OLD
        # marker beside the NEW CAB -- the next run would treat the
        # payload as fully extracted when it is not. The marker is
        # recreated at the end of a successful extraction below.
        $invalidateMarker = {
            if (Test-Path -LiteralPath $extractionCompleteMarker) {
                Remove-Item -LiteralPath $extractionCompleteMarker -Force -ErrorAction Stop
                Unregister-WrittenFile -Path $extractionCompleteMarker
            }
        }

        $needDownload = ((Test-Path -Path $fullPackagePath) -ne $true) -or
        ((Get-Item -Path $fullPackagePath).Length -ne $manifest.ManifestFile.Package.FullPackage.Size)

        if ($needDownload) {
            & $invalidateMarker
            Invoke-WebClientDownload -WebClient $WebClient -Uri $fullPackageUrl -Destination $fullPackagePath
        }

        # Verify the payload hash every run, including cached files, so that
        # local tampering of an on-disk mirror between runs is detected. The
        # payload CAB is not Authenticode-signed by design; the SHA256 published
        # in the (signed) per-engine manifest is the sole trust anchor.
        #
        # Fail-open cache pattern: if the CACHED payload fails the hash check,
        # assume the cache is corrupt (AV interference, disk error, partial
        # write from a killed prior run, or a tampered mirror). Delete the
        # bad file and redownload once from the (published-hash-anchored)
        # endpoint before failing. If the fresh download ALSO fails hash
        # verification, throw fatal -- the endpoint is compromised or the
        # manifest and payload have drifted server-side. Without this
        # rescue, a single corrupt cached file would poison every future
        # run until an operator manually deleted it.
        try {
            Test-FileHash -Path $fullPackagePath -ExpectedSha256Base64 $expectedFullPackageHash -FieldName 'Package.FullPackage.hash.hash'
        } catch {
            if ($needDownload) {
                throw
            }
            Write-Host ("Cached payload at '{0}' failed hash verification; redownloading. Original error: {1}" -f $fullPackagePath, $_.Exception.Message) -ForegroundColor Yellow
            & $invalidateMarker
            Remove-Item -LiteralPath $fullPackagePath -Force -ErrorAction SilentlyContinue
            Invoke-WebClientDownload -WebClient $WebClient -Uri $fullPackageUrl -Destination $fullPackagePath
            $needDownload = $true
            Test-FileHash -Path $fullPackagePath -ExpectedSha256Base64 $expectedFullPackageHash -FieldName 'Package.FullPackage.hash.hash'
        }

        # Track the full-package CAB for end-of-run integrity. The
        # manifest-published SHA256 is the anchor -- reuse it so end-of-run
        # verification is guaranteed to match by construction.
        Register-WrittenFile -Path $fullPackagePath -ExpectedSha256Base64 $expectedFullPackageHash -Source ("FullPackage:{0}" -f $Engine.Name)

        $needExtract = $needDownload -or (-not (Test-Path -Path $extractionCompleteMarker))

        # Parse the manifest's declared file inventory once. Reused by
        # both the extraction path (post-extract "did every declared file
        # land in scratch?" check) and the cached fast path (ledger
        # registration so end-of-run integrity catches quarantine of a
        # file the current run did NOT re-extract).
        $expectedInventory = Get-ExpectedFileInventory -Manifest $manifest

        if ($needExtract) {
            # Extract into a per-invocation scratch subdirectory rather
            # than directly into $fullPackageDir. This has three benefits:
            #
            # 1. B3 -- preserves customer/sibling files. The previous
            #    implementation purged everything in $fullPackageDir
            #    except the payload CAB before re-extracting. Any file
            #    a customer, a sibling tool, or an operator had added
            #    under Package\<version>\ was destroyed. Now we only
            #    move files we produce; anything else is left alone.
            #
            # 2. AV interference recovery. If AV quarantined an
            #    extracted DLL from a prior run, the extraction marker
            #    was still present, so no re-extract would fire. The
            #    end-of-run sanity check catches missing files -- but
            #    even without triggering re-extract, when we DO
            #    re-extract we now overwrite the quarantined slot
            #    without needing to know what's there.
            #
            # 3. Crash isolation. If any step below throws, the scratch
            #    dir is cleaned up in the finally block and
            #    $fullPackageDir is not touched -- no partial mixture.
            #
            # The scratch dir name is randomized per invocation so that a
            # reparse point pre-planted at a predictable name cannot
            # redirect extraction outside $TempFilePath. Same pattern as
            # the ELI scratch dir.

            # Marker invalidation happened before payload mutation above.
            # By the time we reach this branch either (a) the marker was
            # never present, or (b) $invalidateMarker deleted it before
            # the payload was overwritten. No further marker cleanup
            # needed here.

            $packageScratch = Join-Path -Path $TempFilePath -ChildPath ('pkg-' + [guid]::NewGuid().ToString('N'))
            try {
                CreatePath -path $packageScratch

                # Create manifest-declared subdirectories inside both the
                # scratch dir (some CAB expanders require the target subdir
                # to exist before extraction) and $fullPackageDir (so that
                # a manifest declaring an empty subdir yields the empty
                # subdir in the final layout even when extraction produces
                # no files under it).
                $subDirCount = $manifest.ManifestFile.Package.Files.Dir.Count

                for ($i = 0; $i -lt $subDirCount; $i++) {
                    $subDirName = $manifest.ManifestFile.Package.Files.Dir[$i].name
                    Test-ManifestFieldShape -Value $subDirName -Pattern '^[A-Za-z0-9_\-]+$' -FieldName "Files.Dir[$i].name"
                    $subDirScratch = Get-ContainedPath -Root $packageScratch -Segment $subDirName
                    $subDirFinal = Get-ContainedPath -Root $fullPackageDir -Segment $subDirName
                    CreatePath -path $subDirScratch
                    CreatePath -path $subDirFinal
                }

                # Expand the (hash-verified) full package into the
                # scratch dir. The inner component CABs this produces
                # are NOT individually signed and NOT individually
                # hash-checked; they inherit trust from the SHA256
                # verified on the outer archive above. See the
                # top-of-file trust model (row 6) and the -EngineDirPath
                # ACL precondition in Update-Engines-Internals.md for
                # the full rationale.
                ExtractCab -sourceCabPath $fullPackagePath -destinationDirectory $packageScratch

                # Inventory check BEFORE committing anything to
                # $fullPackageDir. Every file the signed per-engine
                # manifest declares must be present in scratch. If AV
                # quarantined a file mid-extract, or the extractor
                # returned success but produced an incomplete output,
                # we detect that here -- BEFORE the completion marker
                # is written -- so the next run correctly re-extracts.
                # Missing files are aggregated so operators see the
                # full list, not just the first miss. -PathType Leaf
                # so that a directory pre-planted (or created by the
                # extractor by accident) at an expected file's path
                # does not satisfy the check.
                $missing = New-Object System.Collections.Generic.List[string]
                foreach ($entry in $expectedInventory) {
                    $scratchPath = Get-ContainedPath -Root $packageScratch -Segment $entry.RelPath
                    if (-not (Test-Path -LiteralPath $scratchPath -PathType Leaf)) {
                        $missing.Add($entry.RelPath) | Out-Null
                    }
                }
                if ($missing.Count -gt 0) {
                    $(throw ("Package extraction for engine '{0}' is incomplete: {1} declared file(s) missing from scratch dir. First few: {2}. Anti-virus quarantine or a corrupt payload is the most likely cause; the next run will retry extraction." -f $Engine.Name, $missing.Count, (($missing | Select-Object -First 5) -join ', ')))
                }

                # Commit the manifest-declared inventory. Iterating
                # $expectedInventory directly (rather than
                # Get-ChildItem $packageScratch) closes the check-to-
                # commit gap: if AV quarantined a file BETWEEN the
                # inventory check above and this loop, this loop's
                # Test-Path/Move-Item will fire on it. -PathType Leaf
                # rejects a directory pre-planted at a file path.
                # -ErrorAction Stop turns non-terminating errors
                # (destination locked, ACL denied) into throws so
                # Register-WrittenFile does not hash a STALE file at
                # the destination and record a false success. Every
                # declared entry MUST land or the completion marker
                # will not be written.
                $movedRelPaths = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($entry in $expectedInventory) {
                    $sourcePath = Get-ContainedPath -Root $packageScratch -Segment $entry.RelPath
                    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
                        $(throw ("Package extraction for engine '{0}' lost declared file '{1}' between the inventory check and commit. Anti-virus quarantine mid-extract is the most likely cause; the next run will retry extraction." -f $Engine.Name, $entry.RelPath))
                    }
                    $dest = Get-ContainedPath -Root $fullPackageDir -Segment $entry.RelPath
                    $destDir = Split-Path -Path $dest -Parent
                    if (-not (Test-Path -LiteralPath $destDir)) {
                        New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null
                    }
                    Move-Item -LiteralPath $sourcePath -Destination $dest -Force -ErrorAction Stop
                    Register-WrittenFile -Path $dest -Source ("Extracted:{0}:{1}" -f $Engine.Name, $entry.RelPath)
                    $movedRelPaths.Add($entry.RelPath) | Out-Null
                }

                # Sweep any extras the extractor produced that the
                # manifest did NOT declare. On a well-formed Microsoft
                # package this should be empty; if a future manifest
                # revision omits a file expand.exe still produces, we
                # still want it committed rather than orphaned in the
                # scratch dir. Files under $fullPackageDir that we did
                # NOT extract (customer artifacts, sibling files, older
                # files from a manifest revision that shrank the file
                # list) are preserved by design; end-of-run integrity
                # coverage is scoped to files THIS run wrote.
                Get-ChildItem -LiteralPath $packageScratch -Recurse -File | ForEach-Object {
                    $rel = $_.FullName.Substring($packageScratch.Length).TrimStart('\', '/')
                    if ($movedRelPaths.Contains($rel)) { return }
                    $dest = Get-ContainedPath -Root $fullPackageDir -Segment $rel
                    $destDir = Split-Path -Path $dest -Parent
                    if (-not (Test-Path -LiteralPath $destDir)) {
                        New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null
                    }
                    Move-Item -LiteralPath $_.FullName -Destination $dest -Force -ErrorAction Stop
                    Register-WrittenFile -Path $dest -Source ("Extracted:{0}:{1}" -f $Engine.Name, $rel)
                }
            } finally {
                if (Test-Path -LiteralPath $packageScratch) {
                    Remove-Item -LiteralPath $packageScratch -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            # Copy the downloaded manifest to the package directory. MUST
            # be the last write in this branch: it doubles as the
            # extraction-completion marker checked above, so any crash
            # earlier in this branch leaves the marker absent and forces
            # the next run to re-extract. -ErrorAction Stop ensures that
            # a copy failure (destination locked, ACL denied) throws
            # instead of silently leaving the marker absent while
            # Register-WrittenFile hashes whatever is at the destination.
            Copy-Item -Path $manifestPath -Destination $fullPackageDir -ErrorAction Stop
            Register-WrittenFile -Path $extractionCompleteMarker -Source ("ExtractionMarker:{0}" -f $Engine.Name)

            if ($needDownload) {
                Write-Host "Download Complete: " $Engine.Name
            } else {
                Write-Host "Re-extract Complete (previous extraction was incomplete): " $Engine.Name
            }
        } else {
            # Cached fast path: extraction was completed by a prior run
            # (marker present, payload hash matched). Even though this
            # run did not extract anything itself, we still need to
            # cover the previously-extracted files with the end-of-run
            # sanity check -- otherwise AV quarantine of an already-
            # extracted file between runs would go completely
            # undetected. Enumerate the manifest's declared inventory,
            # verify each expected file is present under $fullPackageDir,
            # and register each with a runtime SHA256.
            #
            # Semantics: the runtime hash captured here anchors the file
            # for the REMAINDER of this run. It does NOT validate the
            # file against the signed manifest (the per-file hash story
            # for inner CABs is inherited-trust from the outer package's
            # verified SHA256, per the trust model). Post-registration
            # mutation is caught by Test-WrittenFileHashes. A file
            # missing from disk at registration time is caught here.
            $missing = New-Object System.Collections.Generic.List[string]
            foreach ($entry in $expectedInventory) {
                $onDisk = Get-ContainedPath -Root $fullPackageDir -Segment $entry.RelPath
                if (-not (Test-Path -LiteralPath $onDisk)) {
                    $missing.Add($entry.RelPath) | Out-Null
                    continue
                }
                Register-WrittenFile -Path $onDisk -Source ("Cached:{0}:{1}" -f $Engine.Name, $entry.RelPath)
            }
            if ($missing.Count -gt 0) {
                $(throw ("Cached extraction for engine '{0}' is incomplete: {1} declared file(s) missing from '{2}'. First few: {3}. Anti-virus quarantine between runs is the most likely cause; delete the completion marker '{4}' to force re-extraction on the next run." -f $Engine.Name, $missing.Count, $fullPackageDir, (($missing | Select-Object -First 5) -join ', '), $extractionCompleteMarker))
            }

            # Register the existing extraction-completion marker so
            # end-of-run integrity covers it on the cached path too.
            if (Test-Path -LiteralPath $extractionCompleteMarker) {
                Register-WrittenFile -Path $extractionCompleteMarker -Source ("ExtractionMarker:{0}" -f $Engine.Name)
            }

            Write-Host "Engine already up to date: " $Engine.Name
        }

        # Clean up
        if ($CleanUp) {
            CleanUpFolder -path $enginePath -itemsToKeep $VersionsToKeep
        }
    }
}

end {
    # Display Help
    if (($Args[0] -eq "-?") -or ($Args[0] -eq "-help")) {
        ""
        "Usage: Update-Engines.ps1 [-EngineDirPath <string>] [[-UpdatePathUrl] <update url>] [[-Engines] <engine names>]"
        "       [-EngineDirPath <string>]           The directory to serve as the root engines directory. Must be on local storage."
        "                                           UNC paths (\\server\share) and mapped network drives are rejected. Download to a"
        "                                           local path first, then copy the resulting folder to your network share."
        "       [-UpdatePathUrl <update url]        The update path used to pull the updates from"
        "       [[-Engines] <engine names>[]]       The list of names of engines to update. Only 'Microsoft' and 'Command' are"
        "                                           served by the current update endpoints; other engines listed in the"
        "                                           Universal Manifest (Kaspersky, Norman, Symantec, Cloudmark, WormList,"
        "                                           Kaspersky5) return 404 and are no longer downloadable."
        "                                           The amd64 platform is used exclusively; x86 is no longer served."
        ""
        "Examples: "
        "     Update-Engines.ps1 -EngineDirPath C:\Engines\"
        "     Update-Engines.ps1 -EngineDirPath C:\Engines\ -UpdatePathUrl http://forefrontdl.microsoft.com/server/scanengineupdate/ -Engines Microsoft"
        ""
        exit
    }

    # This script is not an advanced function ([CmdletBinding()] would break
    # the $Args[0]-based -?/-help handler above), so PowerShell silently
    # routes unknown flags into $Args instead of erroring. Guard against
    # legacy -Platforms invocations (and any other stray parameter) with a
    # single explicit rejection so that operators who scripted the old
    # parameter surface get a clear, actionable failure instead of a
    # silently-ignored argument.
    if ($Args.Count -gt 0) {
        throw ("Unrecognized argument(s): {0}. The -Platforms parameter was removed; only 'amd64' is served by the update endpoints and it is now hardcoded. See Get-Help .\Update-Engines.ps1 or docs/Admin/Update-Engines.md for the current parameter surface." -f ($Args -join ' '))
    }

    Write-Host ("Update-Engines.ps1 script version $($BuildVersion)") -ForegroundColor Green

    if ($ScriptUpdateOnly) {
        switch (Test-ScriptVersion -AutoUpdate -Confirm:$false) {
            ($true) { Write-Host ("Script was successfully updated") -ForegroundColor Green }
            ($false) { Write-Host ("No update of the script performed") -ForegroundColor Yellow }
            default { Write-Host ("Unable to perform ScriptUpdateOnly operation") -ForegroundColor Red }
        }
        return
    }

    if ((-not($SkipVersionCheck)) -and
        (Test-ScriptVersion -AutoUpdate -Confirm:$false)) {
        Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
        return
    }

    if ($EngineDirPath.Length -eq 0) {
        $(throw "The EngineDirPath is not set. Please set the EngineDirPath parameter to a valid directory.")
    }

    Test-EngineDirPathIsLocal -EngineDirPath $EngineDirPath

    # The directory to store the engines with needs to contain
    # a trailing slash.
    if (!$EngineDirPath.EndsWith("\")) {
        $EngineDirPath += "\"
    }

    #---------------------------------------------------------------------------------------
    # Main Script
    #---------------------------------------------------------------------------------------
    Write-Host "Update Path: " $UpdatePathUrl
    Write-Host "Engine Directory: " $EngineDirPath
    Write-Host "Engines: " $Engines
    Write-Host "Platform: amd64"
    Write-Host "CleanUp: " $CleanUp
    Write-Host "VersionsToKeep: " $VersionsToKeep

    if ((Test-Path -Path $EngineDirPath) -ne $true) {
        $(throw "The directory specified to store the engines does not exist or the user this script is running as does not have permissions to access it. " + $EngineDirPath)
    }

    $tempFilePath = $EngineDirPath + "temp\"

    $wc = New-Object System.Net.WebClient

    $umFile = Invoke-UniversalManifestDownload -WebClient $wc -UpdatePathUrl $UpdatePathUrl -EngineDirPath $EngineDirPath -TempFilePath $tempFilePath

    Invoke-EngineLicenseInfoDownload -WebClient $wc -UpdatePathUrl $UpdatePathUrl -EngineDirPath $EngineDirPath -TempFilePath $tempFilePath -UniversalManifest $umFile

    Write-Host "Begin Processing Engine Updates"

    # Only the amd64 platform is served by the current update endpoints; the
    # x86 packages listed in the Universal Manifest return 404. Hardcoding
    # 'amd64' here (rather than accepting -Platforms) prevents an operator
    # from making a request that we know will fail at the network layer.
    $platform = Get-PlatformElement -UniversalManifest $umFile -PlatformName 'amd64'

    Write-Host "Platform: " $platform.id

    foreach ($e in $Engines) {
        $engine = Get-EngineElement -PlatformElement $platform -EngineName $e

        if ($null -eq $engine) {
            continue
        }

        Invoke-EngineUpdate -WebClient $wc -UpdatePathUrl $UpdatePathUrl -EngineDirPath $EngineDirPath -TempFilePath $tempFilePath -Platform $platform -Engine $engine -CleanUp:$CleanUp -VersionsToKeep $VersionsToKeep
    }

    Write-Host "Engine Update processing completed."

    # End-of-run integrity sanity check. Re-hashes every file we wrote
    # this run and compares against the hash captured at write time. Files
    # with a manifest-published SHA256 (payload CAB, ELI inner archive)
    # are compared against the manifest hash; other files (UM CAB, ELI
    # outer CAB, per-engine manifest CABs, extraction marker copies,
    # extracted content) are compared against a hash we captured
    # immediately after writing. This catches:
    #   - AV interference between write and end-of-run (file quarantined
    #     or replaced with a stub).
    #   - Concurrent tampering by a second admin or attacker with write
    #     access to the staging tree.
    #   - Silent disk corruption after write.
    # Runs after all download/extract work and before the temp cleanup so
    # that the temp scratch dir is still present if an operator needs to
    # investigate a mismatch.
    Test-WrittenFileHashes

    # Clean up the temporary directory
    # that is used during the update
    Remove-Item -Path $tempFilePath -Recurse
}
