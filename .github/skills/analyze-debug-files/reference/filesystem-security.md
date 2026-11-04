<!-- cspell:ignore toctou -->
# Filesystem Security Threat Model

> Reference material for the `analyze-debug-files` skill. Loaded on demand —
> see `SKILL.md` for the workflow spine.


The trust boundary above is about **content** (log lines, embedded
strings) crossing from a customer machine to a Microsoft engineer's
machine. This section is about **filesystem paths** — what we validate,
what we do not, and why.

**IN SCOPE — validated exactly once, at intake:**

- Operator- or caller-supplied paths (worktree parents, cache root,
  debug directory) may unintentionally point at network
  locations. Each entry point runs a one-time check that rejects UNC
  paths, non-FileSystem PSDrives, PSDrives shadowed onto UNC roots,
  NT device namespaces (`\\?\`, `\\.\`, `\??\`), SUBST/DefineDosDevice
  drives whose target is a UNC path, non-`Fixed`/`Removable`/`Ram`
  drive types, and paths whose root-to-leaf walk crosses a reparse
  point.
- Environment variables read as filesystem inputs (`$env:TEMP`,
  `$env:LOCALAPPDATA`) are validated as if they were operator input.
- Existing cache entries are checked through the full XML, metadata, and
  `.last-accessed` paths, including their SHA directory. A safe cache root
  does not prove its children are free of reparse points. A new concurrent
  cache-install winner is validated at its first inspection boundary.
- The output of `git worktree add` — a freshly materialized directory
  path — is validated once immediately after `git` returns, because
  the path did not exist at intake and this is the first opportunity
  to inspect it.
- Debug log file reads use handle-based open + `GetFinalPathNameByHandleW`
  verification so log content itself cannot redirect the read through
  a reparse point. Log files are the primary untrusted input and get
  a stronger check than plain caller-supplied paths.

**OUT OF SCOPE — deliberately not defended against, because the required
attacker capability already implies full compromise:**

- Concurrent same-user processes racing our filesystem validation
  (classic TOCTOU): a process that installs a junction, symlink, or
  SUBST alias in the window between a validation check and any
  subsequent filesystem call.
- Files or directories mutating between initial intake validation
  and later use in the same run.
- Any adversary with concurrent same-user code execution — they can
  compromise the skill by simpler means (editing skill sources, the
  PowerShell profile, or scheduled tasks) than winning a filesystem
  race.

**Rationale:** this skill runs on the operator's own machine under the
operator's own account. An attacker with the ability to race our
filesystem calls already has arbitrary code execution as the operator
and can compromise the skill by simpler means — modifying the skill's
own source files, replacing `Build.ps1`, editing the operator's
PowerShell profile, or dropping a scheduled task. Building handle-based
no-follow directory operations (`CreateFileW` with
`FILE_FLAG_OPEN_REPARSE_POINT`, `SetCurrentDirectoryByHandle`, etc.)
would not defend against that adversary and would diverge from how
every other tool in the CSS-Exchange repository handles filesystem
paths (see HealthChecker, SetupAssist, `Search-Log.ps1`, etc., none of
which defend against concurrent same-user filesystem races).

**Design rule this implies:** every path check happens **exactly once**,
at the point the path first enters the skill or first materializes on
disk. Paths are treated as trusted for the duration of the operation
after that. No revalidation loops before subsequent uses of the same
path.
