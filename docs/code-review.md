# Code Review Findings

## Scope

Reviewed all repository folders and files present in this workspace, including:

- CLI flow and runtime helpers in repository root
- SSH connection, host-key verification, and authorized_keys update flow
- Config loading/parsing/review in `internal/config`
- Secret provider registry and provider implementations in `providers`
- Tests and docs

## Main Flow Map

1. CLI entrypoint (`main.go`)
   - Initializes log writer (`setupRunLogFile`)
   - Parses flags (`--env`)
   - Applies `.env` file values
   - Validates options (including secret ref resolution into runtime password)
   - Prompts for missing required inputs
   - Resolves hosts and public key
   - Builds SSH client config
   - Connects to each host and updates `authorized_keys`

2. Configuration load (`config_bridge.go`, `internal/config`)
   - Optional explicit dotenv from `--env`
   - Optional interactive dotenv discovery near executable
   - Dotenv parser supports comments, quoted values, and `export KEY=...`

3. Secret resolution (`prompts.go`, `providers`)
   - `PASSWORD_SECRET_REF` resolved via provider registry
   - Providers registered with `init()` and loaded by blank imports in `providers/all`

4. SSH connection/auth and host-key verification (`ssh.go`)
   - Password auth only
   - Host key callback with known_hosts check
   - Unknown hosts optionally trusted interactively and appended to known_hosts

5. Authorized key install (`ssh.go`)
   - Remote script creates `~/.ssh`, ensures file modes, and appends key idempotently

6. Logging and errors (`shared_utils.go` and root flow)
   - stdout/stderr mirrored to log file near executable
   - Main flow emits Ansible-style task/recap output

## Findings

### Security

- **Fixed**: Potential secret reference disclosure in provider resolution error strings.
  - Previous resolver errors could include full secret references in error text.
  - Updated errors now avoid printing full references.
  - File: `providers/resolver.go`

- **Observed (acceptable with current behavior)**: `INSECURE_IGNORE_HOST_KEY=true` disables host verification by design.
  - This is clearly named and documented as insecure.

- **Observed (acceptable with current behavior)**: Run log lives near executable with mode `0600`.
  - Good restrictive permissions.
  - Depending on install location, creation may fail; code handles this non-fatally.

- **Observed**: Provider command/API failures can include upstream error text.
  - Current code avoids explicit secret/token formatting.
  - Existing behavior retained unless needed for security fixes.

### Reliability

- Host-key callback reloads known_hosts after trust-on-first-use; locking is present and correct.
- SSH and secret command operations have timeout controls (SSH client timeout and Bitwarden command timeout).
- Dotenv parser includes line-size cap (`1 MiB`) and structured parse errors.
- Host resolution normalizes and deduplicates server list, then sorts output for deterministic behavior.

### Maintainability

- Codebase is compact and test coverage is broad around parsing and runtime paths.
- Provider registry pattern is clear and extensible.
- `internal/config` and root runtime utilities share small overlapping helpers (`expandHomePath`, `normalizeLF`), which is acceptable for now but could be consolidated later.

## Additional Notes by Requested Areas

- **File permissions**: known_hosts and log file are created with `0600`; directories with `0700` where expected.
- **Host key verification controls**: secure by default, explicit insecure override available.
- **Secret exposure**: no direct secret logging observed; resolver error wording hardened.
- **Timeouts**: present for SSH and secret-provider paths.
- **Command execution**: external command invocation uses fixed binaries/args and no shell in provider command execution.
- **Error messages**: mostly contextual and actionable; reviewed for sensitive content leakage.

## Assumptions

- Infisical API endpoint format assumed as `GET /api/v3/secrets/raw/{secretName}` with query params:
  - `workspaceId`
  - `environment`
- No existing provider-specific config block mechanism exists in current config schema; therefore Infisical provider config is environment-variable based.
- Bitwarden provider env-var inventory in docs is derived from repository string-literal/code search only; no Bitwarden-specific `BW_*` or `BITWARDEN_*` env literals are defined in provider code.
- Keeping existing CLI/output behavior is prioritized over broader refactors.
