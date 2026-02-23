# Code Review Findings

## Scope

Repository-wide review across root CLI/runtime files, `config`, provider registry and implementations (`providers/*`), tests, and docs.

## Main Flow Map

1. Parse flags and initialize run log (`main.go`, `shared_utils.go`).
2. Load and parse `.env` configuration (`config_bridge.go`, `config/*`).
3. Resolve `PASSWORD_SECRET_REF` via provider registry (`prompts.go`, `providers/resolver.go`, `providers/all/all.go`).
4. Build SSH client config and host-key callback (`ssh.go`).
5. Resolve hosts and public key input (`ssh.go`).
6. Connect to targets and idempotently update `authorized_keys` (`ssh.go`).
7. Emit task/recap output and status codes (`main.go`).

## Security Issues Found

- **High**: Potential secret-reference leakage in provider error strings.
  - **Rationale**: Secret IDs/refs can be sensitive metadata in logs and CI output.
  - **Changes**:
    - Kept resolver-level redaction behavior.
    - Removed secret identifier echo from Bitwarden fallback errors.
    - Removed full invalid ref echo from Bitwarden/Infisical parse errors.

- **Medium**: Interactive config review showed `Password Secret Ref` in clear text.
  - **Rationale**: Operators can accidentally expose secret identifiers in terminal captures.
  - **Changes**: Redacted `Password Secret Ref` preview in `config/review.go`.

- **Low**: Infisical requests relied only on client timeout.
  - **Rationale**: Explicit request context timeout is more robust when client config is swapped in tests/runtime hooks.
  - **Changes**: Added per-request `context.WithTimeout` in Infisical HTTP resolve path.

## Consistency / Idioms Issues Found

- Provider error behavior was inconsistent on secret-ref echoing.
  - **Recommended/Applied**: Standardized to actionable, non-sensitive messages.
- Config review sensitivity handling treated password and public key as sensitive but not secret refs.
  - **Recommended/Applied**: Treat secret refs as sensitive metadata and redact.
- Error wrapping style already mostly idiomatic (`%w`) and retained.

## Efficiency Issues Found

- No major hot-path inefficiencies requiring structural change.
- Existing host dedupe/sort and provider caching patterns are acceptable for a CLI workload.
- Infisical in-memory cache remains process-lifetime and avoids repeated remote fetches.

## Refactor Plan (Executed)

1. Apply minimal, behavior-preserving security hardening for secret/error surfaces.
2. Add targeted regression tests for redaction and non-leaking error paths.
3. Keep external behavior stable (flags/config/output) while improving safety.
4. Re-run full test + security toolchain.

## What Changed

- Redacted `Password Secret Ref` in interactive config preview.
- Sanitized Bitwarden and Infisical invalid-ref parse errors.
- Sanitized Bitwarden dual-failure resolve error to avoid secret ID echo.
- Added explicit Infisical request context timeout.
- Added/updated tests to prevent regressions in redaction and error-leak behavior.

## Validation

- `go test ./...` passes.
- `make security` passes (`govulncheck`, `gosec`, `staticcheck`).

## Assumptions

- Secret references/secret identifiers are considered sensitive metadata and should not be echoed in user-facing errors.
- Preserving CLI/config/output compatibility remains a priority except for security/correctness fixes.
- Infisical API contract remains `GET /api/v3/secrets/raw/{secretName}` with `workspaceId` and `environment` query parameters.
- Infisical CLI mode assumes the command shape `infisical secrets get <secret-name> --workspaceId <id> --env <env> --plain` supported by installed CLI.

## TODO Disposition

- [x] Search executed for `TODO|FIXME|XXX|HACK|BUG` (case-insensitive) across repository source.
  - Command: `grep -RInE "TODO|FIXME|XXX|HACK|BUG" . --exclude-dir=.git --exclude-dir=.gocache --exclude-dir=build`
  - Result: no matches in source tree.
  - Disposition: no in-repo TODO/FIXME/XXX/HACK/BUG markers required implementation, deferment, or removal.
- [x] Generated cache artifacts (`.gocache`) excluded from disposition scope.
  - Rationale: generated files are not repository source and are recreated by toolchain.
  - Disposition: no code change required.
