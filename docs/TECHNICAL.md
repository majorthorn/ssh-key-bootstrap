# Technical Documentation

## Overview

`ssh-key-bootstrap` is a single-binary CLI that bootstraps SSH public-key access to one or more remote Linux/Unix hosts.

Execution flow:

1. Parse CLI flags
2. Load optional `.env` configuration
3. Validate and complete required inputs (interactive prompts when possible)
4. Resolve target hosts and public key
5. Build SSH client config
6. Connect to each host and run idempotent `authorized_keys` update script
7. Print Ansible-style recap and return status code

## Architecture Deep Dive

## Entrypoint

- Main package: `main.go`
- Binary: `ssh-key-bootstrap`

No `/cmd` tree or additional executable targets are present.

## Package Structure

- `main` package (repository root)
  - Orchestrates CLI flow and output
  - SSH operations and host key handling
  - Prompting and runtime I/O helpers
- `config`
  - `.env` discovery/loading
  - dotenv parsing and normalization
  - loaded-config preview output
- `providers`
  - Provider interface and registry
  - Secret reference dispatching
- `providers/all`
  - Blank-import bootstrap of built-in providers
- `providers/bitwarden`
  - Bitwarden secret reference parsing and command execution

## Data/Control Flow

- `run()` in `main.go` drives the task sequence.
- Config loading is bridged through `config_bridge.go` into `config` via `RuntimeIO` adapter.
- Secret refs are resolved in `prompts.go` through `providers.ResolveSecretReference(...)`.
- SSH connection and remote key update are handled in `ssh.go`.

## Full Configuration Reference

## CLI flags

- `--env <path>`: path to dotenv config file.
- `--help` is supported via Go `flag` help handling (normalized from `--help` to `-h`).

No other CLI flags are implemented.

## Environment/config file keys

Supported keys in dotenv file:

- `SERVER`
- `SERVERS`
- `USER`
- `PASSWORD`
- `PASSWORD_SECRET_REF`
- `KEY`
- `PUBKEY`
- `PUBKEY_FILE`
- `PORT`
- `TIMEOUT`
- `KNOWN_HOSTS`
- `INSECURE_IGNORE_HOST_KEY`

Key handling details:

- Exactly one of `KEY` / `PUBKEY` / `PUBKEY_FILE` may be non-empty.
- Keys are case-insensitive in practice because parser uppercases key names.
- Dotenv key syntax follows `[A-Za-z_][A-Za-z0-9_]*`.

## Defaults

- `PORT=22`
- `TIMEOUT=10`
- `KNOWN_HOSTS=~/.ssh/known_hosts`
- `INSECURE_IGNORE_HOST_KEY=false`

## Required values

Before SSH execution, effective values must exist for:

- user
- password (direct or secret-resolved)
- target hosts (`SERVER` or `SERVERS`)
- public key input

If missing values cannot be interactively prompted (or input ends with EOF), execution fails.

## Configuration Sources and Precedence

Sources:

1. Hardcoded defaults
2. `.env` values (explicit `--env` or interactive discovery next to executable)
3. Interactive prompts for missing required fields

Interactive `.env` discovery behavior:

- If `--env` is absent and runtime is interactive, tool checks for `.env` next to executable.
- If found, prompts whether to use it.
- In non-interactive mode, no auto-discovery prompt is attempted.

## Extended Examples

## Interactive

    ./ssh-key-bootstrap

## Explicit dotenv

    ./ssh-key-bootstrap --env ./.env

## Dotenv example with Bitwarden secret ref

    SERVERS=app01,app02:2222
    USER=deploy
    PASSWORD_SECRET_REF=bw://your-secret-id
    KEY=~/.ssh/id_ed25519.pub
    PORT=22
    TIMEOUT=10
    KNOWN_HOSTS=~/.ssh/known_hosts
    INSECURE_IGNORE_HOST_KEY=false

## Deployment Models

Current repository supports native CLI execution models:

- Local interactive operator workflow
  - Prompt-driven runs from a terminal
- Scripted/non-interactive workflow
  - Provide complete config via `--env`
  - Suitable for CI/job runners with appropriate credentials and network reachability

No Docker image, systemd unit, or Kubernetes deployment manifests are implemented in this repository.

## Security Model

## Host key verification

- Default is secure host key verification via `known_hosts`.
- Unknown hosts trigger interactive trust prompt and optional append to known_hosts.
- `INSECURE_IGNORE_HOST_KEY=true` disables host key verification (testing-only; MITM risk).

## Secret handling

- Password may be provided directly (`PASSWORD`) or via secret reference (`PASSWORD_SECRET_REF`).
- Bitwarden provider supports refs:
  - `bw://...`
- Infisical provider supports refs:
  - `infisical://...`
  - `inf://...`
- Resolution strategy:
  1. `bw get secret <id> --raw`
  2. fallback `bws secret get <id>`
- Command timeout: 10 seconds.

## File access and writes

Reads:

- dotenv file path (`--env` or discovered `.env`)
- key input path (if key input is treated as file path)
- known_hosts file

Writes:

- local run log next to executable: `ssh-key-bootstrap.log`
- local known_hosts append on user-accepted unknown host
- remote `~/.ssh/authorized_keys`

## Remote command behavior

Remote script ensures:

- `~/.ssh` exists with mode `700`
- `~/.ssh/authorized_keys` exists with mode `600`
- key is appended only when exact line is absent (`grep -qxF`)

## Build, Test, and Quality

## Build

    go build -o ssh-key-bootstrap .

## Tests

    go test ./...

## Race tests

    go test -race ./...

## Security/static checks

    make security

`make security` executes:

- `govulncheck ./...`
- `gosec ./...`
- `staticcheck ./...`

## CI

- `.github/workflows/security.yml` runs security tools on PRs.
- `.github/workflows/codeql.yml` runs CodeQL and analysis on push/PR.

## Exit Codes

- `0`: all hosts succeeded
- `1`: one or more hosts failed key update
- `2`: input/config/startup/validation error

## Troubleshooting Reference

- `no interactive terminal available to confirm trust`
  - Run in TTY, prepopulate known_hosts, or use insecure mode for testing.
- `public key input must contain exactly one key`
  - Ensure exactly one non-comment authorized key line is supplied.
- `.env must set only one of KEY/PUBKEY/PUBKEY_FILE`
  - Leave only one key source key in dotenv.
- `resolve password secret reference` errors
  - Validate secret reference format and ensure `bw`/`bws` is installed and authenticated.

## Related Docs

- Landing page: [../README.md](../README.md)
- Security policy: [../SECURITY.md](../SECURITY.md)
