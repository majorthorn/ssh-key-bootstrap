# vibe-ssh-lift

Add a public SSH key to one or more remote Linux/Unix hosts over SSH.

## AI Disclaimer

- This README and the current codebase were created with assistance from Codex (ChatGPT). AI may introduce subtle bugs or omissions.
- The developer has reviewed the code to the best of their ability but is a novice with Go and still learning; please audit every change before use.
- Please review the code, dependencies, and security posture before building or running the tool.
- Test thoroughly in a safe environment and verify host key expectations before granting access.

## What It Does

- Connects to each target host with username/password auth.
- Creates `~/.ssh` and `~/.ssh/authorized_keys` if needed.
- Adds the key only if it is not already present.
- Verifies host keys with `known_hosts` by default (secure mode).
- For unknown hosts, prompts you to trust the presented key and stores it in `known_hosts` when accepted.

## Build

```bash
go build -o vibe-ssh-lift .
```

## Usage

```bash
./vibe-ssh-lift [OPTIONS]
```

If required values are missing, the tool prompts interactively.
If no config flag is provided, the tool checks for `.env` and `config.json` in the same directory as the executable and asks whether to use one.

## Flags

- `--host`, `-s` Host list (`host` or `host:port`, comma-separated).
- `--hosts-file`, `-f` File with one server per line (`#` comments and blank lines allowed).
- `--user`, `-u` SSH username.
- `--key`, `-k` Public key text (`ssh-ed25519 AAAA...`) or path to a public key file.
- `--json`, `-j` JSON config file path.
- `--env`, `-d` dotenv config file path.
- `--skip-review`, `-r` Skip interactive review/edit prompts for config-loaded values.
- `--port`, `-p` Default SSH port (default: `22`).
- `--timeout`, `-t` SSH timeout seconds (default: `10`).
- `--known`, `-o` `known_hosts` file path (default: `~/.ssh/known_hosts`).
- `--insecure`, `-i` Disable host key verification (unsafe).
- `--help`, `-h` Show help.

## Examples

### Single Host, Key File Path via `--key`

```bash
./vibe-ssh-lift \
  --host 192.168.1.10 \
  --user deploy \
  --key ~/.ssh/id_ed25519.pub
```

### Multiple Hosts From File

```bash
./vibe-ssh-lift \
  --hosts-file ./servers.txt \
  --user deploy \
  --key ~/.ssh/id_ed25519.pub
```

`servers.txt` example:

```text
# app nodes
app01.internal
app02.internal:2222
10.0.2.14
```

### Multiple Hosts Inline

```bash
./vibe-ssh-lift \
  --host "host1,host2:2222" \
  --user deploy \
  --key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
```

### Custom known_hosts Path

```bash
./vibe-ssh-lift \
  --host host1 \
  --user deploy \
  --key ~/.ssh/id_ed25519.pub \
  --known ./known_hosts
```

### JSON Config File

```bash
./vibe-ssh-lift --json configexamples/config.example.json
```

`configexamples/config.example.json` example:

```json
{
  "servers": "app01,app02:2222",
  "user": "deploy",
  "password_secret_ref": "bw://replace-with-your-secret-id",
  "key": "~/.ssh/id_ed25519.pub",
  "port": 22,
  "timeout": 10,
  "known_hosts": "~/.ssh/known_hosts",
  "insecure_ignore_host_key": false
}
```

### .env Config File

```bash
./vibe-ssh-lift --env configexamples/.env.example
```

`configexamples/.env.example` example:

```dotenv
SERVERS=app01,app02:2222
USER=deploy
PASSWORD_SECRET_REF=bw://replace-with-your-secret-id
KEY=~/.ssh/id_ed25519.pub
PORT=22
TIMEOUT=10
KNOWN_HOSTS=~/.ssh/known_hosts
INSECURE_IGNORE_HOST_KEY=false
```

## Where to put your configs

Real configs should live outside of Git commits. Keep `configexamples/` full of templates such as the ones above, then copy or rewrite the version you actually use—`config.json` for JSON or `<name>.env` for dotenv—alongside the executable or anywhere else you like. When running `vibe-ssh-lift`, point the tool to them with the matching flags (`--json config.json` or `--env ./my-prod.env`). Use the examples as a starting point, update the credentials/servers, and add that file to `.gitignore` so it stays private while the template remains tracked.

Config discovery and review happen before any keys are pushed:

- When either `config.json` or `.env` is detected next to the binary (or provided via `--json`/`--env`), the tool asks which one to use and loads only that source.
- The selection flow requires an interactive terminal because the tool then asks you to confirm or replace every loaded field before it runs; sensitive fields such as the password are masked (only a short prefix is shown) so you can verify without exposing the secret.
- CLI flags keep taking priority over config values, making it easy to override a template for a single run.

## Optional Secret References

- Use `PASSWORD_SECRET_REF` (`.env`) or `password_secret_ref` (`config.json`) to avoid storing plaintext SSH passwords.
- Bitwarden references are supported via `bw://...`, `bw:...`, or `bitwarden://...`.
- The app tries Bitwarden providers in this order:
  1. `bw get secret <id> --raw`
  2. `bws secret get <id>`
- Secret provider command calls are timeout-bounded to avoid hanging runs.
- `bws` responses must be valid JSON containing a non-empty `value` field.
- If a secret reference is provided and cannot be resolved, the run exits with an error.
- For backward compatibility, `PASSWORD` / `password` still work.

## Adding Secret Providers

Secret resolution is provider-based and extensible.

1. Implement the provider interface in `secrets/providers/<name>/provider_<name>.go` (for example `secrets/providers/aws/provider_aws.go`):

```go
type Provider interface {
	Name() string
	Supports(ref string) bool
	Resolve(ref string) (string, error)
}
```

2. Register the provider from its package using `init()` + `secrets.RegisterProvider(...)`.
3. Add a blank import in `secrets/providers/all/all.go` so the provider package is linked into the binary.

Provider files can be split by concern for easier maintenance (recommended for non-trivial providers):
- `provider_<name>.go` (type + `Supports` + `Resolve` entrypoint)
- `provider_<name>_parse.go` (ref parsing/validation)
- `provider_<name>_cli.go` or `provider_<name>_sdk.go` (integration logic)
  Put these files under `secrets/providers/<name>/`.

4. Define a stable ref scheme for your provider so `Supports(ref)` can route correctly, for example:
   - `aws-sm://...`
   - `vault://...`
   - `gcp-sm://...`

5. Return clear errors from `Resolve` (missing auth, missing secret, invalid ref, etc.) so failures are actionable.

6. Add tests in `secrets/resolver_test.go` and provider-specific tests such as `secrets/providers/<name>/provider_<name>_test.go` for:
   - supported vs unsupported refs
   - success resolution
   - provider failure paths

## Config selection behavior

- If both `.env` and `config.json` are found, the tool shows a menu and asks which one to use for that run.
- If only one is found, the tool asks whether you want to use it.
- If both `--env` and `--json` are set, the tool asks you to choose one and uses only that one.
- CLI flags still override matching values from the selected config file.
- Use `--skip-review` to bypass the interactive per-field confirmation step (useful for non-interactive runs).

## Config Review Prompt

When a config file is used, the tool asks you to review values one-by-one before continuing. For each field you can choose:

- `y` to accept the current value.
- `n` to edit and replace the value.
- `a` to accept all remaining values.

Sensitive values are masked in the preview (for example, the password only shows a short prefix) so you can validate without exposing full secrets on screen.

This review flow requires an interactive terminal session when a config file is used.

## Security Notes

- Secure mode is default: host keys are checked against `known_hosts`.
- Unknown hosts are handled interactively (trust prompt + persist on approval), similar to OpenSSH.
- Use `--insecure` only for temporary testing.
- Prefer `PASSWORD_SECRET_REF` / `password_secret_ref` over plaintext password values.
- Ensure the public key input contains exactly one valid authorized key line.

## Exit Codes

- `0` All hosts succeeded.
- `1` One or more hosts failed.
- `2` Invalid input/configuration or startup error.
