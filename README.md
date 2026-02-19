# vibe-ssh-lift

Add a public SSH key to one or more remote Linux/Unix hosts over SSH.

## AI Disclaimer

- This project was written with AI assistance (Codex/ChatGPT); review it carefully and use caution before trusting it in real environments.

## What It Does

- Connects to each target host with username/password authentication.
- Creates `~/.ssh` and `~/.ssh/authorized_keys` if needed.
- Adds the key only if it is not already present.
- Verifies host keys with `known_hosts` by default (secure mode).
- For unknown hosts, prompts you to trust the presented key and stores it in `known_hosts` when accepted.
- Prints Ansible-style task/status output with a final play recap.
- Writes a run log to `vibe-ssh-lift.log` in the same directory as the executable.

## Build

```bash
go build -o vibe-ssh-lift .
```

## Usage

```bash
./vibe-ssh-lift [--env <path>]
```

If required values are missing, the tool prompts for them interactively.
If `--env` is not provided, interactive runs check for `.env` in the same directory as the executable and ask whether to use it.

## Flags

- `--env` Path to a `.env` config file.
- `--help` Show help.

## Output and Logs

- Runtime output follows an Ansible-style format: `TASK [...]`, per-host `ok/changed/failed`, then `PLAY RECAP`.
- Output is written to console and appended to `vibe-ssh-lift.log` next to the executable.
- Log file lines are prefixed with UTC ISO-8601 timestamps.

## Examples

### Interactive Run

```bash
./vibe-ssh-lift
```

### .env File

```bash
./vibe-ssh-lift --env configexamples/.env.example
```

Example `configexamples/.env.example`:

```dotenv
SERVERS=app01,app02:2222
USER=deploy
# Set one of PASSWORD or PASSWORD_SECRET_REF (not both).
PASSWORD_SECRET_REF=bw://replace-with-your-secret-id
# PASSWORD=replace-with-your-password
KEY=~/.ssh/id_ed25519.pub
PORT=22
TIMEOUT=10
KNOWN_HOSTS=~/.ssh/known_hosts
INSECURE_IGNORE_HOST_KEY=false
```

## Where to Put Config Files

Real config files should live outside Git commits. Keep `configexamples/` for templates such as the one above, then copy or rewrite the version you actually use (`<name>.env`) alongside the executable or anywhere else you prefer. When running `vibe-ssh-lift`, point to it with `--env ./my-prod.env`. Use the example as a starting point, update credentials and servers, and add the real file to `.gitignore` so it stays private while the template remains tracked.

Config discovery and review happen before any keys are pushed:

- When `.env` is detected next to the binary (or passed via `--env`), the tool can load it before execution.
- In interactive runs, loaded config values are shown before execution; sensitive fields such as the password are fully redacted.
- In non-interactive runs, this preview is skipped.

## Optional Secret References

- Use `PASSWORD_SECRET_REF` (`.env`) to avoid storing plaintext SSH passwords.
- Bitwarden references are supported via `bw://...`, `bw:...`, or `bitwarden://...`.
- The app tries Bitwarden commands in this order:
  1. `bw get secret <id> --raw`
  2. `bws secret get <id>`
- Secret command calls are timeout-bounded to avoid hanging runs.
- `bws` responses must be valid JSON containing a non-empty `value` field.
- If a secret reference is provided and cannot be resolved, the run exits with an error.
- For backward compatibility, `PASSWORD` still works.

## Adding Secret Providers

Secret resolution is provider-based and extensible.

1. Implement the provider interface in `providers/<name>/provider_<name>.go` (for example `providers/aws/provider_aws.go`):

```go
type Provider interface {
	Name() string
	Supports(ref string) bool
	Resolve(ref string) (string, error)
}
```

2. Register the provider from its package using `init()` + `providers.RegisterProvider(...)`.
3. Add a blank import in `providers/all/all.go` so the provider package is linked into the binary.

For non-trivial providers, split files by concern for easier maintenance:
- `provider_<name>.go` (type + `Supports` + `Resolve` entrypoint)
- `provider_<name>_parse.go` (ref parsing/validation)
- `provider_<name>_cli.go` or `provider_<name>_sdk.go` (integration logic)
Keep these files under `providers/<name>/`.

4. Define a stable ref scheme for your provider so `Supports(ref)` can route correctly, for example:
   - `aws-sm://...`
   - `vault://...`
   - `gcp-sm://...`

5. Return clear errors from `Resolve` (missing auth, missing secret, invalid ref, etc.) so failures are actionable.

6. Add tests in `providers/resolver_test.go` and provider-specific tests such as `providers/<name>/provider_<name>_test.go` covering supported/unsupported refs, successful resolution, and failure paths.

## Security Notes

- Secure mode is default: host keys are checked against `known_hosts`.
- Unknown hosts are handled interactively (trust prompt + persist on approval), similar to OpenSSH.
- Use `INSECURE_IGNORE_HOST_KEY=true` in `.env` only for temporary testing.
- Prefer `PASSWORD_SECRET_REF` over plaintext password values.
- Ensure the public key input contains exactly one valid authorized key line.

## Exit Codes

- `0` All hosts succeeded.
- `1` One or more hosts failed.
- `2` Invalid input/configuration or startup error.
