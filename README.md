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
./vibe-ssh-lift [--env <path>]
```

If required values are missing, the tool prompts interactively.
If `--env` is not provided, the tool checks for `.env` in the same directory as the executable and asks whether to use it.

## Flags

- `--env` dotenv config file path.
- `--help` Show help.

## Examples

### Interactive Run

```bash
./vibe-ssh-lift
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

Real configs should live outside of Git commits. Keep `configexamples/` full of templates such as the one above, then copy or rewrite the version you actually use (`<name>.env`) alongside the executable or anywhere else you like. When running `vibe-ssh-lift`, point the tool to it with `--env ./my-prod.env`. Use the example as a starting point, update the credentials/servers, and add that file to `.gitignore` so it stays private while the template remains tracked.

Config discovery and review happen before any keys are pushed:

- When `.env` is detected next to the binary (or provided via `--env`), the tool can load it before execution.
- Loaded config values are printed before execution; sensitive fields such as the password are masked (only a short prefix is shown).

## Optional Secret References

- Use `PASSWORD_SECRET_REF` (`.env`) to avoid storing plaintext SSH passwords.
- Bitwarden references are supported via `bw://...`, `bw:...`, or `bitwarden://...`.
- The app tries Bitwarden providers in this order:
  1. `bw get secret <id> --raw`
  2. `bws secret get <id>`
- Secret provider command calls are timeout-bounded to avoid hanging runs.
- `bws` responses must be valid JSON containing a non-empty `value` field.
- If a secret reference is provided and cannot be resolved, the run exits with an error.
- For backward compatibility, `PASSWORD` still works.

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

## Config loading behavior

- If `.env` is found next to the binary, the tool asks whether to use it.
- If `--env` is set, the provided `.env` path is used.

## Config Review Prompt

When a config file is used, the tool prints loaded values before continuing. Sensitive values are masked in the preview (for example, the password only shows a short prefix) so you can validate without exposing full secrets on screen.

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
