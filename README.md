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

## Build

```bash
go build -o vibe-ssh-lift .
```

## Usage

```bash
./vibe-ssh-lift [flags]
```

If required values are missing, the tool prompts interactively.
If no config flag is provided, the tool checks for `.env` and `config.json` in the same directory as the executable and asks whether to use one.

## Flags

- `-server` Single server (`host` or `host:port`).
- `-servers` Comma-separated servers (`host` or `host:port`).
- `-servers-file` File with one server per line (`#` comments and blank lines allowed).
- `-user` SSH username.
- `-password` SSH password (less secure than prompt or env var).
- `-password-env` Name of environment variable containing SSH password.
- `-pubkey` Public key text (`ssh-ed25519 AAAA...`).
- `-pubkey-file` Path to public key file.
- `-json-file` Path to JSON config file.
- `-env-file` Path to `.env` config file.
- `-port` Default port when server entry has no port (default: `22`).
- `-timeout` SSH timeout seconds (default: `10`).
- `-known-hosts` Path to `known_hosts` (default: `~/.ssh/known_hosts`).
- `-insecure-ignore-host-key` Disable host key verification (unsafe).

## Examples

### Single Host, Key File

```bash
./vibe-ssh-lift \
  -server 192.168.1.10 \
  -user deploy \
  -password-env SSH_PASSWORD \
  -pubkey-file ~/.ssh/id_ed25519.pub
```

### Multiple Hosts From File

```bash
./vibe-ssh-lift \
  -servers-file ./servers.txt \
  -user deploy \
  -pubkey-file ~/.ssh/id_ed25519.pub
```

`servers.txt` example:

```text
# app nodes
app01.internal
app02.internal:2222
10.0.2.14
```

### Inline Public Key

```bash
./vibe-ssh-lift \
  -servers "host1,host2:2222" \
  -user deploy \
  -password-env SSH_PASSWORD \
  -pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
```

### Custom known_hosts Path

```bash
./vibe-ssh-lift \
  -server host1 \
  -user deploy \
  -password-env SSH_PASSWORD \
  -pubkey-file ~/.ssh/id_ed25519.pub \
  -known-hosts ./known_hosts
```

### JSON Config File

```bash
./vibe-ssh-lift -json-file configexamples/config.example.json
```

`configexamples/config.example.json` example:

```json
{
  "servers": "app01,app02:2222",
  "user": "deploy",
  "password_env": "SSH_PASSWORD",
  "pubkey_file": "~/.ssh/id_ed25519.pub",
  "port": 22,
  "timeout": 10,
  "known_hosts": "~/.ssh/known_hosts",
  "insecure_ignore_host_key": false
}
```

### .env Config File

```bash
./vibe-ssh-lift -env-file configexamples/.env.example
```

`configexamples/.env.example` example:

```dotenv
SERVERS=app01,app02:2222
USER=deploy
PASSWORD_ENV=SSH_PASSWORD
PUBKEY_FILE=~/.ssh/id_ed25519.pub
PORT=22
TIMEOUT=10
KNOWN_HOSTS=~/.ssh/known_hosts
INSECURE_IGNORE_HOST_KEY=false
```

## Where to put your configs

Real configs should live outside of Git commits. Keep `configexamples/` full of templates such as the ones above, then copy or rewrite the version you actually use—`config.json` for JSON or `<name>.env` for dotenv—alongside the executable or anywhere else you like. When running `vibe-ssh-lift`, point the tool to them with the matching flags (`-json-file config.json` or `-env-file ./my-prod.env`). Use the examples as a starting point, update the credentials/servers, and add that file to `.gitignore` so it stays private while the template remains tracked.

## Config selection behavior

- If both `.env` and `config.json` are found, the tool shows a menu and asks which one to use for that run.
- If only one is found, the tool asks whether you want to use it.
- If both `-env-file` and `-json-file` are set, the tool asks you to choose one and uses only that one.
- CLI flags still override matching values from the selected config file.

## Config Review Prompt

When a config file is used, the tool asks you to review values one-by-one before continuing. For each field you can choose:

- `y` to accept the current value.
- `n` to edit and replace the value.
- `a` to accept all remaining values.

Sensitive values are masked in the preview (for example, the password only shows a short prefix) so you can validate without exposing full secrets on screen.

This review flow requires an interactive terminal session when a config file is used.

## Security Notes

- Secure mode is default: host keys are checked against `known_hosts`.
- Use `-insecure-ignore-host-key` only for temporary testing.
- Prefer `-password-env` or interactive password prompt over `-password`.
- Ensure the public key input contains exactly one valid authorized key line.

## Exit Codes

- `0` All hosts succeeded.
- `1` One or more hosts failed.
- `2` Invalid input/configuration or startup error.
