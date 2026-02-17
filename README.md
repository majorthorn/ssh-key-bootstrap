# vibe-ssh-lift

## AI Disclaimer

- This README and the current codebase were created with assistance from Codex (ChatGPT). AI may introduce subtle bugs or omissions.
- The developer has reviewed the code to the best of their ability but is a novice with Go and still learning; please audit every change before use.
- Please review the code, dependencies, and security posture before building or running the tool.
- Test thoroughly in a safe environment and verify host key expectations before granting access.

Add a public SSH key to one or more remote Linux/Unix hosts over SSH.

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

## Flags

- `-server` Single server (`host` or `host:port`).
- `-servers` Comma-separated servers (`host` or `host:port`).
- `-servers-file` File with one server per line (`#` comments and blank lines allowed).
- `-user` SSH username.
- `-password` SSH password (less secure than prompt or env var).
- `-password-env` Name of environment variable containing SSH password.
- `-pubkey` Public key text (`ssh-ed25519 AAAA...`).
- `-pubkey-file` Path to public key file.
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

## Security Notes

- Secure mode is default: host keys are checked against `known_hosts`.
- Use `-insecure-ignore-host-key` only for temporary testing.
- Prefer `-password-env` or interactive password prompt over `-password`.
- Ensure the public key input contains exactly one valid authorized key line.

## Exit Codes

- `0` All hosts succeeded.
- `1` One or more hosts failed.
- `2` Invalid input/configuration or startup error.

## AI Disclaimer

- This README and the current codebase were created with assistance from Codex (ChatGPT). AI may introduce subtle bugs or omissions.
- The developer has reviewed the code to the best of their ability but is a novice with Go and still learning; please audit every change before use.
- Please review the code, dependencies, and security posture before building or running the tool.
- Test thoroughly in a safe environment and verify host key expectations before granting access.
