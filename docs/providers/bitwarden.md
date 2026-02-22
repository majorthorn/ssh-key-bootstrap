# Bitwarden Provider

## Overview

Use this provider to resolve `PASSWORD_SECRET_REF` values from Bitwarden at runtime.

This provider shells out to the Bitwarden CLIs:

- `bw get secret <id> --raw`
- fallback: `bws secret get <id>`

## Supported Secret Ref Formats

Accepted formats (exact prefixes supported by `Supports()`):

- `bw://<secret-id>`
- `bw:<secret-id>`
- `bitwarden://<secret-id>`

## Authentication Requirements

`ssh-key-bootstrap` does not authenticate to Bitwarden directly; authentication is handled by the installed `bw` / `bws` CLIs and their runtime environment/session.

## Environment Variables Used

The Bitwarden provider code in this repository does not call `os.Getenv` / `os.LookupEnv` and does not define Bitwarden-specific env-var string literals.

Code-derived env-var literals found in provider usage context:

- `PATH` (used by process command resolution; seen in provider tests via `t.Setenv("PATH", ...)`)

Required:

- No provider-specific env var is required by this repository code.

Optional:

- `PATH` (must allow resolving `bw` and/or `bws` binaries)

Defaults:

- None defined by this repository for Bitwarden env vars.

Example value:

- `PATH=/usr/local/bin:/usr/bin:/bin`

## PasswordSecretRef Mapping Examples

```dotenv
PASSWORD_SECRET_REF=bw://replace-with-secret-id
PASSWORD_SECRET_REF=bw:replace-with-secret-id
PASSWORD_SECRET_REF=bitwarden://replace-with-secret-id
```

## Minimal Working Example

`.env`:

```dotenv
SERVERS=app01.internal,app02.internal
USER=deploy
PASSWORD_SECRET_REF=bw://replace-with-secret-id
KEY=~/.ssh/id_ed25519.pub
```

Config mapping snippet:

```dotenv
PASSWORD_SECRET_REF=bw://replace-with-secret-id
```

## Troubleshooting

- `resolve secret ... via bw and bws failed`: verify CLI login/session and that `bw`/`bws` are installed.
- `command timed out after 10s`: check network/CLI responsiveness and retry.
- `invalid bitwarden secret ref`: use one of `bw://`, `bw:`, or `bitwarden://` prefixes.