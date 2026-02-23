# Bitwarden Provider

## Overview

Use this provider to resolve `PASSWORD_SECRET_REF` values from Bitwarden at runtime.

Resolution behavior:

- Primary command: `bw get secret <id> --raw`
- Fallback command: `bws secret get <id>`

## Canonical Secret Ref Format

Canonical format:

```dotenv
PASSWORD_SECRET_REF=bw://<secret-id>
```

Supported formats:

- `bw://<secret-id>`
- `bitwarden://<secret-id>`

## Environment Variables

Required:

- No Bitwarden-specific environment variable is required.

Optional:

- `PATH` (so `bw` and/or `bws` can be found)
- `PASSWORD_PROVIDER=bitwarden` to force Bitwarden resolution by provider name

Notes:

- This tool does not authenticate to Bitwarden directly.
- Authenticate using the installed `bw` and/or `bws` CLI session first.
- Make sure your `PATH` includes the location of the `bw` and/or `bws` binaries.

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
PASSWORD_SECRET_REF=bitwarden://replace-with-secret-id
```

## Troubleshooting

- `resolve secret ... via bw and bws failed`: verify CLI login/session and that `bw`/`bws` are installed.
- `command timed out after 10s`: check network/CLI responsiveness and retry.
- `invalid secret reference format: expected bw://<value> or bitwarden://<value>`: use `bw://<secret-id>` or `bitwarden://<secret-id>`.
