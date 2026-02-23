# Infisical Provider

## Overview

Use this provider to resolve `PASSWORD_SECRET_REF` values from Infisical at runtime.

Mode behavior:

- Default mode: CLI (`INFISICAL_MODE` unset or empty)
- API mode: set `INFISICAL_MODE=api`
- CLI mode (explicit): set `INFISICAL_MODE=cli`

## Canonical Secret Ref Format

Canonical format:

```dotenv
PASSWORD_SECRET_REF=infisical://<secret-name>
```

Accepted aliases (case-insensitive, surrounding whitespace ignored):

- `infisical://<ref>`
- `infisical:<ref>`
- `inf://<ref>`
- `inf:<ref>`

## Environment Variables

Required:

- `INFISICAL_MODE` optional selector (`cli` or `api`; default is `cli`)

CLI mode selector/config:

- `INFISICAL_MODE=cli` (optional; default when unset)
- `INFISICAL_CLI_BIN` (optional, default `infisical`)
- `INFISICAL_CLI_TIMEOUT` (optional duration string, example `10s`, `30s`)

CLI authentication/config env vars are provided by Infisical CLI itself. This project does not define extra CLI auth env vars beyond selecting binary/mode/timeout.

API mode required:

- `INFISICAL_TOKEN`
- `INFISICAL_PROJECT_ID`
- `INFISICAL_ENV` or `INFISICAL_ENVIRONMENT`

Optional:

- `INFISICAL_API_URL` (API mode only, default: `https://api.infisical.com`)

Notes:

- `INFISICAL_API_URL` must be HTTPS.
- You can override project/environment in the ref query string:

```dotenv
PASSWORD_SECRET_REF=infisical://ssh-prod-password?projectId=<project-id>&environment=prod
```

Supported query keys:

- Project: `projectId`, `projectID`, `workspaceId`, `workspaceID`
- Environment: `environment`, `env`

## Minimal Working Example

`.env`:

```dotenv
SERVERS=app01.internal,app02.internal
USER=deploy
PASSWORD_SECRET_REF=infisical://ssh-prod-password
KEY=~/.ssh/id_ed25519.pub

# default mode is CLI when INFISICAL_MODE is unset
INFISICAL_CLI_TIMEOUT=10s
```

API mode example:

```dotenv
INFISICAL_MODE=api
INFISICAL_TOKEN=replace-with-token
INFISICAL_PROJECT_ID=replace-with-project-id
INFISICAL_ENV=prod
INFISICAL_API_URL=https://api.infisical.com
```

Config mapping snippet:

```dotenv
PASSWORD_SECRET_REF=infisical://ssh-prod-password
```

## Troubleshooting

- `invalid INFISICAL_MODE ...`: use `cli` or `api`.
- `infisical CLI binary ... not found in PATH`: install Infisical CLI or set `INFISICAL_CLI_BIN`.
- `infisical token is required`: set `INFISICAL_TOKEN`.
- `infisical project id is required`: set `INFISICAL_PROJECT_ID` or provide `projectId` in the ref query.
- `infisical environment is required`: set `INFISICAL_ENV`/`INFISICAL_ENVIRONMENT` or provide `environment` in the ref query.
- `infisical API URL must use https`: set `INFISICAL_API_URL` to an HTTPS endpoint.
