# Infisical Provider

`ssh-key-bootstrap` supports resolving `PASSWORD_SECRET_REF` from Infisical.

## Canonical Secret Reference Format

Use:

```dotenv
PASSWORD_SECRET_REF=infisical://<secret-name>
```

Accepted aliases (case-insensitive, surrounding whitespace ignored):

- `infisical://<ref>`
- `infisical:<ref>`
- `inf://<ref>`
- `inf:<ref>`

## Required Environment Variables

- `INFISICAL_TOKEN` (required)
- `INFISICAL_PROJECT_ID` (required)
- `INFISICAL_ENV` or `INFISICAL_ENVIRONMENT` (required)

Optional:

- `INFISICAL_API_URL` (default: `https://api.infisical.com`)

The provider enforces HTTPS for the API URL.

## Example

```dotenv
SERVERS=app01.internal,app02.internal
USER=deploy
PASSWORD_SECRET_REF=infisical://ssh-prod-password
KEY=~/.ssh/id_ed25519.pub

INFISICAL_TOKEN=replace-with-token
INFISICAL_PROJECT_ID=replace-with-project-id
INFISICAL_ENV=prod
INFISICAL_API_URL=https://api.infisical.com
```

## Optional Reference Query Overrides

You can override project/environment directly in the secret reference query string:

```dotenv
PASSWORD_SECRET_REF=infisical://ssh-prod-password?projectId=<project-id>&environment=prod
```

Supported query keys:

- Project: `projectId`, `projectID`, `workspaceId`, `workspaceID`
- Environment: `environment`, `env`

When present in the reference, these values override environment-variable defaults.
