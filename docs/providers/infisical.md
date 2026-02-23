# Infisical Provider

## Overview

Infisical secrets are resolved through the official Infisical Go SDK (`github.com/infisical/go-sdk`).
The provider is SDK-backed only (no Infisical CLI mode).

Supported secret references:

- `infisical://<secret-name>`
- `inf://<secret-name>`
- Optional explicit selector: `PASSWORD_PROVIDER=infisical`

Canonical example:

```dotenv
PASSWORD_SECRET_REF=infisical://ssh-prod-password
```

## Authentication

This provider uses Universal Auth through the SDK:

- `Auth().UniversalAuthLogin(clientID, clientSecret)`

Required auth env vars:

- `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`
- `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`

Optional auth env var:

- `INFISICAL_AUTH_ORGANIZATION_SLUG`
  - Used to scope login to a specific organization/sub-organization.

## Project/Environment Selection

Secret resolution needs project and environment:

- `INFISICAL_PROJECT_ID`
- `INFISICAL_ENV` or `INFISICAL_ENVIRONMENT`

You can override both directly in the secret reference query:

```dotenv
PASSWORD_SECRET_REF=infisical://ssh-prod-password?projectId=<project-id>&environment=prod
```

Supported query keys:

- Project: `projectId`, `projectID`, `workspaceId`, `workspaceID`
- Environment: `environment`, `env`

## Host / Site URL

Set the Infisical host with:

- `INFISICAL_SITE_URL` (preferred)
- `INFISICAL_API_URL` (legacy compatibility alias)

Default if unset:

- `https://app.infisical.com`

Validation rules:

- Must use `https`
- Must include host
- Must not include path/query/fragment/userinfo
- Provide host only (for example `https://app.infisical.com` or `https://infisical.example.com`)

Do not append `/api` manually. The SDK handles API endpoint pathing.

## Minimal Example

```dotenv
SERVERS=app01.internal,app02.internal
USER=deploy
PASSWORD_SECRET_REF=infisical://ssh-prod-password
KEY=~/.ssh/id_ed25519.pub

INFISICAL_SITE_URL=https://app.infisical.com
INFISICAL_UNIVERSAL_AUTH_CLIENT_ID=replace-with-client-id
INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=replace-with-client-secret
INFISICAL_PROJECT_ID=replace-with-project-id
INFISICAL_ENV=prod
```

## Migration Notes

Removed from the provider:

- `INFISICAL_MODE`
- `INFISICAL_CLI_BIN`
- `INFISICAL_CLI_TIMEOUT`
- Infisical CLI execution path
- Token-based env auth path (`INFISICAL_TOKEN`)

If you were using CLI mode before, migrate to SDK Universal Auth env vars listed above.

## Troubleshooting

- `invalid secret reference format...`: use `infisical://<secret-name>` or `inf://<secret-name>`.
- `infisical universal auth client id is required`: set `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`.
- `infisical universal auth client secret is required`: set `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`.
- `infisical project id is required`: set `INFISICAL_PROJECT_ID` or provide `projectId` in ref query.
- `infisical environment is required`: set `INFISICAL_ENV`/`INFISICAL_ENVIRONMENT` or provide `environment` in ref query.
- `infisical site url must use https`: set `INFISICAL_SITE_URL` to an HTTPS host URL.
