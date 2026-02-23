# ssh-key-bootstrap

Bootstrap SSH public-key access on one or more remote Linux/Unix hosts using an existing username/password.

It removes repetitive manual key setup by applying one public key to one or many hosts over SSH with secure defaults.

## AI Disclaimer

- This project was written with AI assistance (Codex/ChatGPT); review it carefully and use caution before trusting it in real environments.

## Quick Start

Build:

    go build -o ssh-key-bootstrap .

Run interactively:

    ./ssh-key-bootstrap

Run with a .env file:

    ./ssh-key-bootstrap --env ./configexamples/.env.example

## Minimal Configuration Example

Create `.env`:

    SERVERS=app01,app02:2222
    USER=deploy
    PASSWORD_SECRET_REF=bw://replace-with-your-secret-id
    KEY=~/.ssh/id_ed25519.pub
    PORT=22
    TIMEOUT=10
    KNOWN_HOSTS=~/.ssh/known_hosts
    INSECURE_IGNORE_HOST_KEY=false

Run:

    ./ssh-key-bootstrap --env ./.env

## Secrets Providers

- Bitwarden (`bw://...`, `bw:...`, `bitwarden://...`)
- Infisical (`infisical://...`, plus `infisical:...`, `inf://...`, `inf:...` aliases)

Quick provider ref examples:

- Bitwarden:
    - `PASSWORD_SECRET_REF=bw://replace-with-secret-id`
    - `PASSWORD_SECRET_REF=bw:replace-with-secret-id`
    - `PASSWORD_SECRET_REF=bitwarden://replace-with-secret-id`
- Infisical:
    - `PASSWORD_SECRET_REF=infisical://replace-with-secret-name`
    - `PASSWORD_SECRET_REF=infisical:replace-with-secret-name`
    - `PASSWORD_SECRET_REF=inf://replace-with-secret-name`
    - `PASSWORD_SECRET_REF=inf:replace-with-secret-name`

Infisical mode selection:

- Default: CLI mode (`INFISICAL_MODE` unset/empty)
- API mode: set `INFISICAL_MODE=api`

Use `PASSWORD_SECRET_REF` to resolve the SSH password at runtime.
See provider docs for setup details:

- [docs/providers/bitwarden.md](docs/providers/bitwarden.md)
- [docs/providers/infisical.md](docs/providers/infisical.md)

## Detailed Documentation

- Technical deep dive: [docs/TECHNICAL.md](docs/TECHNICAL.md)
- Security policy: [SECURITY.md](SECURITY.md)

## License

- No license at the present time
