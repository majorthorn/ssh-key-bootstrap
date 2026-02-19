package bitwarden

import (
	"strings"

	"vibe-ssh-lift/secrets"
)

type provider struct{}

func init() {
	secrets.RegisterProvider(provider{})
}

func (provider) Name() string {
	return "bitwarden"
}

func (provider) Supports(secretRef string) bool {
	normalizedRef := strings.ToLower(strings.TrimSpace(secretRef))
	return strings.HasPrefix(normalizedRef, "bw://") ||
		strings.HasPrefix(normalizedRef, "bw:") ||
		strings.HasPrefix(normalizedRef, "bitwarden://")
}

func (provider) Resolve(secretRef string) (string, error) {
	secretID, err := parseSecretID(secretRef)
	if err != nil {
		return "", err
	}

	if secretValue, err := resolveWithBW(secretID); err == nil {
		return secretValue, nil
	}

	secretValue, err := resolveWithBWS(secretID)
	if err != nil {
		return "", err
	}
	return secretValue, nil
}
